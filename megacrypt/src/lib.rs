//! MEGA / transfer.it AES as a native Python extension.
//!
//! Same wire format as the openssl fallback: AES-128-CTR over the whole file (128-bit
//! big-endian counter starting at `nonce || 0^8`) plus MEGA's chunk CBC-MAC (ramp of
//! 128 KiB .. 1 MiB segments, each a fresh chain with IV `nonce || nonce`, condensed into
//! the 8-word file key). Encrypt and decrypt both release the GIL so `-j` threads run in parallel.

use std::fs::File;
use std::io::{Cursor, Read};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::{Aes128, Block};
use ctr::Ctr128BE;
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

const MAC_RAMP: [u64; 7] = [0x20000, 0x60000, 0xC0000, 0x140000, 0x1E0000, 0x2A0000, 0x380000];
const MAC_STEADY: u64 = 0x480000;
const MAC_MAX: u64 = 0x100000;
const AES_BLOCK: u64 = 16;

/// MEGA chunk-MAC boundaries for a zero-padded length, in byte offsets.
pub fn mac_segment_ends(padded_len: u64) -> Vec<u64> {
    let mut ends: Vec<u64> = MAC_RAMP.iter().copied().filter(|&p| p < padded_len).collect();
    let mut pos = MAC_STEADY;
    while pos < padded_len {
        ends.push(pos);
        pos += MAC_MAX;
    }
    ends.push(padded_len);
    ends
}

fn read_full<R: Read + ?Sized>(src: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let n = src.read(&mut buf[done..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file shorter than its declared size",
            ));
        }
        done += n;
    }
    Ok(())
}

struct Core {
    src: Box<dyn Read + Send + Sync>,
    key: Aes128,
    key_words: [u32; 6],
    ctr: Ctr128BE<Aes128>,
    mac_iv: [u8; 16],
    size: u64,
    padded: u64,
    chunk: usize,
    ends: Vec<u64>,
    ei: usize,
    seg: Vec<u8>,
    off: u64,
    cond: Block,
    buf: Vec<u8>,
    ct: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    done: bool,
    filekey: Option<[u32; 8]>,
}

impl Core {
    fn new(
        src: Box<dyn Read + Send + Sync>,
        size: u64,
        ul_key: &[u32],
        chunk: usize,
    ) -> Result<Self, String> {
        if ul_key.len() != 6 {
            return Err(format!("ul_key must have 6 words, got {}", ul_key.len()));
        }
        if chunk < AES_BLOCK as usize {
            return Err("chunk must be at least 16 bytes".into());
        }
        let mut key_words = [0u32; 6];
        key_words.copy_from_slice(ul_key);
        let mut key_bytes = [0u8; 16];
        for (i, w) in key_words[..4].iter().enumerate() {
            key_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let mut nonce = [0u8; 8];
        nonce[..4].copy_from_slice(&key_words[4].to_be_bytes());
        nonce[4..].copy_from_slice(&key_words[5].to_be_bytes());

        let key = Aes128::new(GenericArray::from_slice(&key_bytes));
        // CTR counter starts at nonce || 0^8; each MAC chain starts at nonce || nonce.
        let mut ctr_iv = [0u8; 16];
        ctr_iv[..8].copy_from_slice(&nonce);
        let mut mac_iv = [0u8; 16];
        mac_iv[..8].copy_from_slice(&nonce);
        mac_iv[8..].copy_from_slice(&nonce);
        let ctr = Ctr128BE::<Aes128>::new(
            GenericArray::from_slice(&key_bytes),
            GenericArray::from_slice(&ctr_iv),
        );

        Ok(Self {
            src,
            key,
            key_words,
            ctr,
            mac_iv,
            size,
            padded: size.div_ceil(AES_BLOCK) * AES_BLOCK,
            chunk: chunk - chunk % AES_BLOCK as usize,
            ends: mac_segment_ends(size.div_ceil(AES_BLOCK) * AES_BLOCK),
            ei: 0,
            seg: Vec::new(),
            off: 0,
            cond: Default::default(),
            buf: Vec::new(),
            ct: Vec::new(),
            pending: Vec::new(),
            pending_pos: 0,
            done: false,
            filekey: None,
        })
    }

    /// Fold one finished MAC segment into the condensed state.
    fn condense(&mut self, mac: &[u8]) {
        for (i, b) in mac.iter().enumerate() {
            self.cond[i] ^= b;
        }
        self.key.encrypt_block(&mut self.cond);
    }

    /// MAC of the currently buffered segment (CBC chain over 16-byte blocks, IV = nonce||nonce).
    fn close_segment(&mut self) {
        let mut st: Block = GenericArray::from_slice(&self.mac_iv).to_owned();
        for block in self.seg.chunks_exact(16) {
            for i in 0..16 {
                st[i] ^= block[i];
            }
            self.key.encrypt_block(&mut st);
        }
        self.condense(&st);
        self.seg.clear();
    }

    /// Split one plaintext buffer into MAC segments, closing the ones that complete.
    fn feed_mac(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let prev = if self.ei == 0 { 0 } else { self.ends[self.ei - 1] };
            let size = (self.ends[self.ei] - prev) as usize;
            let take = std::cmp::min(data.len() - i, size - self.seg.len());
            self.seg.extend_from_slice(&data[i..i + take]);
            i += take;
            if self.seg.len() == size {
                self.close_segment();
                self.ei += 1;
            }
        }
    }

    fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        if self.ei == 0 && self.ends.len() == 1 && self.ends[0] == 0 {
            let iv = self.mac_iv;
            self.condense(&iv); // empty file still contributes one MAC
            self.ei = 1;
        }
        if self.ei < self.ends.len() {
            return;
        }
        let c = self.cond;
        let k = self.key_words;
        let c0 = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        let c1 = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
        let c2 = u32::from_be_bytes([c[8], c[9], c[10], c[11]]);
        let c3 = u32::from_be_bytes([c[12], c[13], c[14], c[15]]);
        self.filekey = Some([
            k[0] ^ k[4],
            k[1] ^ k[5],
            k[2] ^ c0 ^ c1,
            k[3] ^ c2 ^ c3,
            k[4],
            k[5],
            c0 ^ c1,
            c2 ^ c3,
        ]);
    }

    /// Produce up to `n` ciphertext bytes, encrypting whole chunks as needed.
    fn pull(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(n.min(1 << 20));
        while out.len() < n {
            if self.pending_pos < self.pending.len() {
                let take = std::cmp::min(n - out.len(), self.pending.len() - self.pending_pos);
                out.extend_from_slice(&self.pending[self.pending_pos..self.pending_pos + take]);
                self.pending_pos += take;
                if self.pending_pos == self.pending.len() && self.off >= self.padded {
                    self.finish(); // the file key is ready as soon as the last byte is delivered
                }
                continue;
            }
            if self.off >= self.padded {
                self.finish();
                break;
            }
            self.fill()?;
        }
        Ok(out)
    }

    /// Encrypt one internal chunk into `pending`.
    fn fill(&mut self) -> std::io::Result<()> {
        let start = self.off;
        let want = std::cmp::min(self.chunk as u64, self.padded - start) as usize;
        let real = std::cmp::min(want as u64, self.size.saturating_sub(start)) as usize;
        self.buf.resize(want, 0);
        let mut buf = std::mem::take(&mut self.buf);
        read_full(&mut *self.src, &mut buf[..real])?;
        buf[real..want].fill(0); // bytes past `size` are zero padding, never the previous chunk
        self.ct.resize(want, 0);
        self.ct.copy_from_slice(&buf);
        self.ctr.apply_keystream(&mut self.ct);
        self.pending.clear();
        self.pending.extend_from_slice(&self.ct[..real]);
        self.pending_pos = 0;
        self.feed_mac(&buf);
        self.buf = buf;
        self.off = start + want as u64;
        Ok(())
    }
}

/// MEGA file encryption of an in-memory buffer: returns (ciphertext, file key words).
pub fn encrypt_bytes_inner(data: &[u8], ul_key: &[u32], chunk: usize) -> Result<(Vec<u8>, [u32; 8]), String> {
    let chunk = chunk.max(AES_BLOCK as usize);
    let mut core = Core::new(Box::new(Cursor::new(data.to_vec())), data.len() as u64, ul_key, chunk)?;
    let mut out = Vec::with_capacity(data.len());
    while out.len() < data.len() {
        let piece = core.pull(std::cmp::min(core.chunk, data.len() - out.len())).map_err(|e| e.to_string())?;
        if piece.is_empty() {
            break;
        }
        out.extend_from_slice(&piece);
    }
    out.truncate(data.len());
    core.finish();
    let filekey = core.filekey.ok_or_else(|| "incomplete encryption".to_string())?;
    Ok((out, filekey))
}

/// Streaming encryptor over a file or any byte source.
///
/// `Core` is `Send + Sync` so PyO3 lets the Python object outlive its worker thread, which
/// happens whenever a traceback keeps it alive past the upload thread.
#[pyclass(module = "megacrypt")]
pub struct FileCipher {
    core: Option<Core>,
}

#[pymethods]
impl FileCipher {
    #[new]
    #[pyo3(signature = (path, size, ul_key, chunk = 8 << 20))]
    fn new(path: &str, size: u64, ul_key: Vec<u32>, chunk: usize) -> PyResult<Self> {
        let file = File::open(path).map_err(|e| PyIOError::new_err(format!("{path}: {e}")))?;
        let core = Core::new(Box::new(file), size, &ul_key, chunk).map_err(PyValueError::new_err)?;
        Ok(Self { core: Some(core) })
    }

    /// Ciphertext bytes; empty once the file is exhausted. Runs without the GIL.
    fn read<'py>(&mut self, py: Python<'py>, n: usize) -> PyResult<Bound<'py, PyBytes>> {
        let core = self.core.as_mut().ok_or_else(|| PyValueError::new_err("cipher is closed"))?;
        let out = py.allow_threads(|| core.pull(n));
        Ok(PyBytes::new(py, &out.map_err(|e| PyIOError::new_err(e.to_string()))?))
    }

    /// 8 key words, available once the whole file has been read.
    #[getter]
    fn filekey(&self) -> Option<Vec<u32>> {
        self.core.as_ref().and_then(|c| c.filekey).map(|k| k.to_vec())
    }

    #[getter]
    fn size(&self) -> u64 {
        self.core.as_ref().map(|c| c.size).unwrap_or(0)
    }
}

#[pyfunction]
#[pyo3(signature = (data, ul_key, chunk = 8 << 20))]
fn encrypt_bytes<'py>(
    py: Python<'py>,
    data: &[u8],
    ul_key: Vec<u32>,
    chunk: usize,
) -> PyResult<(Bound<'py, PyBytes>, Vec<u32>)> {
    let out = py.allow_threads(|| encrypt_bytes_inner(data, &ul_key, chunk));
    let (enc, filekey) = out.map_err(PyValueError::new_err)?;
    Ok((PyBytes::new(py, &enc), filekey.to_vec()))
}

#[pyfunction]
fn segment_ends(padded_len: u64) -> Vec<u64> {
    mac_segment_ends(padded_len)
}

fn aes128(key: &[u8]) -> Result<Aes128, String> {
    if key.len() != 16 {
        return Err(format!("AES key must be 16 bytes, got {}", key.len()));
    }
    Ok(Aes128::new(GenericArray::from_slice(key)))
}

fn require_blocks(data: &[u8]) -> Result<(), String> {
    if data.len() % 16 != 0 {
        return Err(format!("AES data must be a multiple of 16 bytes, got {}", data.len()));
    }
    Ok(())
}

/// AES-128-ECB encrypt. `data` must already be a multiple of 16 bytes.
pub fn aes_ecb_inner(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    require_blocks(data)?;
    let cipher = aes128(key)?;
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    Ok(out)
}

/// AES-128-CBC encrypt. `data` and `iv` must already be 16-byte aligned.
pub fn aes_cbc_inner(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    require_blocks(data)?;
    if iv.len() != 16 {
        return Err(format!("AES IV must be 16 bytes, got {}", iv.len()));
    }
    let cipher = aes128(key)?;
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        prev.copy_from_slice(block);
    }
    Ok(out)
}

/// AES-128-ECB decrypt. `data` must already be a multiple of 16 bytes.
pub fn aes_ecb_decrypt_inner(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    require_blocks(data)?;
    let cipher = aes128(key)?;
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    Ok(out)
}

/// AES-128-CBC decrypt. `data` and `iv` must already be 16-byte aligned.
pub fn aes_cbc_decrypt_inner(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    require_blocks(data)?;
    if iv.len() != 16 {
        return Err(format!("AES IV must be 16 bytes, got {}", iv.len()));
    }
    let cipher = aes128(key)?;
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        let mut saved = [0u8; 16];
        saved.copy_from_slice(block);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = saved;
    }
    Ok(out)
}

/// AES-128-CTR. Encrypt and decrypt are the same xor.
pub fn aes_ctr_inner(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if iv.len() != 16 {
        return Err(format!("AES IV must be 16 bytes, got {}", iv.len()));
    }
    let _ = aes128(key)?;
    let mut ctr = Ctr128BE::<Aes128>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    let mut out = data.to_vec();
    ctr.apply_keystream(&mut out);
    Ok(out)
}

fn word_be(w: u32) -> [u8; 4] {
    w.to_be_bytes()
}

/// MEGA file-key fold: AES key = k[0:4] xor k[4:8], CTR IV = k[4:6] || 0^8.
pub fn aes_key_iv_from_words(k: &[u32]) -> Result<([u8; 16], [u8; 16]), String> {
    if k.len() < 4 {
        return Err(format!("file key must have at least 4 words, got {}", k.len()));
    }
    let mut key = [0u8; 16];
    for i in 0..4 {
        let extra = if k.len() > i + 4 { k[i + 4] } else { 0 };
        key[i * 4..i * 4 + 4].copy_from_slice(&word_be(k[i] ^ extra));
    }
    let mut iv = [0u8; 16];
    if k.len() >= 6 {
        iv[..4].copy_from_slice(&word_be(k[4]));
        iv[4..8].copy_from_slice(&word_be(k[5]));
    }
    Ok((key, iv))
}

/// Recompute the condensed MEGA chunk MAC and compare with key words 6 and 7.
pub fn verify_mac_inner(plain: &[u8], k: &[u32]) -> bool {
    if k.len() > 8 {
        return true;
    }
    if k.len() < 8 {
        return false;
    }
    let Ok((key, _)) = aes_key_iv_from_words(k) else {
        return false;
    };
    let mut mac_iv = [0u8; 16];
    mac_iv[..4].copy_from_slice(&word_be(k[4]));
    mac_iv[4..8].copy_from_slice(&word_be(k[5]));
    mac_iv[8..12].copy_from_slice(&word_be(k[4]));
    mac_iv[12..16].copy_from_slice(&word_be(k[5]));
    let pad = (16 - plain.len() % 16) % 16;
    let mut padded = Vec::with_capacity(plain.len() + pad);
    padded.extend_from_slice(plain);
    padded.resize(plain.len() + pad, 0);
    let ends = mac_segment_ends(padded.len() as u64);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut cond = Block::default();
    let mut start = 0usize;
    for end in ends {
        let end = end as usize;
        let seg = &padded[start..end];
        start = end;
        let mac = if seg.is_empty() {
            GenericArray::clone_from_slice(&mac_iv)
        } else {
            let mut st: Block = GenericArray::clone_from_slice(&mac_iv);
            for block in seg.chunks_exact(16) {
                for i in 0..16 {
                    st[i] ^= block[i];
                }
                cipher.encrypt_block(&mut st);
            }
            st
        };
        for i in 0..16 {
            cond[i] ^= mac[i];
        }
        cipher.encrypt_block(&mut cond);
    }
    let c0 = u32::from_be_bytes([cond[0], cond[1], cond[2], cond[3]]);
    let c1 = u32::from_be_bytes([cond[4], cond[5], cond[6], cond[7]]);
    let c2 = u32::from_be_bytes([cond[8], cond[9], cond[10], cond[11]]);
    let c3 = u32::from_be_bytes([cond[12], cond[13], cond[14], cond[15]]);
    c0 ^ c1 == k[6] && c2 ^ c3 == k[7]
}

/// AES-CTR decrypt of a MEGA file; optional condensed-MAC check against the 8-word file key.
pub fn decrypt_bytes_inner(enc: &[u8], k: &[u32], verify: bool) -> Result<Vec<u8>, String> {
    let (key, iv) = aes_key_iv_from_words(k)?;
    let plain = aes_ctr_inner(&key, enc, &iv)?;
    if verify && !verify_mac_inner(&plain, k) {
        return Err("chunk MAC mismatch: downloaded bytes do not match the file key".into());
    }
    Ok(plain)
}

#[pyfunction]
fn aes_ecb(key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    aes_ecb_inner(key, data).map_err(PyValueError::new_err)
}

#[pyfunction]
fn aes_cbc(key: &[u8], data: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    aes_cbc_inner(key, data, iv).map_err(PyValueError::new_err)
}

#[pyfunction]
fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    aes_ecb_decrypt_inner(key, data).map_err(PyValueError::new_err)
}

#[pyfunction]
fn aes_cbc_decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    aes_cbc_decrypt_inner(key, data, iv).map_err(PyValueError::new_err)
}

#[pyfunction]
fn aes_ctr<'py>(py: Python<'py>, key: &[u8], data: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| aes_ctr_inner(key, data, iv));
    Ok(PyBytes::new(py, &out.map_err(PyValueError::new_err)?))
}

#[pyfunction]
fn verify_mac(py: Python<'_>, plain: &[u8], k: Vec<u32>) -> bool {
    py.allow_threads(|| verify_mac_inner(plain, &k))
}

#[pyfunction]
#[pyo3(signature = (data, k, verify = true))]
fn decrypt_bytes<'py>(
    py: Python<'py>,
    data: &[u8],
    k: Vec<u32>,
    verify: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| decrypt_bytes_inner(data, &k, verify));
    Ok(PyBytes::new(py, &out.map_err(PyValueError::new_err)?))
}

#[pymodule]
fn megacrypt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FileCipher>()?;
    m.add_function(wrap_pyfunction!(encrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(segment_ends, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ecb, m)?)?;
    m.add_function(wrap_pyfunction!(aes_cbc, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ecb_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ctr, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mac, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_bytes, m)?)?;
    m.add("__doc__", "MEGA/transfer.it AES-CTR + chunk-MAC encrypt and decrypt")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UL_KEY: [u32; 6] = [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn golden_vector_matches_openssl_path() {
        let (enc, key) = encrypt_bytes_inner(b"hello transfer.it e2e\n", &UL_KEY, 1 << 20).unwrap();
        assert_eq!(hex(&enc), "aba40842620a60071dd2ba25275b7e6fbd2adba1e250");
        assert_eq!(
            key,
            [1145324612, 1145324612, 825677689, 1756591280, 1431655765, 1717986918, 33940554, 754397428]
        );
    }

    #[test]
    fn empty_file_still_has_a_filekey() {
        let (enc, key) = encrypt_bytes_inner(b"", &UL_KEY, 1 << 20).unwrap();
        assert!(enc.is_empty());
        assert_eq!(key[0], 0x11111111 ^ 0x55555555);
    }

    #[test]
    fn chunk_size_does_not_change_output() {
        let data: Vec<u8> = (0..(0x20000 + 4096u32)).map(|i| (i % 251) as u8).collect();
        let (a, ka) = encrypt_bytes_inner(&data, &UL_KEY, 16).unwrap();
        let (b, kb) = encrypt_bytes_inner(&data, &UL_KEY, 1 << 20).unwrap();
        assert_eq!(a, b);
        assert_eq!(ka, kb);
        assert_eq!(a.len(), data.len());
    }

    #[test]
    fn streaming_source_pads_the_tail() {
        for data in [b"short".as_slice(), b"", b"0123456789abcde", b"0123456789abcdef"] {
            let mut core =
                Core::new(Box::new(Cursor::new(data.to_vec())), data.len() as u64, &UL_KEY, 1 << 20).unwrap();
            let mut out = Vec::new();
            loop {
                let piece = core.pull(4).unwrap();
                if piece.is_empty() {
                    break;
                }
                out.extend_from_slice(&piece);
            }
            core.finish();
            let (want, want_key) = encrypt_bytes_inner(data, &UL_KEY, 1 << 20).unwrap();
            assert_eq!(out, want, "{} bytes", data.len());
            assert_eq!(core.filekey.unwrap(), want_key, "{} bytes", data.len());
        }
    }

    #[test]
    fn padding_never_reuses_the_previous_chunk() {
        // the final chunk is short and unaligned: its padding must be zeros, not the tail of chunk 1
        for (size, chunk) in [(17usize, 16usize), (4097, 1024), (0x20000 + 1, 0x10000), (37, 16)] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (small, key_small) = encrypt_bytes_inner(&data, &UL_KEY, chunk).unwrap();
            let (big, key_big) = encrypt_bytes_inner(&data, &UL_KEY, 1 << 20).unwrap();
            assert_eq!(small, big, "size {size} chunk {chunk}");
            assert_eq!(key_small, key_big, "size {size} chunk {chunk}");
        }
    }

    #[test]
    fn read_returns_at_most_requested() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut core = Core::new(Box::new(Cursor::new(data.clone())), data.len() as u64, &UL_KEY, 4096).unwrap();
        assert_eq!(core.pull(1).unwrap().len(), 1);
        assert_eq!(core.pull(7).unwrap().len(), 7);
        assert_eq!(core.pull(200).unwrap().len(), 200);
        let mut rest = Vec::new();
        loop {
            let piece = core.pull(1000).unwrap();
            assert!(piece.len() <= 1000);
            if piece.is_empty() {
                break;
            }
            rest.extend_from_slice(&piece);
        }
        let (want, want_key) = encrypt_bytes_inner(&data, &UL_KEY, 4096).unwrap();
        assert_eq!(rest.len(), want.len() - 208);
        assert_eq!(core.filekey.unwrap(), want_key);
    }

    #[test]
    fn filekey_arrives_with_the_last_byte() {
        for size in [16usize, 100, 4096, 4097, 9000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut core = Core::new(Box::new(Cursor::new(data.clone())), size as u64, &UL_KEY, 4096).unwrap();
            let mut got = Vec::new();
            while got.len() < size {
                let piece = core.pull(size - got.len()).unwrap();
                assert!(!piece.is_empty(), "size {size}");
                got.extend_from_slice(&piece);
            }
            assert_eq!(got.len(), size);
            assert!(core.filekey.is_some(), "size {size}: key not published with the last byte");
            let (_, want_key) = encrypt_bytes_inner(&data, &UL_KEY, 4096).unwrap();
            assert_eq!(core.filekey.unwrap(), want_key, "size {size}");
        }
    }

    #[test]
    fn segment_boundaries_are_the_mega_ramp() {
        assert_eq!(mac_segment_ends(0), vec![0]);
        assert_eq!(mac_segment_ends(0x20000), vec![0x20000]);
        assert_eq!(mac_segment_ends(0x20010), vec![0x20000, 0x20010]);
        let huge = 3_692_512_458u64;
        let ends = mac_segment_ends(huge);
        assert_eq!(&ends[..7], &MAC_RAMP);
        assert_eq!(ends[ends.len() - 2], MAC_STEADY + ((huge - 1 - MAC_STEADY) / MAC_MAX) * MAC_MAX);
        assert_eq!(*ends.last().unwrap(), huge);
    }

    #[test]
    fn aes_ecb_and_cbc_match_known_blocks() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8) * 0x11;
        }
        let pt = b"0123456789abcdef";
        let ecb = aes_ecb_inner(&key, pt).unwrap();
        assert_eq!(ecb.len(), 16);
        assert_eq!(aes_ecb_inner(&key, pt).unwrap(), ecb);
        let iv = [0u8; 16];
        let cbc = aes_cbc_inner(&key, pt, &iv).unwrap();
        assert_eq!(cbc, ecb, "CBC with a zero IV equals ECB on one block");
        let two = [pt.as_slice(), pt.as_slice()].concat();
        let cbc2 = aes_cbc_inner(&key, &two, &iv).unwrap();
        assert_eq!(&cbc2[..16], &cbc[..]);
        assert_ne!(&cbc2[16..], &cbc[..]);
        assert!(aes_ecb_inner(&key, b"short").is_err());
        assert!(aes_cbc_inner(&key, pt, &[0u8; 8]).is_err());
        let enc = aes_ecb_inner(&key, pt).unwrap();
        assert_eq!(aes_ecb_decrypt_inner(&key, &enc).unwrap(), pt);
        let cbc_enc = aes_cbc_inner(&key, &two, &iv).unwrap();
        assert_eq!(aes_cbc_decrypt_inner(&key, &cbc_enc, &iv).unwrap(), two);
        let ctr = aes_ctr_inner(&key, pt, &iv).unwrap();
        assert_eq!(aes_ctr_inner(&key, &ctr, &iv).unwrap(), pt);
    }

    #[test]
    fn decrypt_bytes_roundtrips_encrypt_bytes() {
        for data in [b"".as_slice(), b"hello transfer.it e2e\n", b"0123456789abcdef!"] {
            let (enc, filekey) = encrypt_bytes_inner(data, &UL_KEY, 1 << 20).unwrap();
            let plain = decrypt_bytes_inner(&enc, &filekey, true).unwrap();
            assert_eq!(plain, data);
            assert!(verify_mac_inner(data, &filekey));
        }
        let (enc, filekey) = encrypt_bytes_inner(b"hello transfer.it e2e\n", &UL_KEY, 1 << 20).unwrap();
        let mut flipped = enc.clone();
        flipped[0] ^= 1;
        assert!(decrypt_bytes_inner(&flipped, &filekey, true).is_err());
        assert_eq!(decrypt_bytes_inner(&flipped, &filekey, false).unwrap().len(), enc.len());
        assert!(verify_mac_inner(b"", &[0; 10]));
        assert!(!verify_mac_inner(b"", &[0; 7]));
    }
}
