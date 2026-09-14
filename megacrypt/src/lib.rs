//! MEGA / transfer.it file encryption as a native Python extension.
//!
//! Same wire format as the openssl fallback in `transferit_upload.py`: AES-128-CTR over the
//! whole file (128-bit big-endian counter starting at `nonce || 0^8`) plus MEGA's chunk
//! CBC-MAC (ramp of 128 KiB .. 1 MiB segments, each a fresh chain with IV `nonce || nonce`,
//! condensed into the 8-word file key). One `read()` call runs without the GIL, so several
//! upload threads actually run in parallel instead of queueing on the interpreter lock.

use std::fs::File;
use std::io::{Cursor, Read};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
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
        let mut out: Vec<u8> = Vec::with_capacity(n);
        while out.len() < n {
            if self.off >= self.padded {
                self.finish();
                break;
            }
            let start = self.off;
            let want = std::cmp::min(self.chunk as u64, self.padded - start) as usize;
            let real = std::cmp::min(want as u64, self.size.saturating_sub(start)) as usize;
            self.buf.resize(want, 0);
            let mut buf = std::mem::take(&mut self.buf);
            read_full(&mut *self.src, &mut buf[..real])?; // the tail beyond `size` stays zero padding
            let keep = std::cmp::min(want as u64, self.size.saturating_sub(start)) as usize;
            self.ct.resize(want, 0);
            self.ct.copy_from_slice(&buf);
            self.ctr.apply_keystream(&mut self.ct);
            out.extend_from_slice(&self.ct[..keep]);
            self.feed_mac(&buf);
            self.buf = buf;
            self.off = start + want as u64;
        }
        Ok(out)
    }
}

/// MEGA file encryption of an in-memory buffer: returns (ciphertext, file key words).
pub fn encrypt_bytes_inner(data: &[u8], ul_key: &[u32], chunk: usize) -> Result<(Vec<u8>, [u32; 8]), String> {
    let chunk = chunk.max(AES_BLOCK as usize);
    let padded = data.len().div_ceil(16) * 16;
    let mut src = data.to_vec();
    src.resize(padded, 0); // the MAC sees the zero-padded tail
    let mut core = Core::new(Box::new(Cursor::new(src)), data.len() as u64, ul_key, chunk)?;
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

#[pymodule]
fn megacrypt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FileCipher>()?;
    m.add_function(wrap_pyfunction!(encrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(segment_ends, m)?)?;
    m.add("__doc__", "MEGA/transfer.it AES-CTR + chunk-MAC encryption")?;
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
}
