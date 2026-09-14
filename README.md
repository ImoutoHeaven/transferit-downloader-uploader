# transfer.it headless tools

Two command line scripts and one optional native extension for moving files
through [transfer.it](https://transfer.it) (MEGA) without a browser.

| Path | Purpose |
| --- | --- |
| `transferit_upload.py` | Upload files and folders, produce transfer links |
| `transferit_download.py` | Download one or more transfer links, plain or packed |
| `megacrypt/` | Rust extension that encrypts uploads; wheels in `megacrypt/dist/` |

## Requirements

- Python 3.8 or newer; both scripts are exercised on 3.8, 3.9, 3.10, and 3.11.
- `openssl` on `PATH` for the uploader (cipher fallback) and the downloader (decryption).
- Uploader: `pip install tqdm`.
- Downloader: `pip install curl_cffi`.
- Uploader, optional and recommended: the `megacrypt` wheel, which moves encryption
  into native code and releases the GIL.

## Install

```sh
pip install "megacrypt/dist/megacrypt-0.1.0-cp38-abi3-manylinux_2_34_x86_64.whl"   # Linux, glibc >= 2.34
pip install "megacrypt/dist/megacrypt-0.1.0-cp38-abi3-win_amd64.whl"               # Windows
```

The wheels use the stable ABI (abi3), so one wheel per platform serves every CPython
from 3.8 onward. Build your own with a Rust toolchain and `maturin`:

```sh
pip install maturin
cd megacrypt && python -m maturin build --release && pip install dist/*.whl
```

## Upload

```sh
python transferit_upload.py -j 4 /data/2026-08                      # tree mode, one link
python transferit_upload.py --mode split -j 4 /data/2026-08         # one link per folder
python transferit_upload.py -v --state job.json /data/2026-08       # phase log + resume file
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode tree` | yes | One link for the whole folder, relative paths preserved |
| `--mode split` | | One link per folder containing direct files |
| `-j, --jobs` | 4 | Total concurrent uploads, shared across folders |
| `--state` | `.transferit-upload.json` | Resume file, written atomically and kept out of the transfer |
| `-v, --verbose` | | Timestamped phase log on stderr with a stall watchdog |
| `--chunk-mib` | 8 | Streaming encrypt/read chunk per file |

Tree mode takes exactly one path and prints one link. Split mode takes any number of
paths, prints `folder: link` for each folder that published, then the bare links.

### Behaviour

- A transfer link appears once every file and folder is in place. Registration of each
  file (`xp`) precedes the close call (`xc`) that makes the link public.
- Fail-closed. A tree upload stops when a file keeps failing, which leaves the transfer
  unclosed and unpublished. A split upload skips only the failing folder's link and
  publishes the folders that completed.
- Folders holding direct files appear in the transfer.
- Resume: state lives in the `--state` JSON (session, transfer handles, created folders,
  per-file size/mtime/done, published link). Re-running the same command continues where
  the previous run stopped; completed files are skipped.
- Ctrl+C ends the process immediately. State is already on disk, so the next run resumes.
- Progress shows a file-count bar from `tqdm`, replaced by the phase log under `-v`.
- Streaming. Encryption and upload both work in chunks: peak memory tracks `--chunk-mib`
  and the socket buffer. Per in-flight file, budget roughly three times the chunk for
  encryption plus one 32 MiB write buffer.
- Socket writes carry 32 MiB each, which roughly halves wall clock against 8 KiB writes.
- `-j` bounds total concurrency: split mode divides it between folder workers and the
  file workers inside each folder.
- The per-request socket timeout is `max(120, size / 256KiB)` seconds, measured as
  inactivity on the socket, so a large file gets a generous window while a silent peer
  ends the attempt.
- The state JSON is validated when loaded; a malformed or half-written record stops the
  run with `error: ...` and a non-zero exit rather than being trusted.
- Only folders holding direct files appear in the transfer; split mode targets those
  folders, and tree mode creates the ancestor folders its relative paths need.

### Traces

`-v` prints one line per phase: API calls with latency, folder creation, upload URL
acquisition, POST start and throughput, node registration, close, and the final link.
A watchdog thread reports every in-flight file that has been idle for 25 seconds:

```
[20:04:34] verbose on; python=3.11.9 platform=win32
[20:04:34] encoder=megacrypt .../site-packages/megacrypt/__init__.py
[20:04:34] mode=tree root=/data/2026-08 files=2 (state=tr.json)
[20:04:35] api up ok in 1.44s
[20:04:36] api us ok in 1.41s
[20:04:38] transfer created xh=TfwbNu4jFLSQ
[20:04:39] folder sub created in 1.52s
[20:04:39] queue: 2 file(s), 2 to upload, jobs=2
[20:04:41] upload a.bin: got upload URL host=gfs440n010.userstorage.mega.co.nz in 1.59s
[20:04:41] POST a.bin: sending 3145728 bytes to gfs440n010.userstorage.mega.co.nz (socket timeout 120s, encrypt chunk 8 MiB, socket write 32 MiB)
[20:04:43] POST a.bin: done in 1.5s (1.98 MiB/s), response 36 bytes
[20:04:44] upload a.bin: complete in 4.5s
[20:04:44] <-- a.bin ok in 4.5s (state saved)
[20:04:44] all files uploaded; closing transfer (xc)
[20:04:45] link https://transfer.it/t/TfwbNu4jFLSQ
```

The first verbose line names the encoder, either `megacrypt` with its path or
`openssl fallback`.

## Download

```sh
python transferit_download.py -o downloads https://transfer.it/t/XXXXXXXXXXXX
python transferit_download.py -j 8 --chunk-size 8388608 https://transfer.it/t/A https://transfer.it/t/B
python transferit_download.py --zip -o downloads https://transfer.it/t/XXXXXXXXXXXX
python transferit_download.py --password "hunter2" https://transfer.it/t/XXXXXXXXXXXX
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --out` | `downloads` | Output root; each link writes under `<out>/<link id>/` |
| `-j, --jobs` | 4 | Total concurrent requests, shared across links, files and ranges |
| `--chunk-size` | 1 MiB | Byte range size per range request |
| `--zip` | | Packed download: the server zip when the transfer offers one, otherwise a local zip |
| `--no-verify` | | Skip the chunk MAC check on decrypted files |
| `--password` | | Plaintext password for password-protected links |
Relative paths inside a link are recreated on disk; the packed mode keeps the same
structure inside the archive. Intermediate directories are created as needed. Every range
response is required to carry exactly the requested length, and each decrypted file is
checked against the chunk MAC in its file key (keys carrying per-chunk MACs from other
clients are skipped).

Node names are reduced to a single safe path component, `.` and `..` members are dropped,
and every write is verified to stay inside the destination directory. Two nodes that would
land on the same path are refused, as is a server archive whose members would escape on
extraction; members of the archive this tool builds are sanitized the same way.

## Encoder

`transferit_upload.py` imports `megacrypt` and uses its `FileCipher` when the extension
is installed; otherwise it runs the equivalent openssl pipeline in `EncStream`. Both
implement the same wire format, and the test suite checks the two against each other
byte for byte.

`megacrypt` exposes:

```python
megacrypt.FileCipher(path, size, ul_key, chunk)   # .read(n) -> bytes, .filekey -> 8 words
megacrypt.encrypt_bytes(data, ul_key, chunk)      # -> (bytes, [8 words])
megacrypt.segment_ends(padded_len)                # MEGA chunk-MAC boundaries
```

Encryption runs inside `Python::allow_threads`, so `--jobs` threads encrypt in parallel.
Measured on 8-core hosts, 128 MiB file, one run each:

| Encoder | 1 file | 4 concurrent |
| --- | --- | --- |
| `megacrypt` (Windows) | 607 MiB/s | 0.30 s |
| `megacrypt` (container, 4 CPUs) | 413 MiB/s | 0.64 s |
| openssl pipeline (Windows) | 20 MiB/s | 7.96 s |
| openssl pipeline (container, 4 CPUs) | 90 MiB/s | 11.15 s |

## Wire format

- Anonymous session: `up`, `us` on `g.api.mega.co.nz`; transfers created with `xn`,
  files registered with `xp`, folders with `xp` (`t: 1`), close with `xc`, all on
  `bt7.api.mega.co.nz`.
- API calls are JSON arrays over `/cs?id=...&v=3&wcv=...&domain=transferit&sid=...`,
  with `MEGA-Chrome-Antileak` set to the path and query. A `402` answer carries an
  `X-Hashcash` challenge that the client solves and resends.
- File key: 6 words. First 16 bytes are the AES-128 key, the last 8 bytes the nonce.
- Content: AES-128-CTR with the counter starting at `nonce || 0^8`, 128-bit big-endian
  increments, applied to the file padded to a 16-byte multiple.
- Chunk MACs: segments ending at 128 KiB, 384 KiB, 768 KiB, 1280 KiB, 1920 KiB,
  2688 KiB, 3584 KiB, and 4608 KiB, then at 1 MiB steps. Each segment is a fresh CBC
  chain keyed by the file key with IV `nonce || nonce`, and its 16-byte result is folded
  into a condensed state by XOR plus one AES block. The condensed state becomes words
  2..7 of the file key.
- Upload: `{"a": "u", "s": size, "ssl": 1}` returns a `userstorage` URL whose path takes
  one POST carrying the whole encrypted file; the response body is a 36-character handle
  used by `xp`.
- Parallelism comes from multiple files in flight. One upload URL serves one whole-file
  POST.
- Attribute blocks (`a` on every node) are `MEGA` plus JSON, encrypted with AES-128-CBC
  and a zero IV, keyed from the node key.

## Verification

```sh
python transferit_upload.py --selfcheck       # cipher vectors, MAC boundaries, native vs openssl, state, interrupts
python transferit_download.py --selfcheck     # decryption and MAC vectors, ranges, hostile names, queue
cd megacrypt && cargo test --release          # cipher vectors, segment ramp, tail padding
```

Linux builds, encoder equivalence, throughput, and a real upload/download round trip run
inside a container:

```sh
docker run --rm --cpus 4 \
  -v "$PWD:/w:ro" -v "$PWD/megacrypt/dist:/out" -v "$PWD/megacrypt/verify-linux.sh:/verify.sh:ro" \
  rust:1-slim-bookworm sh /verify.sh
```

The scripts exit non-zero on failure and print `error: ...` on stderr. Self-checks print
`selfcheck ok`.
