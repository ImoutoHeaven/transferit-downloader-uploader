# transfer.it headless tools

Move files through [transfer.it](https://transfer.it) (MEGA) from a shell:
`transferit_upload.py` uploads a folder and publishes links,
`transferit_download.py` fetches links, and the Rust extension in `megacrypt/` does MEGA
AES in native code.

## Requirements

Python 3.8 or newer.

```sh
pip install tqdm curl_cffi
```

The optional `megacrypt` extension does AES in native code and releases the GIL, so `-j`
threads encrypt and decrypt in parallel. Build it with a Rust toolchain:

```sh
pip install maturin
cd megacrypt && python -m maturin build --release --out dist && pip install dist/*.whl
```

`--out dist` names the directory the install command reads; maturin writes to `target/wheels`
by default. The wheels use the stable ABI (abi3), so one wheel per platform serves every
CPython from 3.8 on. A Python-only install uses `openssl` on `PATH`.

## Upload

```sh
python transferit_upload.py -j 4 /data/2026-08                    # one link for the folder
python transferit_upload.py --mode split -j 4 /data/2026-08       # one link per folder
python transferit_upload.py -v --state job.json /data/2026-08     # phase log and resume file
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode` | `tree` | `tree`: one link, relative paths preserved. `split`: one link per folder holding direct files |
| `-j, --jobs` | 4 | Concurrent uploads, shared across folders |
| `--state` | `.transferit-upload.json` | Resume file, written atomically and kept out of the transfer |
| `-v, --verbose` | | Timestamped phase log on stderr, with a stall watchdog |
| `--chunk-mib` | 8 | Encrypt and read chunk per file; socket writes stay at 32 MiB |

Tree mode takes one path and prints one link. Split mode takes any number of paths and
prints `folder: link` for each folder that published. A link appears once every file is
registered and the transfer is closed.

Files stream, so peak memory per in-flight file is bounded by a few chunks of `--chunk-mib`
plus one 32 MiB write buffer, and socket inactivity is tolerated for `max(120, size / 256 KiB)`
seconds.

Uploads fail closed: a file that keeps failing leaves the transfer unclosed and its link
unpublished, while split mode still publishes the folders that completed. Re-running the
same command resumes from the state file and skips completed files, and Ctrl+C ends the
process immediately with that state already on disk.

## Download

```sh
python transferit_download.py -o downloads https://transfer.it/t/XXXXXXXXXXXX
python transferit_download.py -v -j 8 https://transfer.it/t/A https://transfer.it/t/B
python transferit_download.py --zip -o downloads https://transfer.it/t/XXXXXXXXXXXX
python transferit_download.py --password "hunter2" https://transfer.it/t/XXXXXXXXXXXX
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --out` | `downloads` | Output root; each link writes under `<out>/<link id>/` |
| `-j, --jobs` | 4 | Concurrent requests, shared across links, files and ranges |
| `--chunk-size` | 8 MiB | Bytes per range request |
| `--zip` | | One archive per link: the transfer zip when offered, a locally built zip otherwise |
| `--password` | | Plaintext password for protected links |
| `-v, --verbose` | | Timestamped phase log on stderr, with a stall watchdog |
| `--no-verify` | | Skip the chunk MAC check on decrypted files |

Relative paths inside a link are recreated on disk, with intermediate directories created
as needed. Every range response carries exactly the requested length, and each file is
checked against the condensed chunk MAC in its file key. Keys in the per-chunk MAC form
carry a different layout, so those files are written unverified; `--no-verify` does the same
for every file.

Names are reduced to one safe path component, `.` and `..` members are dropped, and every
write is verified to stay inside the destination. Two nodes that would land on the same
path, or an ambiguous file/directory nest, stop the run before anything is overwritten.

A per-link file bar writes to stderr. `-v` replaces it with a timestamped phase log and a
stall watchdog. Ctrl+C ends the process immediately.

## Verification

```sh
python transferit_upload.py --selfcheck     # cipher vectors, MAC boundaries, native vs openssl, retries, state
python transferit_download.py --selfcheck   # decryption and MAC vectors, ranges, tree validation, hostile names
cd megacrypt && cargo test --release        # cipher vectors, segment ramp, tail padding, key publication
```

Linux builds, encoder equivalence, throughput, and a real upload and download round trip run
inside a container:

```sh
mkdir -p megacrypt/dist
docker run --rm --cpus 4 \
  -v "$PWD:/w:ro" -v "$PWD/megacrypt/dist:/out" -v "$PWD/megacrypt/verify-linux.sh:/verify.sh:ro" \
  rust:1-slim-bookworm sh /verify.sh
```

Both self-checks run on CPython 3.8 and 3.11. Failures exit non-zero and print `error: ...`
on stderr; self-checks print `selfcheck ok`.
