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

The optional `megacrypt` extension does AES in native code. Its streaming encryptor and
AES-CTR primitive release the GIL; the CBC primitive holds it for each call. Build it with
a Rust toolchain:

```sh
pip install maturin
cd megacrypt && python -m maturin build --release --out dist && pip install dist/*.whl
```

`--out dist` names the directory the install command reads; maturin writes to `target/wheels`
by default. The wheels use the stable ABI (abi3), so one wheel per platform serves every
CPython from 3.8 on. A Python-only install uses `openssl` on `PATH`.

## Upload

```sh
python transferit_upload.py -j 4 /data/2026-08                                           # one link for the folder
python transferit_upload.py --mode split --state split.json -j 4 /data/2026-08           # one link per folder
python transferit_upload.py --mode files -o links --state files.json -j 4 /data/2026-08  # one link file per file
python transferit_upload.py -v --state job.json /data/2026-08                            # phase log and resume file
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode` | `tree` | `tree`: one link, relative paths preserved. `split`: one link per folder holding direct files. `files`: one link per regular file under a directory, recursive |
| `-o, --out` | | Link output directory for `--mode files` (rejected in other modes) |
| `-j, --jobs` | 4 | Concurrent uploads, shared across folders and files |
| `--state` | `.transferit-upload.json` | Resume file, written atomically and kept out of the transfer |
| `-v, --verbose` | | Timestamped phase log on stderr, with a stall watchdog |
| `--chunk-mib` | 8 | Encrypt and read chunk per file; socket writes stay at 32 MiB |

Tree mode takes one path and prints one link. Split mode takes one or more paths and creates
one transfer per folder holding direct files (plus any file path given directly). Files mode
takes one input directory and `-o, --out`, walks it recursively without following directory
symlinks, and creates an independent transfer and link for every regular file, including
zero-byte files, while omitting empty directories; an input directory with no uploadable
regular files (excluding `<state>` and `<state>.tmp`) fails with `error: no files`. Both
`split` and `files` print `<path>: <link>` for each published transfer followed by `---` and
the bare URLs on stdout.

In `files` mode, each file writes `<out>/<rel>-link.txt`, appending `-link.txt` to the full
filename (`sub/photo.jpg` -> `links/sub/photo.jpg-link.txt`), as UTF-8 `<link>\n` via an
atomic rename as soon as that file's transfer closes. Resolved input and output directories
must not overlap in either direction. Symbolic file aliases in the source tree, symlinked or
non-directory parents under the resolved `--out` root, colliding `-link.txt` paths, and paths
that overlap `--state` or `<state>.tmp` are rejected before upload. Existing files under
`--out` are never overwritten; a destination file may remain only when it already contains
that file's saved `<link>\n`.

Files stream, so peak memory per in-flight file is bounded by a few chunks of `--chunk-mib`
plus one 32 MiB write buffer, and socket inactivity is tolerated for `max(120, size / 256 KiB)`
seconds.

Uploads fail closed: a link is emitted only after every file in its transfer is registered
with unchanged size and modification time and closing succeeds. In `split` and `files`
modes, each failed target reports an error while the remaining targets finish; any failure
makes the process exit non-zero. If writing `-link.txt` fails after closing, the published
link remains in `--state` for reconstruction on resume. `--state` is bound to `--mode` and,
in `tree` and `files` modes, the resolved input root (`<state>` and `<state>.tmp` are skipped
when inside the input tree); use the same `--state` to resume a job and a separate `--state`
for another mode or root.

Re-running the same command resumes from `--state`, and Ctrl+C ends the process immediately
with saved state on disk. In `files` mode, each file saves its confirmed upload metadata to
`--state`, closes its transfer, saves the published link to `--state`, and then writes
`<rel>-link.txt`. On resume, closed transfers skip upload and reconstruct any missing
`-link.txt` files directly from `--state` (including into a new disjoint `--out` directory),
confirmed uploads whose close did not finish retry closing only, and unconfirmed uploads
(including files interrupted or modified mid-upload) start a fresh transfer on resume to
avoid duplicate registered nodes. In-flight files restart rather than resume from a byte
offset. Confirmed uploads are checked by `size`, `mtime`, and `mtime_ns`, not a content
hash; if a source file changes after its upload is confirmed, `files` mode fails rather than
reusing or overwriting its link, and uploading the modified file requires a new `--state` and
`--out`.

## Download

```sh
python transferit_download.py -o downloads https://transfer.it/t/XXXXXXXXXXXX
python transferit_download.py -v --state job.json -j 8 https://transfer.it/t/A https://transfer.it/t/B
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
| `--state` | `.transferit-download.json` | Resume file, written atomically |
| `-v, --verbose` | | Timestamped phase log on stderr, with a stall watchdog |
| `--no-verify` | | Skip the chunk MAC check on decrypted files |

Relative paths inside a link are recreated on disk, with intermediate directories created
as needed. Every range response carries exactly the requested length, and each file is
checked against the condensed chunk MAC in its file key. Keys in the per-chunk MAC form
carry a different layout, so those files are written unverified; `--no-verify` does the same
for every file.

Downloads stage ranges directly on disk, then decrypt and verify in segments of at most
1 MiB. Memory covers small buffers per worker and range-scheduling metadata. Completed
files replace their destinations atomically after verification. Local ZIP creation adds
each completed member from disk; temporary disk space holds the archive and active members.

Names are reduced to one safe path component, `.` and `..` members are dropped, and every
write is verified to stay inside the destination. Two nodes that would land on the same
path, or an ambiguous file/directory nest, stop the run before anything is overwritten.

A per-link file bar writes to stderr. `-v` replaces it with a timestamped phase log and a
stall watchdog. Ctrl+C ends the process immediately, with completed files already recorded
in the state file. Re-running the same command skips those files when the destination size
still matches.

## Verification

```sh
python transferit_upload.py --selfcheck     # cipher vectors, MAC boundaries, native vs openssl, retries, state, per-file resume and link safety
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
