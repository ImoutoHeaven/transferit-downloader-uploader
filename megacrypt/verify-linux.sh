#!/bin/sh
# Docker-side verification for the megacrypt native encoder.
# Builds the wheel inside the container, installs it, then checks:
#   1. native output == openssl reference output
#   2. single-file throughput and GIL-free parallel scaling
#   3. real transfer.it round trip: upload with the native encoder, download, byte compare
# Mounts: /w  = repo root (read only)   /out = wheel output directory (writable)
set -eu

PIP="python3 -m pip install --break-system-packages --quiet"

apt-get update -qq
apt-get install -y -qq python3 python3-dev python3-pip openssl >/dev/null
$PIP maturin tqdm curl_cffi

cp -r /w/megacrypt /tmp/megacrypt
cd /tmp/megacrypt
python3 -m maturin build --release --out /out
WHEEL=$(ls /out/*manylinux*.whl | tail -1)
echo "installing $WHEEL"
python3 -m pip install --break-system-packages --quiet --force-reinstall --no-deps "$WHEEL"

cd /w
echo "=== module ==="
python3 -c "import megacrypt, sys; print(megacrypt.__file__); print('golden', megacrypt.encrypt_bytes(b'hello transfer.it e2e\n', [0x11111111,0x22222222,0x33333333,0x44444444,0x55555555,0x66666666])[0].hex())"

echo "=== selfcheck (native encoder loaded) ==="
python3 transferit_upload.py --selfcheck

echo "=== native vs openssl equivalence ==="
python3 - <<'PY'
import os
import megacrypt
import transferit_upload as u

k = u.rand_a32(6)
sizes = (0, 1, 17, 4096, 0x20000, 0x20000 + 16, 0x60000, 0x60000 + 1000, 3 << 20)
bad = []
for s in sizes:
    d = os.urandom(s)
    enc_ref, key_ref = u.encrypt_file(d, k)
    enc_nat, key_nat = megacrypt.encrypt_bytes(d, k, 8 << 20)
    if bytes(enc_nat) != enc_ref or list(key_nat) != key_ref:
        bad.append(s)
print("sizes", len(sizes), "mismatches", bad)
assert not bad
PY

echo "=== throughput and parallel scaling (128 MiB file) ==="
python3 - <<'PY'
import os, threading, time
from pathlib import Path

import megacrypt
import transferit_upload as u

size = 128 << 20
p = Path("/tmp/bench.bin")
blk = os.urandom(1 << 20)
with p.open("wb") as fh:
    for _ in range(size >> 20):
        fh.write(blk)
k = u.rand_a32(6)


def native():
    c = megacrypt.FileCipher(str(p), size, k, 8 << 20)
    while c.read(32 << 20):
        pass
    assert c.filekey


def openssl():
    s = u.EncStream(p.open("rb"), size, k, chunk=8 << 20)
    while s.read(32 << 20):
        pass
    assert s.filekey


def run(fn, n):
    t0 = time.perf_counter()
    ts = [threading.Thread(target=fn) for _ in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return time.perf_counter() - t0


print("cpus", os.cpu_count())
for name, fn in (("native", native), ("openssl", openssl)):
    one = run(fn, 1)
    four = run(fn, 4)
    print(f"{name:>8}: 1 file {one:6.2f}s ({size / 1048576 / one:6.1f} MiB/s)   4 concurrent {four:6.2f}s")
p.unlink()
PY

echo "=== real e2e: upload (native) -> download -> byte compare ==="
mkdir -p /tmp/e2e/src/Part11/sub
python3 - <<'PY'
import os
from pathlib import Path

blk = os.urandom(1 << 20)
plan = (("/tmp/e2e/src/Part11/a.rar", 40), ("/tmp/e2e/src/Part11/b.rar", 24), ("/tmp/e2e/src/Part11/sub/c.bin", 8))
for name, mb in plan:
    with Path(name).open("wb") as fh:
        for _ in range(mb):
            fh.write(blk)
PY
python3 /w/transferit_upload.py -v -j 3 --state /tmp/e2e/state.json /tmp/e2e/src >/tmp/e2e/out.log 2>/tmp/e2e/err.log
grep -E "encoder=|link " /tmp/e2e/err.log || true
LINK=$(tail -1 /tmp/e2e/out.log)
echo "link: $LINK"
XH=${LINK##*/}
python3 - "$XH" <<'PY'
import shutil, sys
from pathlib import Path

from transferit_download import MegaAPI, download_transfer

xh = sys.argv[1]
out = Path("/tmp/e2e/dl")
shutil.rmtree(out, ignore_errors=True)
paths = download_transfer(MegaAPI(), xh, out / xh, jobs=3, chunk=8 << 20, packed=False)
bad = [str(p) for p in paths if p.read_bytes() != (Path("/tmp/e2e/src") / p.relative_to(out / xh)).read_bytes()]
print("downloaded", len(paths), "mismatches", bad)
assert not bad
print("LINUX_NATIVE_E2E_OK")
PY
