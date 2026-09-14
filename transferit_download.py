#!/usr/bin/env python3
"""Headless transfer.it downloader. curl_cffi + openssl."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import signal
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import urlparse

from curl_cffi import requests
from curl_cffi.requests.exceptions import RequestException

BT7 = "https://bt7.api.mega.co.nz/"
WCV = "2.246.1130"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
)
RETRY_HTTP = {408, 429, 500, 502, 503, 504}
RETRY_MEGA = {-3, -4, -6}
ATTEMPTS = 5
_tls = threading.local()


class Retry(Exception):
    pass


def session() -> requests.Session:
    s = getattr(_tls, "s", None)
    if s is None:
        s = requests.Session(impersonate="chrome")
        _tls.s = s
    return s


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def a32_to_bytes(a: list[int]) -> bytes:
    return struct.pack(">%dI" % len(a), *(_u32(x) for x in a))


def bytes_to_a32(b: bytes) -> list[int]:
    if len(b) % 4:
        b += b"\0" * (4 - len(b) % 4)
    return list(struct.unpack(">%dI" % (len(b) // 4), b))


def b64u_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def b64u_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")


def openssl_aes(mode: str, key: bytes, data: bytes, iv: bytes | None = None, decrypt: bool = False) -> bytes:
    if len(data) % 16:
        data = data + b"\0" * (16 - len(data) % 16)
    args = ["openssl", "enc"]
    if decrypt:
        args.append("-d")
    args += [f"-aes-128-{mode}", "-K", key.hex(), "-nopad"]
    if mode != "ecb":
        args += ["-iv", (iv or b"\0" * 16).hex()]
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf-8", "replace") or "openssl failed")
    return p.stdout


def aes_key_iv(k: list[int]) -> tuple[bytes, bytes]:
    key = a32_to_bytes(
        [
            k[0] ^ (k[4] if len(k) > 4 else 0),
            k[1] ^ (k[5] if len(k) > 5 else 0),
            k[2] ^ (k[6] if len(k) > 6 else 0),
            k[3] ^ (k[7] if len(k) > 7 else 0),
        ]
    )
    iv = (a32_to_bytes(k[4:6]) + b"\0" * 8) if len(k) >= 6 else b"\0" * 16
    return key, iv


def decrypt_attr(at: str, k: list[int]) -> dict:
    raw = openssl_aes("cbc", aes_key_iv(k)[0], b64u_decode(at), decrypt=True)
    raw = raw.split(b"\0", 1)[0]
    if not raw.startswith(b"MEGA"):
        raise RuntimeError("bad attr")
    return json.loads(raw[4:] or "{}")


def decrypt_file(enc: bytes, k: list[int]) -> bytes:
    if not enc:
        return b""
    key, iv = aes_key_iv(k)
    return openssl_aes("ctr", key, enc, iv, decrypt=True)[: len(enc)]


MAC_RAMP = (0x20000, 0x60000, 0xC0000, 0x140000, 0x1E0000, 0x2A0000, 0x380000)
MAC_STEADY = 0x480000
MAC_MAX = 0x100000


def mac_segment_ends(padded_len: int) -> list[int]:
    """MEGA chunk-MAC boundaries for a zero-padded length."""
    ends = [p for p in MAC_RAMP if p < padded_len]
    pos = MAC_STEADY
    while pos < padded_len:
        ends.append(pos)
        pos += MAC_MAX
    ends.append(padded_len)
    return ends


def verify_mac(plain: bytes, k: list[int]) -> bool:
    """Recompute the MEGA chunk MAC over `plain` and compare it with key words 6 and 7.

    Keys carrying extra per-chunk MACs (more than 8 words) come from clients that chunk
    differently, so there is nothing to compare against and the check passes. A key with
    fewer than 8 words is malformed for a file node and fails.
    """
    if len(k) > 8:
        return True
    if len(k) < 8:
        return False
    key, _ = aes_key_iv(k)
    mac_iv = a32_to_bytes(k[4:6]) * 2
    padded = plain + b"\0" * (-len(plain) % 16)
    cond = [0, 0, 0, 0]
    start = 0
    for end in mac_segment_ends(len(padded)):
        seg = padded[start:end]
        start = end
        mac = openssl_aes("cbc", key, seg, mac_iv)[-16:] if seg else mac_iv
        words = bytes_to_a32(mac)
        mixed = a32_to_bytes([c ^ w for c, w in zip(cond, words)])
        cond = bytes_to_a32(openssl_aes("ecb", key, mixed)[:16])
    return cond[0] ^ cond[1] == k[6] and cond[2] ^ cond[3] == k[7]


def decrypt_verified(enc: bytes, k: list[int], verify: bool = True) -> bytes:
    """Decrypt and, when the key carries a meta MAC, refuse data that fails it."""
    plain = decrypt_file(enc, k)
    if verify and not verify_mac(plain, k):
        raise RuntimeError("chunk MAC mismatch: downloaded bytes do not match the file key")
    return plain


def install_fast_interrupt() -> None:
    """Exit immediately on Ctrl+C; a stalled range request would otherwise hold the process."""

    def _die(_sig, _frame):
        os._exit(130)

    signal.signal(signal.SIGINT, _die)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _die)


def _backoff(i: int) -> None:
    time.sleep(min(8.0, 0.5 * (2**i)) + secrets.randbelow(250) / 1000.0)


def retryable(exc: BaseException) -> bool:
    if isinstance(exc, Retry):
        return True
    if isinstance(exc, RequestException):
        return True
    return False


def retry(fn, attempts: int = ATTEMPTS):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            last = e
            if not retryable(e) or i + 1 == attempts:
                raise
            _backoff(i)
    raise last  # pragma: no cover


def hashcash(token_b64: str, easiness: int) -> str:
    token = b64u_decode(token_b64)
    threshold = (((easiness & 63) << 1) + 1) << ((easiness >> 6) * 7 + 3)
    buf = bytearray(4 + 262144 * 48)
    for i in range(262144):
        buf[4 + i * 48 : 4 + i * 48 + len(token)] = token
    while True:
        digest = hashlib.sha256(buf).digest()
        if int.from_bytes(digest[:4], "big") <= threshold:
            return b64u_encode(bytes(buf[:4]))
        j = 0
        while True:
            buf[j] = (buf[j] + 1) & 0xFF
            if buf[j]:
                break
            j += 1


def create_password(xh: str, password: str) -> str:
    salt = b64u_decode(xh)[-6:] * 3
    dk = hashlib.pbkdf2_hmac("sha256", password.strip().encode("utf-8"), salt, 100000, dklen=32)
    return b64u_encode(dk)


XH_ALPHABET = set(string.ascii_letters + string.digits + "-_")


def parse_xh(s: str) -> str:
    s = s.strip()
    if "/t/" in s:
        s = s.rsplit("/t/", 1)[-1]
    s = s.split("?", 1)[0].strip("/")
    if len(s) != 12 or not set(s) <= XH_ALPHABET:
        raise ValueError(f"bad transfer.it link: {s}")
    return s


WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
WIN_RESERVED |= {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
WIN_RESERVED |= {f"COM{s}" for s in "\u00b9\u00b2\u00b3"} | {f"LPT{s}" for s in "\u00b9\u00b2\u00b3"}


def safe_name(name: str) -> str:
    """One path component that cannot escape a directory on either platform."""
    name = name.replace("\\", "/").split("/")[-1].replace("\x00", "").strip()
    # ':' would introduce a Windows drive or stream path when joined onto a directory
    name = "".join(c for c in name if c.isprintable() and c != ":")
    dots = name if set(name) <= {"."} else ""
    name = name.rstrip(" .")  # Win32 drops trailing dots and spaces, aliasing other names
    if dots:
        name = "_" * max(1, len(dots))
    if name.split(".")[0].upper() in WIN_RESERVED:
        name = "_" + name
    return name or "file"


def safe_rel(rel: str) -> str:
    """Join cleaned components, dropping `.`, `..` and empty members."""
    parts = [safe_name(raw) for raw in rel.replace("\\", "/").split("/") if raw not in ("", ".", "..")]
    return "/".join(parts) or "file"


def under(root: Path, path: Path) -> bool:
    """True when `path` stays inside `root` after resolution."""
    root_s, path_s = str(root.resolve()), str(path.resolve())
    return path_s == root_s or path_s.startswith(root_s.rstrip("/\\") + os.sep)


def ranges(size: int, chunk: int) -> list[tuple[int, int]]:
    if size <= 0:
        return []
    out = []
    i = 0
    while i < size:
        j = min(i + chunk, size) - 1
        out.append((i, j))
        i = j + 1
    return out


def split_jobs(total: int, parallel: int) -> int:
    """Workers to give each parallel unit so the product stays within `total`."""
    return max(1, total // max(1, parallel))


def queue_run(items: list, fn, jobs: int, attempts: int = ATTEMPTS) -> list:
    """Task queue + retry queue. Returns results in input order."""
    if not items:
        return []
    q: Queue = Queue()
    rq: Queue = Queue()
    out = [None] * len(items)
    failed: list[tuple] = []
    for i, item in enumerate(items):
        q.put((i, item, 0))

    def work() -> None:
        while True:
            try:
                idx, item, n = q.get(timeout=0.05)
            except Empty:
                return
            try:
                out[idx] = fn(item)
            except Exception as e:
                if retryable(e) and n + 1 < attempts:
                    _backoff(n)
                    rq.put((idx, item, n + 1))
                else:
                    failed.append((item, e))
            finally:
                q.task_done()

    while True:
        nwork = max(1, min(jobs, q.qsize() or 1))
        with ThreadPoolExecutor(max_workers=nwork) as ex:
            futs = [ex.submit(work) for _ in range(nwork)]
            q.join()
            for f in futs:
                f.result()
        if rq.empty():
            break
        while not rq.empty():
            q.put(rq.get())
    if failed:
        item, e = failed[0]
        raise RuntimeError(f"task failed: {item}: {e}") from e
    return out


class MegaAPI:
    def __init__(self):
        self.seq = secrets.randbelow(10**8) + 10**7
        self.pws: dict[str, str] = {}
        self._lock = threading.Lock()  # ponytail: global seq lock

    def xqs(self, xh: str) -> str:
        q = f"&x={xh}"
        if xh in self.pws:
            q += f"&pw={self.pws[xh]}"
        return q

    def _qs(self, extra: str = "") -> str:
        with self._lock:
            seq = self.seq
            self.seq += 1
        q = f"id={seq}&v=3&lang=en&wcv={WCV}&domain=transferit{extra}&bc=1"
        return q

    def call(self, payload, extra: str = ""):
        body = json.dumps(payload if isinstance(payload, list) else [payload], separators=(",", ":"))
        cash = None
        last = None
        q = self._qs(extra)
        for attempt in range(8):
            if cash is None:
                q = self._qs(extra)
            headers = {
                "Content-Type": "text/plain;charset=UTF-8",
                "Origin": "https://transfer.it",
                "Referer": "https://transfer.it/",
                "User-Agent": UA,
                "MEGA-Chrome-Antileak": f"/cs?{q}",
            }
            if cash:
                headers["X-Hashcash"] = cash
            try:
                r = session().post(f"{BT7}cs?", headers=headers, data=body, timeout=60)
            except RequestException as e:
                last = e
                cash = None
                _backoff(attempt)
                continue
            if r.status_code == 402:
                h = r.headers.get("X-Hashcash") or ""
                parts = h.split(":")
                cash = f"1:{parts[3]}:{hashcash(parts[3], int(parts[1]))}"
                last = Retry("hashcash")
                continue
            if r.status_code in RETRY_HTTP:
                last = Retry(f"http {r.status_code}")
                cash = None
                _backoff(attempt)
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"http {r.status_code}: {r.text[:200]}")
            data = r.json()
            if isinstance(data, list) and len(data) == 1:
                data = data[0]
            err = data if isinstance(data, int) else None
            if err in RETRY_MEGA:
                last = Retry(f"API {err}")
                cash = None
                _backoff(attempt)
                continue
            if isinstance(err, int) and err < 0:
                raise RuntimeError(f"API error {err}")
            return data
        raise RuntimeError(f"API request failed after 8 attempts: {last}")  # one owned retry budget


def http_get(url: str, headers: dict | None = None, timeout: int = 120) -> bytes:
    h = {"User-Agent": UA, "Origin": "https://transfer.it", "Referer": "https://transfer.it/"}
    if headers:
        h.update(headers)
    r = session().get(url, headers=h, timeout=timeout)
    if r.status_code in RETRY_HTTP:
        raise Retry(f"http {r.status_code}")
    if r.status_code not in (200, 206):
        raise RuntimeError(f"GET {r.status_code} {url[:80]}")
    return r.content


def fetch_range(url: str, start: int, end: int, kind: str) -> bytes:
    if kind == "mega":
        return http_get(f"{url}/{start}-{end}")
    return http_get(url, headers={"Range": f"bytes={start}-{end}"})


def g_url(api: MegaAPI, xh: str, h: str, plain: bool = False) -> tuple[str, int]:
    payload = {"a": "g", "n": h, "g": 1, "ssl": 1}
    if plain:
        payload["pt"] = 1
    res = api.call(payload, extra=api.xqs(xh))
    url = res.get("g") if isinstance(res, dict) else None
    if not isinstance(url, str) or not url.startswith("http"):
        raise RuntimeError(f"g failed: {res}")
    return url, int(res.get("s") or 0)


def download_blob(url: str, size: int, chunk: int, jobs: int, kind: str) -> bytes:
    rs = ranges(size, chunk)
    if not rs:
        return b""

    def one(se):
        a, b = se
        data = fetch_range(url, a, b, kind)  # retries belong to the queue, not to each range
        if len(data) != b - a + 1:
            raise Retry(f"range {a}-{b}: {len(data)} bytes back")
        return data

    if len(rs) == 1:
        return one(rs[0])[:size]
    blob = b"".join(queue_run(rs, one, jobs))
    return blob[:size]


def unlock(api: MegaAPI, xh: str, password: str) -> None:
    token = create_password(xh, password)
    try:
        res = api.call({"a": "xv", "xh": xh, "pw": token})
    except RuntimeError as e:
        raise RuntimeError(f"wrong password for {xh}") from e
    if res != 1:
        raise RuntimeError(f"wrong password for {xh} (xv={res})")
    api.pws[xh] = token


def resolve_rel(n: dict, by_h: dict[str, dict]) -> str:
    parts = [safe_name(n["name"])]
    seen = {n.get("h")}
    p = n.get("p")
    while p and p in by_h:
        if p in seen:
            raise RuntimeError("malformed transfer tree: parent cycle")
        seen.add(p)
        parent = by_h[p]
        if parent.get("p") and parent.get("name"):
            parts.append(safe_name(parent["name"]))
        p = parent.get("p")
    parts.reverse()
    return "/".join(parts)


def fold_key(name: str) -> str:
    """Paths that collide on this platform share a key (Windows folds case)."""
    return name.casefold() if os.name == "nt" else name


def node_dirs(n: dict, by_h: dict[str, dict]) -> list[tuple[str, str]]:
    """(sanitized directory path, folder handle) for every ancestor of a file node."""
    names: list[str] = []  # innermost first
    handles: list[str] = []
    seen = {n.get("h")}
    p = n.get("p")
    while p and p in by_h:
        if p in seen:
            raise RuntimeError("malformed transfer tree: parent cycle")
        seen.add(p)
        parent = by_h[p]
        if parent.get("p"):  # the transfer root itself contributes no path component
            names.append(safe_name(parent.get("name") or ""))
            handles.append(p)
        p = parent.get("p")
    return [("/".join(reversed(names[i:])), handle) for i, handle in enumerate(handles)]


def load_nodes(
    api: MegaAPI, xh: str, password: str | None = None
) -> tuple[dict, list[dict], dict[str, set[str]]]:
    """Return (transfer info, file nodes carrying `rel`, sanitized dir path -> folder handles)."""
    info = api.call({"a": "xi", "xh": xh})
    if isinstance(info, dict) and info.get("pw"):
        if not password:
            raise RuntimeError(f"{xh} is password-protected; pass --password")
        unlock(api, xh, password)
    tree = api.call({"a": "f", "c": 1, "r": 1, "xnc": 1}, extra=api.xqs(xh))
    nodes = tree["f"] if isinstance(tree, dict) else tree
    by_h = {}
    for n in nodes:
        k = bytes_to_a32(b64u_decode(n["k"]))
        name = decrypt_attr(n["a"], k).get("n") or n["h"]
        n = {**n, "k": k, "name": safe_name(name)}
        by_h[n["h"]] = n
    files = []
    dirs: dict[str, set[str]] = {}
    for n in by_h.values():
        if n.get("t"):
            continue
        n["rel"] = resolve_rel(n, by_h)
        for path, handle in node_dirs(n, by_h):
            dirs.setdefault(fold_key(path), set()).add(handle)
        files.append(n)
    return info, files, dirs


def temp_path(directory: Path, suffix: str) -> Path:
    """Unique staging name: collisions with real members are impossible, the fd is closed."""
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".dl-", suffix=suffix)
    os.close(fd)
    return Path(tmp)


def save(path: Path, data: bytes) -> None:
    """Write through a unique temporary name so a failed write leaves no partial final file."""
    tmp = temp_path(path.parent, ".part")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def unique_rels(files: list[dict], dirs: dict[str, set[str]] | None = None) -> None:
    """Refuse transfers whose sanitized paths would collide or nest ambiguously."""
    seen: dict[str, str] = {}
    for n in files:
        rel = safe_rel(n["rel"])
        key = fold_key(rel)
        if key in seen:
            raise RuntimeError(f"two nodes map to the same path: {seen[key]!r} and {n['rel']!r}")
        seen[key] = n["rel"]
    for key in seen:
        parts = key.split("/")
        for i in range(1, len(parts)):
            prefix = "/".join(parts[:i])
            if prefix in seen:
                raise RuntimeError(f"a file and a directory share the path {prefix!r}")
    for key, handles in (dirs or {}).items():
        if key in seen:
            raise RuntimeError(f"a file and a directory share the path {key!r}")
        if len(handles) > 1:
            raise RuntimeError(f"two folders map to the same path {key!r}")


def download_transfer(
    api: MegaAPI,
    xh: str,
    dest: Path,
    jobs: int,
    chunk: int,
    packed: bool,
    password: str | None = None,
    verify: bool = True,
) -> list[Path]:
    info, files, dirs = load_nodes(api, xh, password)
    dest.mkdir(parents=True, exist_ok=True)
    z = info.get("z") if isinstance(info, dict) else None
    written: list[Path] = []
    workers = max(1, min(jobs, len(files))) if files else 1
    per_file = split_jobs(jobs, workers)
    if packed:
        if z:
            name = f"{xh}{safe_name(str(z))}.zip"
            path = dest / name
            if not under(dest, path):
                raise RuntimeError(f"refusing to write outside {dest}: {name!r}")
            url, size = g_url(api, xh, z, plain=True)
            data = download_blob(url, size, chunk, jobs, kind="http")
            save(path, data)
            return [path]
        unique_rels(files, dirs)
        buf = dest / f"{xh}.zip"
        staged = temp_path(dest, ".zip")
        try:
            with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_STORED) as zf:
                def one(n):
                    url, size = g_url(api, xh, n["h"], plain=False)
                    enc = download_blob(url, size or n.get("s") or 0, chunk, per_file, kind="mega")
                    return n["rel"], decrypt_verified(enc, n["k"], verify)
                for rel, data in queue_run(files, one, workers):
                    zf.writestr(safe_rel(rel), data)
            os.replace(staged, buf)
        except BaseException:
            staged.unlink(missing_ok=True)
            raise
        return [buf]

    unique_rels(files, dirs)

    def one(n):
        url, size = g_url(api, xh, n["h"], plain=False)
        enc = download_blob(url, size or n.get("s") or 0, chunk, per_file, kind="mega")
        path = dest / safe_rel(n["rel"])
        if not under(dest, path):
            raise RuntimeError(f"refusing to write outside {dest}: {n['rel']!r}")
        save(path, decrypt_verified(enc, n["k"], verify))
        return path

    written = queue_run(files, one, workers)
    return written


def selfcheck() -> None:
    enc = bytes.fromhex("33d20a2fdd011ec6d9d07254610b79126531d459a821")
    k = [527450335, 1773456421, 2848265909, 1494836302, 956789286, 1404853608, 551298358, 4078008913]
    assert decrypt_file(enc, k) == b"hello transfer.it e2e\n"
    assert verify_mac(b"hello transfer.it e2e\n", k)
    assert not verify_mac(b"hello transfer.it e2e\r", k)
    flipped = bytes([enc[0] ^ 1]) + enc[1:]
    assert not verify_mac(decrypt_file(flipped, k), k)
    assert verify_mac(b"", [0] * 4) is False and verify_mac(b"", [0] * 7) is False
    try:
        decrypt_verified(flipped, k)
        raise AssertionError("corrupted ciphertext accepted")
    except RuntimeError:
        pass
    assert verify_mac(b"", k + [0, 0])  # per-chunk keys are skipped
    at = "Nw-u-ZTbw_9vRD2AIxhVuZVZaxzCOoaTu90_-KWvyCA"
    assert decrypt_attr(at, k)["n"] == "hello.txt"
    assert ranges(22, 8) == [(0, 7), (8, 15), (16, 21)]
    assert [split_jobs(4, n) for n in (1, 2, 4, 8)] == [4, 2, 1, 1]
    n = [0]

    def flaky():
        n[0] += 1
        if n[0] < 3:
            raise Retry("boom")
        return "ok"

    assert retry(flaky) == "ok" and n[0] == 3

    # the API layer owns one retry budget: exhaustion is not retryable again by callers
    calls = [0]

    class Boom:
        def post(self, *_a, **_kw):
            calls[0] += 1
            raise RequestException("down")

    real_session = session
    try:
        globals()["session"] = lambda: Boom()
        try:
            MegaAPI().call({"a": "xi", "xh": "a" * 12})
            raise AssertionError("api failure did not raise")
        except RuntimeError as exc:
            assert calls[0] == 8, calls[0]
            assert not retryable(exc), exc
        try:
            retry(lambda: MegaAPI().call({"a": "xi", "xh": "a" * 12}))
            raise AssertionError("outer retry swallowed the api failure")
        except RuntimeError:
            pass
        assert calls[0] == 16, calls[0]
    finally:
        globals()["session"] = real_session
    got = queue_run([1, 2, 3], lambda x: x * 10, jobs=2)
    assert got == [10, 20, 30]
    tok = create_password("EEDIThgnUbJZ", "testpass")
    assert len(b64u_decode(tok)) == 32
    assert create_password("EEDIThgnUbJZ", " testpass ") == tok
    mock_tree = {
        "r": {"h": "r", "p": "", "name": "root", "t": 1},
        "s1": {"h": "s1", "p": "r", "name": "sub1", "t": 1},
        "s2": {"h": "s2", "p": "s1", "name": "sub2", "t": 1},
        "f": {"h": "f", "p": "s2", "name": "file.txt", "t": 0},
    }
    assert resolve_rel(mock_tree["f"], mock_tree) == "sub1/sub2/file.txt"

    # hostile node names must stay inside the output directory
    assert safe_name("..") == "__" and safe_name(".") == "_" and safe_name("a/b") == "b"
    assert safe_name("nul\x00l") == "null" and safe_name("   ") == "file"
    assert safe_name("C:evil") == "Cevil" and safe_name("nul") == "_nul" and safe_name("COM1.txt") == "_COM1.txt"
    assert safe_name("12:30 mix.mp3") == "1230 mix.mp3" and safe_name("plain name.mp4") == "plain name.mp4"
    assert safe_name("file.") == "file" and safe_name("CONOUT$") == "_CONOUT$" and safe_name("COM\u00b9") == "_COM\u00b9"
    try:
        parse_xh("../../escape")
        raise AssertionError("path-like transfer id accepted")
    except ValueError:
        pass
    assert parse_xh("https://transfer.it/t/z5ImA2wjUToI") == "z5ImA2wjUToI"
    cycle = {
        "a": {"h": "a", "p": "b", "name": "a", "t": 1},
        "b": {"h": "b", "p": "a", "name": "b", "t": 1},
        "f": {"h": "f", "p": "a", "name": "f", "t": 0},
    }
    try:
        resolve_rel(cycle["f"], cycle)
        raise AssertionError("cyclic tree accepted")
    except RuntimeError:
        pass
    unique_rels([{"rel": "a.txt"}, {"rel": "b.txt"}, {"rel": "dir/c.txt"}])
    for bad_files, bad_dirs in (
        ([{"rel": "ab"}, {"rel": "a:b"}], None),
        ([{"rel": "dup.txt"}, {"rel": "dup.txt"}], None),
        ([{"rel": "a"}, {"rel": "a/b"}], None),
        ([{"rel": "ab/x"}], {"ab": {"h1", "h2"}}),
        ([{"rel": "ab"}], {"ab": {"h1"}}),
    ):
        try:
            unique_rels(bad_files, bad_dirs)
            raise AssertionError(f"accepted collision {bad_files} {bad_dirs}")
        except RuntimeError:
            pass
    unique_rels([{"rel": "a/b.txt"}, {"rel": "a/c.txt"}], {"a": {"h1"}})
    try:
        node_dirs(cycle["f"], cycle)
        raise AssertionError("cycle accepted by node_dirs")
    except RuntimeError:
        pass
    deep = {
        "r": {"h": "r", "p": "", "name": "root", "t": 1},
        "a": {"h": "a", "p": "r", "name": "a", "t": 1},
        "b": {"h": "b", "p": "a", "name": "b", "t": 1},
        "f": {"h": "f", "p": "b", "name": "file", "t": 0},
    }
    assert node_dirs(deep["f"], deep) == [("a/b", "b"), ("a", "a")], node_dirs(deep["f"], deep)
    assert resolve_rel(deep["f"], deep) == "a/b/file"
    # sibling branches that share a subfolder name must stay distinct
    unique_rels([{"rel": "A/X/f"}, {"rel": "B/X/g"}], {"A": {"hA"}, "A/X": {"hAX"}, "B": {"hB"}, "B/X": {"hBX"}})
    for files_, dirs_ in (
        ([{"rel": "ab/x/a"}], {"ab": {"h1"}, "ab/x": {"h2"}}),
        ([{"rel": "ab/y/b"}], {"ab": {"h3"}, "ab/y": {"h4"}}),
    ):
        unique_rels(files_, dirs_)
    for merged in ({"ab": {"h1", "h3"}}, {"ab": {"h1", "h3"}, "ab/x": {"h2"}}):
        try:
            unique_rels([{"rel": "ab/x/a"}], merged)
            raise AssertionError(f"merged folders accepted: {merged}")
        except RuntimeError:
            pass
    try:
        parse_xh("\u00e9" * 12)
        raise AssertionError("non-ASCII transfer id accepted")
    except ValueError:
        pass
    tmp = Path(tempfile.mkdtemp())
    try:
        payload = b"payload"
        target = tmp / "sub" / "file.bin"
        save(target, payload)
        assert target.read_bytes() == payload and not list(tmp.rglob(".dl-*"))
        staging = temp_path(tmp, ".zip")
        assert staging.parent == tmp and staging.name.startswith(".dl-")
        staging.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    assert safe_rel("../../etc/passwd") == "etc/passwd"
    assert safe_rel("a/../b") == "a/b"
    hostile = {
        "r": {"h": "r", "p": "", "name": "root", "t": 1},
        "up": {"h": "up", "p": "r", "name": "..", "t": 1},
        "x": {"h": "x", "p": "up", "name": "..\\payload", "t": 0},
    }
    rel = resolve_rel(hostile["x"], hostile)
    assert rel == "__/payload", rel
    dest = Path(tempfile.mkdtemp())
    try:
        assert under(dest, dest / safe_rel(rel)) and not under(dest, dest / "../escaped")
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    install_fast_interrupt()
    assert signal.getsignal(signal.SIGINT).__name__ == "_die"
    print("selfcheck ok")


def relax_stream_errors() -> None:
    """Non-ASCII names must not crash printing on a narrow console encoding."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    relax_stream_errors()
    ap = argparse.ArgumentParser(description="Download transfer.it links (concurrent, chunked, optional zip).")
    ap.add_argument("links", nargs="*", help="https://transfer.it/t/XXXXXXXXXXXX")
    ap.add_argument("-o", "--out", type=Path, default=Path("downloads"))
    ap.add_argument("-j", "--jobs", type=int, default=4)
    ap.add_argument("--chunk-size", type=int, default=1 << 20)
    ap.add_argument("--zip", action="store_true", help="packed download (server zip if available)")
    ap.add_argument("--password", default=None, help="plaintext password for xv-protected links")
    ap.add_argument("--no-verify", action="store_true", help="skip the chunk MAC check on decrypted files")
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args(argv)
    if args.selfcheck:
        selfcheck()
        return 0
    install_fast_interrupt()
    if not args.links or args.jobs < 1 or args.chunk_size < 1:
        ap.error("need links; --jobs/--chunk-size >= 1")
    xhs = list(dict.fromkeys(parse_xh(s) for s in args.links))
    api = MegaAPI()
    args.out.mkdir(parents=True, exist_ok=True)
    link_workers = max(1, min(args.jobs, len(xhs)))
    per_link = split_jobs(args.jobs, link_workers)

    def one(xh: str):
        dest = args.out / xh
        paths = download_transfer(
            api, xh, dest, per_link, args.chunk_size, args.zip, args.password, not args.no_verify
        )
        return xh, paths

    results = queue_run(xhs, one, link_workers)
    for xh, paths in results:
        for p in paths:
            print(f"{xh}: {p}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        raise
