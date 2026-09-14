#!/usr/bin/env python3
"""Headless transfer.it downloader. curl_cffi + openssl."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
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


def parse_xh(s: str) -> str:
    s = s.strip()
    if "/t/" in s:
        s = s.rsplit("/t/", 1)[-1]
    s = s.split("?", 1)[0].strip("/")
    if len(s) != 12:
        raise ValueError(f"bad transfer.it link: {s}")
    return s


def safe_name(name: str) -> str:
    name = name.replace("\\", "/").split("/")[-1].replace("\x00", "").strip()
    return name or "file"


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
        raise last or RuntimeError("API retries exhausted")


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
    if len(rs) == 1:
        data = retry(lambda: fetch_range(url, rs[0][0], rs[0][1], kind))
        return data[:size] if kind == "http" else data

    def one(se):
        a, b = se
        return retry(lambda: fetch_range(url, a, b, kind))

    parts = queue_run(rs, one, jobs)
    blob = b"".join(parts)
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
    parts = [n["name"]]
    p = n.get("p")
    while p and p in by_h:
        parent = by_h[p]
        if parent.get("p") and parent.get("name"):
            parts.append(parent["name"])
        p = parent.get("p")
    parts.reverse()
    return "/".join(parts)


def load_nodes(api: MegaAPI, xh: str, password: str | None = None) -> tuple[dict, list[dict]]:
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
    for n in by_h.values():
        if n.get("t"):
            continue
        n["rel"] = resolve_rel(n, by_h)
        files.append(n)
    return info, files


def save(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def download_transfer(
    api: MegaAPI, xh: str, dest: Path, jobs: int, chunk: int, packed: bool, password: str | None = None
) -> list[Path]:
    info, files = load_nodes(api, xh, password)
    dest.mkdir(parents=True, exist_ok=True)
    z = info.get("z") if isinstance(info, dict) else None
    written: list[Path] = []
    if packed:
        if z:
            url, size = g_url(api, xh, z, plain=True)
            data = download_blob(url, size, chunk, jobs, kind="http")
            path = dest / f"{xh}{z}.zip"
            save(path, data)
            return [path]
        buf = dest / f"{xh}.zip"
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            def one(n):
                url, size = g_url(api, xh, n["h"], plain=False)
                enc = download_blob(url, size or n.get("s") or 0, chunk, jobs, kind="mega")
                return n["rel"], decrypt_file(enc, n["k"])
            for rel, data in queue_run(files, one, jobs):
                zf.writestr(rel, data)
        return [buf]

    def one(n):
        url, size = g_url(api, xh, n["h"], plain=False)
        enc = download_blob(url, size or n.get("s") or 0, chunk, jobs, kind="mega")
        path = dest / n["rel"]
        save(path, decrypt_file(enc, n["k"]))
        return path

    written = queue_run(files, one, jobs)
    return written


def selfcheck() -> None:
    enc = bytes.fromhex("33d20a2fdd011ec6d9d07254610b79126531d459a821")
    k = [527450335, 1773456421, 2848265909, 1494836302, 956789286, 1404853608, 551298358, 4078008913]
    assert decrypt_file(enc, k) == b"hello transfer.it e2e\n"
    at = "Nw-u-ZTbw_9vRD2AIxhVuZVZaxzCOoaTu90_-KWvyCA"
    assert decrypt_attr(at, k)["n"] == "hello.txt"
    assert ranges(22, 8) == [(0, 7), (8, 15), (16, 21)]
    n = [0]

    def flaky():
        n[0] += 1
        if n[0] < 3:
            raise Retry("boom")
        return "ok"

    assert retry(flaky) == "ok" and n[0] == 3
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
    print("selfcheck ok")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Download transfer.it links (concurrent, chunked, optional zip).")
    ap.add_argument("links", nargs="*", help="https://transfer.it/t/XXXXXXXXXXXX")
    ap.add_argument("-o", "--out", type=Path, default=Path("downloads"))
    ap.add_argument("-j", "--jobs", type=int, default=4)
    ap.add_argument("--chunk-size", type=int, default=1 << 20)
    ap.add_argument("--zip", action="store_true", help="packed download (server zip if available)")
    ap.add_argument("--password", default=None, help="plaintext password for xv-protected links")
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args(argv)
    if args.selfcheck:
        selfcheck()
        return 0
    if not args.links or args.jobs < 1 or args.chunk_size < 1:
        ap.error("need links; --jobs/--chunk-size >= 1")
    xhs = [parse_xh(s) for s in args.links]
    api = MegaAPI()
    args.out.mkdir(parents=True, exist_ok=True)

    def one(xh: str):
        dest = args.out / xh
        paths = download_transfer(api, xh, dest, args.jobs, args.chunk_size, args.zip, args.password)
        return xh, paths

    results = queue_run(xhs, one, args.jobs)
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
