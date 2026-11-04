"""Deterministic threat-intel provider sink for dev/test/e2e (the `mock` provider).

Stdlib only (python:3.12-alpine). It sits on the `egress` network alone, so the enrich worker
is its only client. Every request but `/health` must carry `X-Mock-Key` equal to
`TI_MOCK_EXPECTED_KEY` (401 otherwise). Like some real providers, every 401 body echoes the
key it received: the key-leak suite (phase 7) proves the worker never logs or stores it.

Routes:
- `GET /health`
- `GET /v1/verify`: 200 when the key matches
- `GET /v1/lookup/<type>/<percent-encoded value>`

The behaviour is chosen by the first label of the value's host (the value itself for a
domain, the URL host, the email domain), so `hit.example.com`, `http://hit.example.com/x`
and `a@hit.example.com` behave alike:

| first label       | answer                                                            |
|-------------------|-------------------------------------------------------------------|
| `hit*`            | 200, found                                                        |
| `echo401*`        | 401 echoing the (valid) key it received                           |
| `notfound*`       | 404                                                               |
| `ratelimit-ra*`   | 429 with `Retry-After: 5` on the first request for that value, then a hit |
| `ratelimit-long*` | always 429 with `Retry-After: 3600`                               |
| `ratelimit*`      | always 429 without `Retry-After`                                  |
| `err500*`         | 500                                                               |
| `slow*`           | a hit after 12 s (beyond the client's 10 s read timeout)          |
| `big*`            | a 2 MiB body                                                      |
| `redirect*`       | 302 to another host                                               |
| `badjson*`        | a truncated body                                                  |
| `deep*`           | valid JSON nested 3000 levels                                     |

Hashes starting with `deadbeef` are hits. Every other value is a deterministic 404, so a job
run against `mock` alone ends `completed` unless a fault value is present.
"""

import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

EXPECTED_KEY = os.environ.get("TI_MOCK_EXPECTED_KEY", "")
TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"}
HIT = {"found": True, "behaviour": "hit", "label": "test-hit", "hits": 3, "tags": ["mock"]}

_seen_lock = threading.Lock()
_seen: set[str] = set()


def _first_seen(value: str) -> bool:
    with _seen_lock:
        if value in _seen:
            return False
        if len(_seen) > 100_000:
            _seen.clear()
        _seen.add(value)
        return True


def _label(ioc_type: str, value: str) -> str:
    if ioc_type == "url":
        host = urlsplit(value).hostname or ""
    elif ioc_type == "email":
        host = value.rpartition("@")[2]
    else:
        host = value
    return host.split(".")[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "ti-mock"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Request lines only (never headers: they carry the mock key).
        print(f"ti-mock {self.command} {self.path.split('?')[0][:120]}", flush=True)

    def _raw(self, status: int, data: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _send(self, status: int, body: object, headers: dict[str, str] | None = None) -> None:
        self._raw(status, json.dumps(body).encode(), headers)

    def _authorized(self) -> bool:
        key = self.headers.get("X-Mock-Key", "")
        return bool(EXPECTED_KEY) and hmac.compare_digest(key.encode(), EXPECTED_KEY.encode())

    def _unauthorized(self) -> None:
        received = self.headers.get("X-Mock-Key", "")
        self._send(401, {"error": "unauthorized", "received_key": received})

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/health":
            self._send(200, {"status": "ok"})
            return
        if not self._authorized():
            self._unauthorized()
            return
        if path == "/v1/verify":
            self._send(200, {"status": "valid"})
            return
        parts = path.split("/")
        if len(parts) != 5 or parts[1:3] != ["v1", "lookup"] or parts[3] not in TYPES:
            self._send(404, {"error": "unknown route"})
            return
        self._lookup(parts[3], unquote(parts[4]))

    def _lookup(self, ioc_type: str, value: str) -> None:  # noqa: C901
        if ioc_type in ("md5", "sha1", "sha256"):
            if value.startswith("deadbeef"):
                self._send(200, HIT)
            else:
                self._send(404, {"found": False})
            return
        label = _label(ioc_type, value)
        if label.startswith("echo401"):
            self._unauthorized()
        elif label.startswith("hit"):
            self._send(200, HIT)
        elif label.startswith("notfound"):
            self._send(404, {"found": False})
        elif label.startswith("ratelimit-ra"):
            if _first_seen(value):
                self._send(429, {"error": "slow down"}, {"Retry-After": "5"})
            else:
                self._send(200, {**HIT, "behaviour": "after-retry"})
        elif label.startswith("ratelimit-long"):
            self._send(429, {"error": "slow down"}, {"Retry-After": "3600"})
        elif label.startswith("ratelimit"):
            self._send(429, {"error": "slow down"})
        elif label.startswith("err500"):
            self._send(500, {"error": "internal"})
        elif label.startswith("slow"):
            time.sleep(12)
            self._send(200, HIT)
        elif label.startswith("big"):
            self._raw(200, b'{"pad":"' + b"x" * (2 * 1024 * 1024) + b'"}')
        elif label.startswith("redirect"):
            self._send(302, {}, {"Location": "http://elsewhere.invalid/"})
        elif label.startswith("badjson"):
            self._raw(200, b'{"found": true, "label": "trunc')
        elif label.startswith("deep"):
            self._raw(200, b"[" * 3000 + b"]" * 3000)
        else:
            self._send(404, {"found": False})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104
