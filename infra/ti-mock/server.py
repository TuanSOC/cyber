"""Deterministic threat-intel provider sink for dev/test/e2e (the `mock` provider).

Stdlib only (python:3.12-alpine). It sits on the `egress` network alone, so the enrich worker
is its only client. Requests must carry `X-Mock-Key` equal to `TI_MOCK_EXPECTED_KEY`.

M4 phase 1 skeleton: `GET /health`, and `GET /v1/lookup/<type>/<value>` answering a hit for
values starting with `hit.` and not-found for everything else. Phase 2 adds the fault
behaviours (429 with and without Retry-After, 500, slow, oversize, redirect, malformed).
"""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

EXPECTED_KEY = os.environ.get("TI_MOCK_EXPECTED_KEY", "")


class Handler(BaseHTTPRequestHandler):
    server_version = "ti-mock"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Request lines only (never headers: they carry the mock key).
        print(f"ti-mock {self.command} {self.path.split('?')[0][:120]}", flush=True)

    def _send(self, status: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"status": "ok"})
            return
        key = self.headers.get("X-Mock-Key", "")
        if not EXPECTED_KEY or not hmac.compare_digest(key.encode(), EXPECTED_KEY.encode()):
            self._send(401, {"error": "unauthorized"})
            return
        parts = self.path.split("?")[0].split("/")
        if len(parts) != 5 or parts[1:3] != ["v1", "lookup"]:
            self._send(404, {"error": "unknown route"})
            return
        value = unquote(parts[4])
        if value.startswith("hit."):
            self._send(200, {"found": True, "label": "test-hit", "hits": 3, "tags": ["mock"]})
        else:
            self._send(404, {"found": False})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104
