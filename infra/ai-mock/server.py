"""Deterministic LLM sink for the AI `mock` provider (dev/test/e2e only).

Stdlib only (python:3.12-alpine), on the `egress` network alone, so the analyst worker is its
only client. Phase 1 skeleton: `GET /health` answers 200 and every other route 501. Phase 2
owns this file and implements the wire protocol documented in
`apps/api/app/modules/ai/contracts.py` (`POST /v1/analyze`, `POST /v1/count_tokens`,
`GET /v1/verify`, the `ai-mock:*` behaviour markers and the test-only `GET /_last`), checking
`X-Mock-Key` against `AI_MOCK_EXPECTED_KEY`.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "ai-mock/0"

    def _send(self, status: int, body: dict[str, object]) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(501, {"error": "not_implemented"})

    def do_POST(self) -> None:  # noqa: N802
        self._send(501, {"error": "not_implemented"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return  # request lines may carry nothing secret, but keep the sink quiet


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104
