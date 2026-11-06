"""Hostile OIDC IdP mock (M11 phase 8; phase 1 stub).

Test and e2e profiles only, on the `egress` network (reached through `egress-proxy-test`, or
directly by ENV=test lanes). Phase 8 implements discovery, JWKS (signing keys generated at
start, never committed), authorize / token endpoints and the hostile modes (alg `none` / HS256,
wrong `iss` / `aud` / `azp` / nonce, expired, mix-up `iss`, unverified email, foreign domain,
unknown `kid`, `missing_hd`, `stale_auth_time`). Until then every request answers 503.
Stdlib only.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8443


class Handler(BaseHTTPRequestHandler):
    def _answer(self) -> None:
        body = json.dumps({"error": "idp_mock_not_implemented"}).encode()
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _answer  # noqa: N815
    do_POST = _answer  # noqa: N815

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104
