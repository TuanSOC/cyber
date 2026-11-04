import { NextResponse, type NextRequest } from "next/server";

import { buildCsp, generateNonce } from "@/lib/csp";

/**
 * Per-request nonce CSP for app pages. The policy goes on the request too: Next.js extracts
 * the `'nonce-…'` from the request's Content-Security-Policy header while rendering and puts
 * it on every script it emits. The gateway (Caddy) only sets a fallback CSP when this header
 * is absent, so this is the policy browsers enforce for HTML.
 */
export function proxy(request: NextRequest) {
  const nonce = generateNonce();
  const csp = buildCsp(nonce, { dev: process.env.NODE_ENV === "development" });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      // Everything except the API (proxied to FastAPI by the gateway anyway), build assets,
      // image optimisation and static files with an extension (favicon, images, fonts).
      source: "/((?!api/|_next/static|_next/image|.*\\.(?:ico|png|jpg|jpeg|gif|svg|webp|avif|woff2?|txt)$).*)",
      // Prefetches return RSC payloads, never HTML that a browser enforces a CSP on.
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
