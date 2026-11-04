/**
 * Content-Security-Policy for HTML responses, set per request by `proxy.ts`.
 *
 * Scripts: only those carrying the request's nonce run ('strict-dynamic' lets them load their
 * own chunks; it also makes browsers ignore 'self' for scripts). Next.js reads the nonce back
 * from the request's CSP header and stamps it on its own framework and bootstrap scripts.
 * Styles keep 'unsafe-inline' without a nonce: Radix/sonner set inline `style` attributes, and
 * a nonce in style-src would make browsers ignore 'unsafe-inline' (red-team RT1).
 */

/** Base64 of 16 random bytes (128 bits) from the platform CSPRNG. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export function buildCsp(nonce: string, { dev }: { dev: boolean }): string {
  const directives: Record<string, string[]> = {
    "default-src": ["'self'"],
    // Dev only: React rebuilds server error stacks with eval.
    "script-src": ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(dev ? ["'unsafe-eval'"] : [])],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'", "data:"],
    // Dev only: the HMR websocket (ws: is not covered by 'self' in every browser).
    "connect-src": ["'self'", ...(dev ? ["ws:"] : [])],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
  };
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
}
