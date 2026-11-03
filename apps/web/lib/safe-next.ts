// Control characters, whitespace and backslashes are rejected outright: browsers strip or
// normalize them while resolving URLs ("/\t/evil.example" becomes "//evil.example").
const UNSAFE = /[\u0000- \u007f\\]/;

/** Only same-origin paths are allowed as post-login redirects (no open redirect). */
export function safeNext(
  value: string | null | undefined,
  fallback = "/",
  origin: string = typeof window === "undefined" ? "http://localhost" : window.location.origin,
): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || UNSAFE.test(value)) {
    return fallback;
  }
  let url: URL;
  try {
    url = new URL(value, origin);
  } catch {
    return fallback;
  }
  if (url.origin !== origin) return fallback;
  return `${url.pathname}${url.search}${url.hash}`;
}
