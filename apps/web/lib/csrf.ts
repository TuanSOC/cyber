export const CSRF_COOKIE = "cl_csrf";

export function readCsrfToken(): string {
  if (typeof document === "undefined") return "";
  for (const part of document.cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === CSRF_COOKIE) return decodeURIComponent(rest.join("="));
  }
  return "";
}
