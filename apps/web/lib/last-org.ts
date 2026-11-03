// Per-browser convenience only: which org to open on "/". Never trusted for access decisions.
const KEY = "cyberlab.lastOrg";

export function readLastOrg(): string | null {
  try {
    return window.localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function rememberOrg(orgId: string): void {
  try {
    window.localStorage.setItem(KEY, orgId);
  } catch {
    // storage unavailable (private mode / blocked): harmless
  }
}
