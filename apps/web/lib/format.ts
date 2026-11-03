const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

export function formatBytes(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(value >= 100 ? 0 : 1)} ${UNITS[unit]}`;
}

const LOCAL = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

/** Local time for display; the exact UTC instant goes in the title tooltip. */
export function formatDate(iso: string): { local: string; utc: string } {
  const date = new Date(iso);
  return { local: LOCAL.format(date), utc: date.toISOString() };
}

export function shortHash(hash: string, size = 12): string {
  return hash.length > size ? `${hash.slice(0, size)}…` : hash;
}

export const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  in_progress: "In progress",
  closed: "Closed",
  archived: "Archived",
};
