import { vis } from "@/lib/report-format";
import { cn } from "@/lib/utils";

/**
 * Snapshot text: one React text node (never HTML, Markdown or a link), bidi-isolated, with
 * invisible characters made visible by the renderer's `vis` rule (RT24). Line breaks are kept;
 * long values wrap.
 */
export function RText({
  value,
  mono = false,
  block = false,
  className,
}: {
  value: string | number | null | undefined;
  mono?: boolean;
  block?: boolean;
  className?: string;
}) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">—</span>;
  }
  const text = typeof value === "number" ? String(value) : vis(value);
  return (
    <span
      dir="auto"
      className={cn(
        "break-words whitespace-pre-wrap [unicode-bidi:isolate]",
        block && "block",
        mono && "font-mono text-xs break-all",
        className,
      )}
    >
      {text}
    </span>
  );
}
