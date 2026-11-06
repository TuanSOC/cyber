import { hasHiddenCharacters, inertText } from "@/lib/disk";
import { cn } from "@/lib/utils";

/**
 * Attacker-chosen text from a disk image (a path, a name, an EWF value, a message): a React
 * text node only, with bidi / invisible characters made visible (`⟨U+202E⟩`), cut with an
 * ellipsis and the full (marked) value in the tooltip. Never markup, a link or a file name.
 */
export function InertText({
  value,
  className,
  mono,
  wrap,
  max,
}: {
  value: string | null | undefined;
  className?: string;
  mono?: boolean;
  /** Wrap instead of truncating (detail views). */
  wrap?: boolean;
  max?: number;
}) {
  if (value === null || value === undefined || value === "") return <span className="text-muted-foreground">—</span>;
  const shown = inertText(value, max);
  const hidden = hasHiddenCharacters(value);
  return (
    <span
      className={cn(
        wrap ? "break-all whitespace-pre-wrap" : "block max-w-full truncate",
        mono && "font-mono text-xs",
        hidden && "decoration-amber-500 underline decoration-dotted",
        className,
      )}
      title={hidden ? `${inertText(value)}\n(contains hidden or direction-changing characters, shown as ⟨U+…⟩)` : inertText(value)}
    >
      {shown}
    </span>
  );
}
