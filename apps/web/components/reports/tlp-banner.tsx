import { TLP_BACKGROUND, TLP_COLOURS, TLP_DEFINITIONS, TLP_LABELS, type Tlp } from "@/lib/tlp";
import { cn } from "@/lib/utils";

/**
 * The TLP marking of a report: the label in the FIRST colour on black and the FIRST one-line
 * definition (RT23), as text. `sticky` keeps the top banner visible while scrolling.
 */
export function TlpBanner({
  tlp,
  position,
  sticky = false,
}: {
  tlp: Tlp;
  position: "top" | "bottom";
  sticky?: boolean;
}) {
  return (
    <div
      role="note"
      aria-label={`Marking ${position === "top" ? "(top)" : "(bottom)"}: ${TLP_LABELS[tlp]}`}
      data-tlp={tlp}
      className={cn(
        "flex flex-wrap items-baseline gap-x-3 gap-y-1 rounded-md px-3 py-2 print:static",
        sticky && "sticky top-0 z-20 shadow-sm",
      )}
      style={{ backgroundColor: TLP_BACKGROUND }}
    >
      <span className="font-mono text-base font-bold tracking-wide" style={{ color: TLP_COLOURS[tlp] }}>
        {TLP_LABELS[tlp]}
      </span>
      <span className="text-xs text-white">{TLP_DEFINITIONS[tlp]}</span>
    </div>
  );
}
