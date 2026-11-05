import { TLP_BACKGROUND, TLP_COLOURS, TLP_DEFINITIONS, TLP_LABELS, type Tlp } from "@/lib/tlp";
import { cn } from "@/lib/utils";

/**
 * The TLP 2.0 marking (FIRST colours on black). The label text is always present, so the
 * marking never depends on colour alone; `withDefinition` adds the FIRST one-line definition.
 */
export function TlpBadge({
  tlp,
  withDefinition = false,
  className,
}: {
  tlp: Tlp;
  withDefinition?: boolean;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex flex-col gap-1", className)}>
      <span
        role="img"
        aria-label={`Traffic Light Protocol ${TLP_LABELS[tlp]}`}
        title={TLP_DEFINITIONS[tlp]}
        className="inline-flex w-fit items-center rounded-sm px-2 py-0.5 font-mono text-xs font-bold tracking-wide"
        style={{ backgroundColor: TLP_BACKGROUND, color: TLP_COLOURS[tlp] }}
      >
        {TLP_LABELS[tlp]}
      </span>
      {withDefinition ? <span className="text-muted-foreground text-xs">{TLP_DEFINITIONS[tlp]}</span> : null}
    </span>
  );
}
