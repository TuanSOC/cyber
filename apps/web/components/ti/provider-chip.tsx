import { ExternalLink } from "lucide-react";

import {
  type IocEnrichment,
  type ProviderSummary,
  chipText,
  chipTitle,
  httpsPermalink,
  tlpBadges,
} from "@/lib/ti";
import { cn } from "@/lib/utils";

type ChipSource = Pick<
  IocEnrichment,
  "provider" | "status" | "found" | "score" | "score_scale" | "detections" | "stale" | "fetched_at"
>;

/**
 * One provider's answer as a compact chip ("VT 12/71 engines"), titled "Reported by …".
 * A single neutral style for every chip: no colour by count, score or status (RT20).
 */
export function ProviderChip({
  e,
  summary,
  className,
}: {
  e: ChipSource;
  summary?: ProviderSummary | null;
  className?: string;
}) {
  const title = chipTitle(e);
  return (
    <span
      className={cn(
        "inline-flex max-w-56 items-center truncate rounded border border-border bg-muted/40 px-1.5 text-[11px] whitespace-nowrap text-foreground",
        e.stale && "border-dashed",
        className,
      )}
      title={title}
      aria-label={title}
      data-provider={e.provider}
    >
      {chipText(e, summary)}
    </span>
  );
}

/** Text-only chips for provider strings (tags, families, pulse names), truncated with a tooltip. */
export function TextList({ values, max = 12, mono = false }: { values: readonly string[]; max?: number; mono?: boolean }) {
  if (values.length === 0) return <span className="text-muted-foreground">—</span>;
  const shown = values.slice(0, max);
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((value, index) => (
        <span
          key={`${value}-${index}`}
          className={cn("max-w-64 truncate rounded border px-1.5 text-[11px]", mono && "font-mono")}
          title={value}
        >
          {value}
        </span>
      ))}
      {values.length > max && (
        <span className="text-[11px] text-muted-foreground" title={values.slice(max).join(", ")}>
          +{values.length - max}
        </span>
      )}
    </span>
  );
}

/** MISP TLP labels as text badges; TLP:RED and TLP:AMBER are outlined to stand out. */
export function TlpBadges({ summary }: { summary: ProviderSummary | null | undefined }) {
  const badges = tlpBadges(summary);
  if (badges.length === 0) return null;
  return (
    <span className="flex flex-wrap gap-1">
      {badges.map((b) => (
        <span
          key={b.label}
          className={cn(
            "rounded border px-1.5 font-mono text-[11px] font-medium",
            b.highlight ? "border-foreground" : "border-border text-muted-foreground",
          )}
          title={`Sharing label set by the MISP event: ${b.label}`}
        >
          {b.label}
        </span>
      ))}
    </span>
  );
}

/** The provider's own page for the indicator: only a server-built `https:` URL is linked. */
export function Permalink({ url, label }: { url: string | null | undefined; label: string }) {
  const href = httpsPermalink(url);
  if (!href) return null;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      referrerPolicy="no-referrer"
      className="inline-flex items-center gap-1 text-xs text-primary underline-offset-4 hover:underline"
      title={href}
    >
      {label} <ExternalLink className="size-3" aria-hidden />
    </a>
  );
}
