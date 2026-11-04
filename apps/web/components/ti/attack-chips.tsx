"use client";

import { type AttackLabel, type AttackMeta, attackChip, attackIds } from "@/lib/ti";
import { useAttackLabels } from "@/lib/use-ti";
import { cn } from "@/lib/utils";

export type AttackLookup = {
  labels: Map<string, AttackLabel>;
  meta: AttackMeta | undefined;
  loaded: boolean;
};

/** Labels for a batch of ids (one request per page of rows), as a lookup map. */
export function useAttackLookup(ids: readonly string[]): AttackLookup {
  const query = useAttackLabels(ids);
  const labels = new Map<string, AttackLabel>();
  for (const label of query.data?.techniques ?? []) labels.set(label.id, label);
  return { labels, meta: query.data?.meta, loaded: query.isSuccess };
}

/**
 * ATT&CK technique chips: "T1055 · Process Injection", tactics in the tooltip, linked to the
 * ATT&CK page (https only). `link={false}` renders text only (printable report).
 */
export function AttackChips({
  ids,
  lookup,
  link = true,
  max = 8,
}: {
  ids: readonly string[];
  lookup: AttackLookup;
  link?: boolean;
  max?: number;
}) {
  const valid = attackIds(ids);
  if (valid.length === 0) return <span className="text-muted-foreground">—</span>;
  const shown = valid.slice(0, max);
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((id) => {
        const chip = attackChip(id, lookup.labels.get(id), lookup.loaded ? lookup.meta : undefined);
        const className = "max-w-72 truncate rounded border px-1.5 text-[11px]";
        return link && chip.href ? (
          <a
            key={id}
            href={chip.href}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
            className={cn(className, "hover:bg-muted")}
            title={chip.title}
          >
            {chip.text}
          </a>
        ) : (
          <span key={id} className={cn(className, !lookup.labels.has(id) && "font-mono")} title={chip.title}>
            {chip.text}
          </span>
        );
      })}
      {valid.length > max && (
        <span className="text-[11px] text-muted-foreground" title={valid.slice(max).join(", ")}>
          +{valid.length - max}
        </span>
      )}
    </span>
  );
}

/** The MITRE notice and index version, shown wherever ATT&CK labels appear. */
export function MitreNotice({ meta, className }: { meta: AttackMeta | undefined; className?: string }) {
  if (!meta) return null;
  return (
    <p className={cn("text-[11px] text-muted-foreground", className)}>
      MITRE ATT&amp;CK® Enterprise v{meta.version} (offline index). {meta.notice}
    </p>
  );
}

/** Notice footer for pages that need it without labelling ids themselves. */
export function MitreNoticeFooter({ className }: { className?: string }) {
  const lookup = useAttackLookup([]);
  return <MitreNotice meta={lookup.meta} className={className} />;
}
