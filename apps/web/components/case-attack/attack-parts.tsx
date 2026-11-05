import Link from "next/link";

import { AddToReportButton } from "@/components/reports/add-to-report";
import type { JobRoute } from "@/lib/ai";
import { visText } from "@/lib/case";
import {
  type AttackMapping,
  MAPPING_STATUS_LABELS,
  type MappingStatus,
  type MatrixTactic,
  SOURCE_KIND_LABELS,
  type SourceDescriptor,
  mitreHref,
  sourceHref,
  tacticLabel,
  techniqueText,
  techniqueWarning,
} from "@/lib/case-attack";
import { citedRowRef } from "@/lib/reports";
import { cn } from "@/lib/utils";

/*
 * Presentational ATT&CK parts. Statuses use one neutral style with the label text (no
 * verdict colours); rationale is plain text.
 */

const STATUS_STYLE: Record<MappingStatus, string> = {
  confirmed: "border-foreground font-semibold",
  suspected: "border-dashed",
  rejected: "line-through text-muted-foreground",
};

export function StatusChip({ status }: { status: MappingStatus }) {
  return (
    <span className={cn("inline-flex rounded border px-1.5 text-[11px]", STATUS_STYLE[status])} data-status={status}>
      {MAPPING_STATUS_LABELS[status]}
    </span>
  );
}

/** Technique id and name; the MITRE page is linked only when it is an https attack.mitre.org URL. */
export function TechniqueLabelText({ label }: { label: AttackMapping["label"] }) {
  const href = mitreHref(label.url);
  const warning = techniqueWarning(label);
  const text = techniqueText(label);
  return (
    <span className="inline-flex flex-wrap items-baseline gap-1">
      {href ? (
        <a href={href} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" className="hover:underline">
          {text}
        </a>
      ) : (
        <span>{text}</span>
      )}
      {warning ? <span className="text-[11px] text-muted-foreground">({warning})</span> : null}
    </span>
  );
}

/** Tactic-grouped matrix: a responsive grid of tactic columns (never a 14-column table). */
export function AttackMatrix({ matrix }: { matrix: readonly MatrixTactic[] }) {
  const tactics = matrix.filter((t) => t.techniques.length > 0);
  if (tactics.length === 0) {
    return <p className="text-sm text-muted-foreground">No confirmed or suspected techniques yet.</p>;
  }
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4" role="list" aria-label="ATT&CK matrix">
      {tactics.map((t) => (
        <section key={t.tactic} role="listitem" className="flex flex-col gap-2 rounded-md border p-3" aria-label={tacticLabel(t.tactic)}>
          <h4 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{tacticLabel(t.tactic)}</h4>
          <ul className="flex flex-col gap-1.5">
            {t.techniques.map((m) => (
              <li key={m.id} className="flex flex-wrap items-center gap-1.5 text-xs">
                <StatusChip status={m.status} />
                <TechniqueLabelText label={m.label} />
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

/**
 * Sources of a mapping or suggestion, each with its kind and an internal link when known. With
 * `citeIn` (the case id), citable sources (findings, capabilities) get "Add to report".
 */
export function SourceList({
  orgId,
  sources,
  routes,
  citeIn,
}: {
  orgId: string;
  sources: readonly SourceDescriptor[];
  routes: ReadonlyMap<string, JobRoute>;
  citeIn?: string;
}) {
  if (sources.length === 0) return <span className="text-xs text-muted-foreground">No linked source</span>;
  return (
    <ul className="flex flex-wrap gap-1">
      {sources.map((s, index) => {
        const href = sourceHref(orgId, s, routes);
        const text = `${SOURCE_KIND_LABELS[s.kind]} · ${s.ref_id.slice(0, 8)}`;
        const cited = citeIn ? citedRowRef(s.kind, s.ref_id, s.job_id) : null;
        return (
          <li key={`${s.kind}-${s.ref_id}-${index}`} className="flex items-center gap-1 rounded border px-1.5 text-[11px]">
            {href ? (
              <Link href={href} className="hover:underline">
                {text}
              </Link>
            ) : (
              <span>{text}</span>
            )}
            {citeIn && cited ? <AddToReportButton orgId={orgId} investigationId={citeIn} row={cited} /> : null}
          </li>
        );
      })}
    </ul>
  );
}

/** A rationale as plain text. */
export function RationaleText({ text }: { text: string }) {
  if (!text) return null;
  return <p className="text-xs whitespace-pre-wrap break-words text-muted-foreground">{visText(text)}</p>;
}
