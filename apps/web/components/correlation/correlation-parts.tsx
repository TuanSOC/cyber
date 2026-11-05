"use client";

import Link from "next/link";

import { IocValue } from "@/components/ioc-collections/ioc-parts";
import { Badge } from "@/components/ui/badge";
import { caseTabHref, visText } from "@/lib/case";
import {
  type CorrelationKind,
  type Occurrence,
  type RelatedCase,
  type SeenIn,
  commonBadgeText,
  evidenceHref,
  kindLabel,
  kindsText,
  occurrenceJobHref,
  seenInChipText,
  sharedKeysText,
} from "@/lib/correlation";
import { STATUS_LABELS, formatDate } from "@/lib/format";

/*
 * Presentational parts of the correlation pivots. Observable values are attacker-controlled:
 * defanged text, never a link. Wording stays neutral ("also observed in"): a shared observable
 * is a fact about the data, not a claim about who is behind it.
 */

export type KeyTarget = { kind: CorrelationKind; value: string };

export function WhenText({ iso, prefix }: { iso: string | null | undefined; prefix: string }) {
  if (!iso) return null;
  const { local, utc } = formatDate(iso);
  return (
    <span className="text-xs text-muted-foreground" title={utc}>
      {prefix} {local}
    </span>
  );
}

export function CommonBadge({ jobs }: { jobs: number }) {
  return (
    <Badge variant="outline" className="border-amber-500/50 text-amber-600 dark:text-amber-400" title={commonBadgeText(jobs)}>
      {commonBadgeText(jobs)}
    </Badge>
  );
}

/**
 * One key of the job: value, kind, the "seen in N other cases" chip (opens the drawer).
 * `onPage`: an IOC row shown in the table below carries the key (joined by row id).
 */
export function SeenInRow({
  item,
  onOpen,
  onPage = false,
}: {
  item: SeenIn;
  onOpen: (target: KeyTarget) => void;
  onPage?: boolean;
}) {
  return (
    <li className="flex flex-wrap items-center gap-2 py-1" data-on-page={onPage ? "" : undefined}>
      <Badge variant="secondary">{kindLabel(item.kind)}</Badge>
      <IocValue value={item.value} type={item.kind} reveal={false} />
      <button
        type="button"
        onClick={() => onOpen({ kind: item.kind, value: item.value })}
        className="rounded-full border px-2 py-0.5 text-xs outline-none hover:bg-muted focus-visible:ring-[3px] focus-visible:ring-ring/50"
        aria-label={`${seenInChipText(item)}: show where ${kindLabel(item.kind)} value was also observed`}
      >
        {seenInChipText(item)}
      </button>
      {item.common && <CommonBadge jobs={item.other_jobs + 1} />}
      {onPage && (
        <span className="text-xs text-muted-foreground" title="An IOC row shown below carries this value">
          in the rows below
        </span>
      )}
    </li>
  );
}

export function SeenInList({
  items,
  onOpen,
  limit,
  onPageCount = 0,
}: {
  items: readonly SeenIn[];
  onOpen: (target: KeyTarget) => void;
  limit?: number;
  /** The first `onPageCount` items are carried by IOC rows on screen. */
  onPageCount?: number;
}) {
  const shown = limit === undefined ? items : items.slice(0, limit);
  return (
    <ul className="flex flex-col divide-y">
      {shown.map((item, index) => (
        <SeenInRow key={`${item.kind}:${item.key}`} item={item} onOpen={onOpen} onPage={index < onPageCount} />
      ))}
    </ul>
  );
}

/** Where one observable was seen: case, evidence and job links, first / last seen. */
export function OccurrenceList({ orgId, items }: { orgId: string; items: readonly Occurrence[] }) {
  return (
    <ul className="flex flex-col gap-2">
      {items.map((o) => {
        const jobHref = occurrenceJobHref(orgId, o);
        const fileHref = evidenceHref(orgId, o.evidence_id);
        return (
          <li key={o.job_id} className="flex flex-col gap-0.5 rounded-md border p-2">
            <Link href={caseTabHref(orgId, o.investigation_id)} className="text-sm font-medium underline-offset-4 hover:underline">
              <span className="font-mono text-xs">{visText(o.case_ref)}</span> {visText(o.title)}
            </Link>
            <span className="flex flex-wrap gap-x-3 text-xs">
              {fileHref && (
                <Link href={fileHref} className="break-all underline-offset-4 hover:underline">
                  {visText(o.evidence_filename)}
                </Link>
              )}
              {jobHref && (
                <Link href={jobHref} className="underline-offset-4 hover:underline">
                  {o.analyzer === "pcap" ? "capture analysis" : "file analysis"}
                </Link>
              )}
            </span>
            <span className="flex flex-wrap gap-x-3">
              <WhenText iso={o.first_seen} prefix="first seen" />
              <WhenText iso={o.last_seen} prefix="last seen" />
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/** Ranked cases sharing observables with this one (counts only, no score). */
export function RelatedCasesList({ orgId, items }: { orgId: string; items: readonly RelatedCase[] }) {
  return (
    <ol className="flex flex-col gap-2">
      {items.map((c) => (
        <li key={c.investigation_id} className="flex flex-col gap-0.5 rounded-md border p-2">
          <div className="flex flex-wrap items-center gap-2">
            <Link href={caseTabHref(orgId, c.investigation_id)} className="min-w-0 text-sm font-medium underline-offset-4 hover:underline">
              <span className="font-mono text-xs">{visText(c.case_ref)}</span> {visText(c.title)}
            </Link>
            {(c.status === "archived" || c.status === "closed") && (
              <Badge variant="outline">{STATUS_LABELS[c.status] ?? c.status}</Badge>
            )}
          </div>
          <span className="text-xs">
            {sharedKeysText(c.shared_keys)}
            {kindsText(c.kinds) && <span className="text-muted-foreground"> ({kindsText(c.kinds)})</span>}
          </span>
          {(c.sample_keys ?? []).length > 0 && (
            <ul className="flex flex-col gap-0.5" aria-label="Sample shared observables">
              {(c.sample_keys ?? []).map((k) => (
                <li key={`${k.kind}:${k.key}`} className="flex flex-wrap items-center gap-2 text-xs">
                  <Badge variant="secondary">{kindLabel(k.kind)}</Badge>
                  <IocValue value={k.value} type={k.kind} reveal={false} />
                </li>
              ))}
            </ul>
          )}
          <WhenText iso={c.last_seen} prefix="last observed" />
        </li>
      ))}
    </ol>
  );
}
