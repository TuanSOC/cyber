import {
  Activity,
  Bell,
  CircleDot,
  FileSearch,
  Flag,
  type LucideIcon,
  ShieldCheck,
  StickyNote,
} from "lucide-react";
import Link from "next/link";

import { AddToReportButton } from "@/components/reports/add-to-report";
import type { JobRoute } from "@/lib/ai";
import { type RefKindName, type TimelineEntry, isCaseEvent, timelineKindLabel, visText } from "@/lib/case";
import { formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { citedRowRef } from "@/lib/reports";

const KIND_ICON: Record<RefKindName, LucideIcon> = {
  custody: ShieldCheck,
  job: Activity,
  timeline: CircleDot,
  alert: Bell,
  finding: FileSearch,
  note: StickyNote,
  status: Flag,
};

const JOB_TAB: Partial<Record<string, string>> = { alert: "alerts", finding: "findings", timeline: "timeline" };

/**
 * One merged-timeline entry. Case events (notes, status changes) have no evidence: they are
 * labelled as case events and get no evidence link (RT10). Titles are text only.
 */
export function TimelineRow({
  orgId,
  entry,
  routes,
  citeIn,
}: {
  orgId: string;
  entry: TimelineEntry;
  routes: ReadonlyMap<string, JobRoute>;
  /** The case id when rows may be added to a report draft (findings, alerts, notes...). */
  citeIn?: string;
}) {
  const Icon = KIND_ICON[entry.ref_kind as RefKindName] ?? CircleDot;
  const when = formatDate(entry.ts);
  const route = entry.job_id ? routes.get(entry.job_id) : undefined;
  const tab = JOB_TAB[entry.ref_kind];
  const jobHref =
    route && entry.job_id
      ? orgPath(orgId, `${route}/${entry.job_id}${tab ? `?tab=${tab}&ref=${encodeURIComponent(entry.ref_id)}` : ""}`)
      : null;
  const caseEvent = isCaseEvent(entry);
  const cited = citeIn ? citedRowRef(entry.ref_kind, entry.ref_id, entry.job_id) : null;
  return (
    <li className="flex gap-3 px-3 py-2 text-sm" data-kind={entry.ref_kind}>
      <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <p className="break-words">{visText(entry.title)}</p>
        <p className="flex flex-wrap gap-x-2 text-xs text-muted-foreground">
          <span>{timelineKindLabel(entry.ref_kind)}</span>
          <time dateTime={entry.ts} title={`${when.utc} (${entry.ts_source} clock)`}>
            {when.local}
          </time>
          {entry.severity ? <span>severity {entry.severity}</span> : null}
          {caseEvent ? (
            <span>case event</span>
          ) : entry.evidence_id ? (
            <Link href={orgPath(orgId, `evidence/${entry.evidence_id}`)} className="underline-offset-4 hover:underline">
              evidence
            </Link>
          ) : null}
          {jobHref ? (
            <Link href={jobHref} className="underline-offset-4 hover:underline">
              open in analysis
            </Link>
          ) : null}
        </p>
      </div>
      {citeIn && cited ? (
        <div className="shrink-0">
          <AddToReportButton orgId={orgId} investigationId={citeIn} row={cited} />
        </div>
      ) : null}
    </li>
  );
}
