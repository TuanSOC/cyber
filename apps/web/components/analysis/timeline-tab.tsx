"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { CirclePlay, CircleStop, Flag, Handshake, Info, type LucideIcon, Siren } from "lucide-react";

import { FlowButton, PAGE_SIZE, Trunc, When, usePageOffset } from "@/components/analysis/result-parts";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { SeverityBadge } from "@/components/severity-badge";
import { api, unwrap } from "@/lib/api";
import { type FlowLink, type TimelineItem, endpointText } from "@/lib/pcap-results";

const EVENTS: Record<string, [LucideIcon, string]> = {
  capture_start: [CirclePlay, "Capture start"],
  capture_end: [CircleStop, "Capture end"],
  finding: [Flag, "Finding"],
  alert: [Siren, "Alert"],
  first_contact: [Handshake, "First contact"],
};

export function TimelineTab({
  orgId,
  jobId,
  onShowFlow,
}: {
  orgId: string;
  jobId: string;
  onShowFlow: (link: FlowLink) => void;
}) {
  const [offset, setOffset] = usePageOffset("");
  const query = { limit: PAGE_SIZE, offset };
  const timeline = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "timeline", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/timeline", {
          params: { path: { org_id: orgId, job_id: jobId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
  });
  const items = timeline.data?.items;

  return (
    <div className="flex flex-col gap-3">
      {timeline.isError && <QueryError error={timeline.error} onRetry={() => void timeline.refetch()} />}
      {timeline.isPending && !timeline.isError && (
        <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">Loading…</p>
      )}
      {items?.length === 0 && (
        <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">No timeline entries.</p>
      )}
      {items && items.length > 0 && (
        <ol className="relative ml-3 border-l pl-6">
          {items.map((entry) => (
            <TimelineEntry key={entry.id} entry={entry} onShowFlow={onShowFlow} />
          ))}
        </ol>
      )}
      <Pager offset={offset} total={timeline.data?.total ?? 0} onChange={setOffset} />
    </div>
  );
}

function TimelineEntry({ entry, onShowFlow }: { entry: TimelineItem; onShowFlow: (link: FlowLink) => void }) {
  const [Icon, label] = Object.hasOwn(EVENTS, entry.event) ? EVENTS[entry.event] : [Info, entry.event];
  const hasEnds = entry.src_ip || entry.dst_ip;
  return (
    <li className="relative pb-4 last:pb-0">
      <span className="absolute top-0.5 -left-[2.3rem] flex size-6 items-center justify-center rounded-full border bg-background">
        <Icon className="size-3.5 text-muted-foreground" aria-hidden />
      </span>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span className="text-xs">
          <When iso={entry.ts} />
        </span>
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        {entry.severity && <SeverityBadge severity={entry.severity} />}
      </div>
      <Trunc value={entry.title} className="mt-0.5 max-w-full text-sm font-medium" />
      {(hasEnds || entry.ref) && (
        <div className="mt-0.5 flex flex-wrap items-center gap-x-3 text-xs text-muted-foreground">
          {hasEnds && (
            <span className="max-w-96 truncate font-mono">
              {endpointText(entry.src_ip, null)} → {endpointText(entry.dst_ip, null)}
            </span>
          )}
          {entry.ref && (
            <span className="inline-flex min-w-0 items-center gap-1">
              <span>{entry.event === "alert" ? "SID" : "Ref"}</span>
              <Trunc value={entry.ref} mono className="max-w-48" />
            </span>
          )}
          {entry.event === "first_contact" && entry.ref && (
            <FlowButton link={{ ip: entry.dst_ip ?? entry.src_ip ?? undefined, ref: entry.ref }} onShowFlow={onShowFlow} />
          )}
        </div>
      )}
    </li>
  );
}
