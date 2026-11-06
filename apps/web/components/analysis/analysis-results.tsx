"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";

import { AiAnalystTab } from "@/components/ai/ai-tab";
import { AlertsTab } from "@/components/analysis/alerts-tab";
import { AnalysisOverview } from "@/components/analysis/analysis-overview";
import { FindingsTab } from "@/components/analysis/findings-tab";
import { FlowsTab } from "@/components/analysis/flows-tab";
import { IocsTab } from "@/components/analysis/iocs-tab";
import { RecordsTab } from "@/components/analysis/records-tab";
import { NoResults } from "@/components/analysis/result-parts";
import { TimelineTab } from "@/components/analysis/timeline-tab";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AnalysisJob } from "@/lib/analysis";
import { evidenceEnrichDisabledReason } from "@/lib/memory-sensitivity";
import { useEvidenceRecord } from "@/lib/use-memory-job";
import { type FlowLink, REF_TABS, RESULT_TABS, parseOverview, parseTab, withParams } from "@/lib/pcap-results";

// Flow filters live in the URL only while the Flows tab is open; a cited row (`ref`) only on
// the tab it was linked to.
const FLOW_PARAMS = { ip: undefined, port: undefined, ref: undefined };

/**
 * Overview + result tabs. The active tab (`?tab=`) and the Flows filters (`ip`, `port`, `ref`)
 * are kept in the URL so a view, e.g. "the flow behind this finding", can be shared. On the
 * other list tabs `ref=<row id>` (an AI citation deep link) narrows the list to the cited row.
 * Native history calls are used; Next.js keeps `useSearchParams` in sync with them.
 */
export function AnalysisResults({ orgId, job }: { orgId: string; job: AnalysisJob }) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const tab = parseTab(searchParams.get("tab"));
  // Bumped on every flow link so the Flows tab restarts from the linked filters.
  const [linkCount, setLinkCount] = useState(0);
  const ready = job.status === "succeeded";
  const suricataMissing = parseOverview(job.summary).engineErrors.some((code) => code.startsWith("suricata_"));
  // Enrich is hidden on restricted evidence (a memory image's other analyses, RT3/RT16).
  const evidence = useEvidenceRecord(orgId, job.evidence_id);

  const go = (updates: Record<string, string | number | undefined>, mode: "push" | "replace") => {
    const href = `${pathname}${withParams(window.location.search, updates)}`;
    if (mode === "push") window.history.pushState(null, "", href);
    else window.history.replaceState(null, "", href);
  };
  const showFlow = (link: FlowLink) => {
    setLinkCount((n) => n + 1);
    go({ tab: "flows", ip: link.ip, port: link.port, ref: link.ref }, "push");
  };
  const citedRef = REF_TABS.has(tab) ? searchParams.get("ref") : null;
  const clearRef = () => go({ ref: undefined }, "replace");
  const props = { orgId, jobId: job.id, onShowFlow: showFlow };
  const cited = { citedRef, onClearRef: clearRef };

  return (
    <Tabs
      value={tab}
      onValueChange={(value) =>
        go({ ...FLOW_PARAMS, tab: value === "overview" ? undefined : value }, "replace")
      }
    >
      <TabsList aria-label="Analysis results">
        <TabsTrigger value="overview">Overview</TabsTrigger>
        {RESULT_TABS.map(([value, label]) => (
          <TabsTrigger key={value} value={value}>
            {label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value="overview">
        <AnalysisOverview job={job} onShowFlows={ready ? showFlow : undefined} />
      </TabsContent>
      {RESULT_TABS.map(([value]) => (
        <TabsContent key={value} value={value}>
          {!ready ? (
            <NoResults status={job.status} />
          ) : value === "findings" ? (
            <FindingsTab {...props} {...cited} />
          ) : value === "alerts" ? (
            <AlertsTab {...props} {...cited} suricataMissing={suricataMissing} />
          ) : value === "flows" ? (
            <FlowsTab
              key={linkCount}
              orgId={orgId}
              jobId={job.id}
              initialIp={searchParams.get("ip") ?? ""}
              initialPort={searchParams.get("port") ?? ""}
              highlightRef={searchParams.get("ref")}
              onUrlChange={(updates) => go(updates, "replace")}
            />
          ) : value === "dns" || value === "http" || value === "tls" ? (
            <RecordsTab {...props} {...cited} kind={value} />
          ) : value === "iocs" ? (
            <IocsTab
              orgId={orgId}
              jobId={job.id}
              {...cited}
              enrichDisabledReason={evidenceEnrichDisabledReason(evidence.data)}
            />
          ) : value === "ai" ? (
            <AiAnalystTab orgId={orgId} job={job} />
          ) : (
            <TimelineTab {...props} {...cited} />
          )}
        </TabsContent>
      ))}
    </Tabs>
  );
}
