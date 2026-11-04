"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";

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
import { type FlowLink, RESULT_TABS, parseOverview, parseTab, withParams } from "@/lib/pcap-results";

// Flow filters live in the URL only while the Flows tab is open.
const FLOW_PARAMS = { ip: undefined, port: undefined, ref: undefined };

/**
 * Overview + result tabs. The active tab (`?tab=`) and the Flows filters (`ip`, `port`, `ref`)
 * are kept in the URL so a view, e.g. "the flow behind this finding", can be shared.
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

  const go = (updates: Record<string, string | number | undefined>, mode: "push" | "replace") => {
    const href = `${pathname}${withParams(window.location.search, updates)}`;
    if (mode === "push") window.history.pushState(null, "", href);
    else window.history.replaceState(null, "", href);
  };
  const showFlow = (link: FlowLink) => {
    setLinkCount((n) => n + 1);
    go({ tab: "flows", ip: link.ip, port: link.port, ref: link.ref }, "push");
  };
  const props = { orgId, jobId: job.id, onShowFlow: showFlow };

  return (
    <Tabs
      value={tab}
      onValueChange={(value) =>
        go({ ...(value === "flows" ? {} : FLOW_PARAMS), tab: value === "overview" ? undefined : value }, "replace")
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
            <FindingsTab {...props} />
          ) : value === "alerts" ? (
            <AlertsTab {...props} suricataMissing={suricataMissing} />
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
            <RecordsTab {...props} kind={value} />
          ) : value === "iocs" ? (
            <IocsTab orgId={orgId} jobId={job.id} />
          ) : (
            <TimelineTab {...props} />
          )}
        </TabsContent>
      ))}
    </Tabs>
  );
}
