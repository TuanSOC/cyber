"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";

import { FindingsTab } from "@/components/analysis/findings-tab";
import { IocsTab } from "@/components/analysis/iocs-tab";
import { NoResults } from "@/components/analysis/result-parts";
import { TimelineTab } from "@/components/analysis/timeline-tab";
import { ArtifactsTab } from "@/components/memory/artifacts-tab";
import { MemoryOverview } from "@/components/memory/memory-overview";
import { NetworkTab } from "@/components/memory/network-tab";
import { ProcessPanel } from "@/components/memory/process-panel";
import { ProcessesTab, useProcessFlags } from "@/components/memory/processes-tab";
import { RegionsTab } from "@/components/memory/regions-tab";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AnalysisJob } from "@/lib/analysis";
import { MEMORY_REF_TABS, type MemorySummary, type MemoryTab, memoryTabs, parseMemoryTab } from "@/lib/memory";
import { withParams } from "@/lib/pcap-results";

function SharedProcessPanel({
  orgId,
  jobId,
  pid,
  onSelect,
}: {
  orgId: string;
  jobId: string;
  pid: number | null;
  onSelect: (pid: number | null) => void;
}) {
  const { flags } = useProcessFlags(orgId, jobId);
  return <ProcessPanel orgId={orgId} jobId={jobId} pid={pid} flags={flags} onSelect={onSelect} onClose={() => onSelect(null)} />;
}

/**
 * Overview + result tabs of a memory analysis. The active tab (`?tab=`) lives in the URL so a
 * view can be shared; a cited row (`?ref=<row id>`) narrows its tab to that row. The OS decides
 * the Windows (Modules, Services, Registry) or Linux tabs. No YARA tab (RT8), no AI tab (no
 * memory task; generic AI only after release).
 */
export function MemoryResults({
  orgId,
  job,
  summary,
  enrichDisabledReason,
}: {
  orgId: string;
  job: AnalysisJob;
  summary: MemorySummary | undefined;
  /** RT16: why Enrich is hidden (restricted evidence or TI flag), undefined when allowed. */
  enrichDisabledReason: string | undefined;
}) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const [pid, setPid] = useState<number | null>(null);
  const os = summary?.os ?? null;
  const tabs = memoryTabs(os);
  const tab = parseMemoryTab(searchParams.get("tab"), os);
  const ready = job.status === "succeeded";
  const props = { orgId, jobId: job.id };

  const go = (updates: Record<string, string | undefined>) =>
    window.history.replaceState(null, "", `${pathname}${withParams(window.location.search, updates)}`);
  const cited = {
    citedRef: MEMORY_REF_TABS.has(tab) ? searchParams.get("ref") : null,
    onClearRef: () => go({ ref: undefined }),
  };
  const select = (value: string) => go({ tab: value === "overview" ? undefined : value, ref: undefined });

  const content = (value: Exclude<MemoryTab, "overview">) => {
    switch (value) {
      case "processes":
        return <ProcessesTab {...props} {...cited} onSelect={setPid} />;
      case "network":
        return <NetworkTab {...props} {...cited} onShowProcess={setPid} />;
      case "regions":
        return <RegionsTab {...props} {...cited} />;
      case "modules":
      case "services":
      case "registry":
      case "linux":
        return <ArtifactsTab {...props} {...cited} tab={value} profile={job.profile} />;
      case "findings":
        return <FindingsTab {...props} {...cited} variant="static" />;
      case "iocs":
        return <IocsTab {...props} {...cited} source="memory image" enrichDisabledReason={enrichDisabledReason} />;
      case "timeline":
        return <TimelineTab {...props} {...cited} onShowFlow={() => select("network")} />;
    }
  };

  return (
    <>
      <Tabs value={tab} onValueChange={select}>
        <TabsList aria-label="Memory analysis results" className="h-auto flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {tabs.map(([value, label]) => (
            <TabsTrigger key={value} value={value}>
              {label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="overview">
          {summary ? <MemoryOverview summary={summary} /> : <NoResults status={job.status} />}
        </TabsContent>
        {tabs.map(([value]) => (
          <TabsContent key={value} value={value}>
            {ready ? content(value) : <NoResults status={job.status} />}
          </TabsContent>
        ))}
      </Tabs>
      {ready ? <SharedProcessPanel orgId={orgId} jobId={job.id} pid={pid} onSelect={setPid} /> : null}
    </>
  );
}
