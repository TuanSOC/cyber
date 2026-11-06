"use client";

import { usePathname, useSearchParams } from "next/navigation";

import { FindingsTab } from "@/components/analysis/findings-tab";
import { IocsTab } from "@/components/analysis/iocs-tab";
import { NoResults } from "@/components/analysis/result-parts";
import { FunctionView } from "@/components/reverse/function-view";
import { FunctionsTab } from "@/components/reverse/functions-tab";
import { ReOverview } from "@/components/reverse/re-overview";
import { ImportsTab, StringsTab } from "@/components/reverse/symbols-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AnalysisJob } from "@/lib/analysis";
import { withParams } from "@/lib/pcap-results";
import { type FunctionTab, RE_REF_TABS, RE_TABS, type ReSummary, type ReTab, formatAddress, parseReLocation } from "@/lib/reverse";

/**
 * Overview + result tabs of an RE job. The state lives in the URL so a view can be shared and
 * AI citations can deep-link: `?tab=`, `?fn=<entry>&tab=facts|code` (one function, opened above
 * the functions table) and `?ref=<row id>` (a cited row). No call-graph view (RT24): callers and
 * callees are linked lists in the function view.
 */
export function ReResults({ orgId, job, summary }: { orgId: string; job: AnalysisJob; summary: ReSummary | undefined }) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const location = parseReLocation(searchParams);
  const ready = job.status === "succeeded";
  const props = { orgId, jobId: job.id };
  const profile = summary?.profile ?? (job.profile === "quick" ? "quick" : "full");

  const go = (updates: Record<string, string | undefined>) =>
    window.history.replaceState(null, "", `${pathname}${withParams(window.location.search, updates)}`);
  const cited = {
    citedRef: RE_REF_TABS.has(location.tab) && !location.fn ? location.ref : null,
    onClearRef: () => go({ ref: undefined }),
  };
  const select = (value: string) => go({ tab: value === "overview" ? undefined : value, ref: undefined, fn: undefined });
  const openFunction = (entry: string, tab: FunctionTab = "facts") =>
    go({ tab, fn: formatAddress(entry), ref: undefined });

  const content = (value: Exclude<ReTab, "overview">) => {
    switch (value) {
      case "functions":
        return (
          <>
            {location.fn ? (
              <FunctionView
                orgId={orgId}
                job={job}
                entry={location.fn}
                tab={location.functionTab}
                profile={profile}
                onTab={(tab) => openFunction(location.fn ?? "", tab)}
                onOpen={(entry) => openFunction(entry)}
                onClose={() => go({ tab: "functions", fn: undefined })}
              />
            ) : null}
            <FunctionsTab {...props} {...cited} selected={location.fn} onOpen={(entry) => openFunction(entry)} />
          </>
        );
      case "imports":
        return <ImportsTab {...props} {...cited} onOpen={(entry) => openFunction(entry)} />;
      case "strings":
        return <StringsTab {...props} {...cited} onOpen={(entry) => openFunction(entry)} />;
      case "findings":
        return <FindingsTab {...props} {...cited} variant="static" />;
      case "iocs":
        return <IocsTab {...props} {...cited} source="program strings" />;
    }
  };

  return (
    <Tabs value={location.tab} onValueChange={select}>
      <TabsList aria-label="Reverse engineering results" className="h-auto flex-wrap">
        <TabsTrigger value="overview">Overview</TabsTrigger>
        {RE_TABS.map(([value, label]) => (
          <TabsTrigger key={value} value={value}>
            {label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value="overview">{summary ? <ReOverview orgId={orgId} summary={summary} /> : <NoResults status={job.status} />}</TabsContent>
      {RE_TABS.map(([value]) => (
        <TabsContent key={value} value={value}>
          {ready ? content(value) : <NoResults status={job.status} />}
        </TabsContent>
      ))}
    </Tabs>
  );
}
