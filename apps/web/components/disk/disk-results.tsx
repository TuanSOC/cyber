"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { FindingsTab } from "@/components/analysis/findings-tab";
import { IocsTab } from "@/components/analysis/iocs-tab";
import { NoResults } from "@/components/analysis/result-parts";
import { TimelineTab } from "@/components/analysis/timeline-tab";
import { DiskOverview } from "@/components/disk/disk-overview";
import { DiskTimelineTab } from "@/components/disk/disk-timeline-tab";
import { ExportsTab } from "@/components/disk/exports-tab";
import { FileDrawer } from "@/components/disk/file-drawer";
import { FilesTab } from "@/components/disk/files-tab";
import { PartitionsTab } from "@/components/disk/partitions-tab";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AnalysisJob } from "@/lib/analysis";
import { DISK_EXPORT_MAX_FILES, DISK_REF_TABS, DISK_TABS, type DiskSummary, type DiskTab, parseDiskTab } from "@/lib/disk";
import { fileExportErrorText } from "@/lib/disk-exports";
import { withParams } from "@/lib/pcap-results";
import { useRequestFileExports } from "@/lib/use-disk-job";

const isoParam = (value: string | null): string | undefined => (value && Number.isFinite(Date.parse(value)) ? value : undefined);

/**
 * Overview + result tabs of a disk analysis. The active tab (`?tab=`) lives in the URL so a view
 * can be shared; a cited row (`?ref=`) narrows its tab; `from` / `to` open the timeline on a
 * range. The file drawer and the export batch are shared by the Files and Timeline tabs.
 */
export function DiskResults({
  orgId,
  job,
  summary,
  restricted,
  canWrite,
  enrichDisabledReason,
}: {
  orgId: string;
  job: AnalysisJob;
  summary: DiskSummary | undefined;
  restricted: boolean;
  canWrite: boolean;
  /** RT16: why Enrich is hidden (restricted segments or TI flag), undefined when allowed. */
  enrichDisabledReason: string | undefined;
}) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const tab = parseDiskTab(searchParams.get("tab"));
  const ready = job.status === "succeeded";
  const props = { orgId, jobId: job.id };
  const [openFile, setOpenFile] = useState<string | null>(null);
  const [batch, setBatch] = useState<string[]>([]);
  const request = useRequestFileExports(orgId, job.id);

  const go = (updates: Record<string, string | undefined>) =>
    window.history.replaceState(null, "", `${pathname}${withParams(window.location.search, updates)}`);
  const cited = {
    citedRef: DISK_REF_TABS.has(tab) ? searchParams.get("ref") : null,
    onClearRef: () => go({ ref: undefined }),
  };
  const select = (value: string) => go({ tab: value === "overview" ? undefined : value, ref: undefined, from: undefined, to: undefined });

  const exportFiles = (ids: string[]) =>
    request.mutate(ids, {
      onSuccess: (list) => {
        toast.success(`${list.items.length} file export${list.items.length === 1 ? "" : "s"} requested: see the Exports tab`);
        setBatch([]);
      },
      onError: (error) => toast.error(fileExportErrorText(error)),
    });
  const toggleBatch = (id: string) =>
    setBatch((current) =>
      current.includes(id) ? current.filter((other) => other !== id) : current.length >= DISK_EXPORT_MAX_FILES ? current : [...current, id],
    );

  const content = (value: Exclude<DiskTab, "overview">) => {
    switch (value) {
      case "partitions":
        return <PartitionsTab {...props} sectorSize={summary?.sector_size ?? null} />;
      case "files":
        return (
          <FilesTab
            {...props}
            {...cited}
            openId={openFile}
            onOpen={setOpenFile}
            batch={batch}
            onExportBatch={() => exportFiles(batch)}
            onClearBatch={() => setBatch([])}
            exportPending={request.isPending}
          />
        );
      case "timeline":
        return cited.citedRef ? (
          <TimelineTab {...props} {...cited} onShowFlow={() => undefined} />
        ) : (
          <DiskTimelineTab
            {...props}
            artifacts={(summary?.artifacts ?? []).map((a) => a.artifact)}
            initialRange={{ from: isoParam(searchParams.get("from")), to: isoParam(searchParams.get("to")) }}
            onOpenFile={setOpenFile}
          />
        );
      case "findings":
        return <FindingsTab {...props} {...cited} variant="static" />;
      case "iocs":
        return <IocsTab {...props} {...cited} source="disk image" enrichDisabledReason={enrichDisabledReason} />;
      case "exports":
        return <ExportsTab {...props} investigationId={job.investigation_id} restricted={restricted} canWrite={canWrite} />;
    }
  };

  return (
    <>
      <Tabs value={tab} onValueChange={select}>
        <TabsList aria-label="Disk analysis results" className="h-auto flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {DISK_TABS.map(([value, label]) => (
            <TabsTrigger key={value} value={value}>
              {label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="overview">{summary ? <DiskOverview summary={summary} /> : <NoResults status={job.status} />}</TabsContent>
        {DISK_TABS.map(([value]) => (
          <TabsContent key={value} value={value}>
            {ready ? content(value) : <NoResults status={job.status} />}
          </TabsContent>
        ))}
      </Tabs>
      {ready ? (
        <FileDrawer
          {...props}
          fileId={openFile}
          canExport={canWrite}
          inBatch={(id) => batch.includes(id)}
          exportPending={request.isPending}
          onExport={(id) => exportFiles([id])}
          onToggleBatch={toggleBatch}
          onClose={() => setOpenFile(null)}
        />
      ) : null}
    </>
  );
}
