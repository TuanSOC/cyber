"use client";

import { usePathname, useSearchParams } from "next/navigation";

import { AttackTab } from "@/components/case-attack/attack-tab";
import { InvestigationAnalyses } from "@/components/analysis/investigation-analyses";
import { CaseAiTab } from "@/components/investigations/case-ai-tab";
import { CaseEvidenceTab } from "@/components/investigations/case-evidence-tab";
import { LegalHoldBadge } from "@/components/investigations/legal-hold-badge";
import { OverviewTab } from "@/components/investigations/overview-tab";
import { CaseIocsTab } from "@/components/ioc-collections/case-iocs-tab";
import { NotesTab } from "@/components/notes/notes-tab";
import { CaseReportsPanel } from "@/components/reports/case-reports-panel";
import { CaseTimeline } from "@/components/timeline/case-timeline";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CASE_TABS, type CaseTab, type Investigation, type InvestigationUpdate, parseCaseTab } from "@/lib/case";
import { withParams } from "@/lib/pcap-results";
import type { Permission } from "@/lib/roles";

/**
 * The case workspace: one `role="tablist"` (Radix: arrow keys move between tabs) whose active
 * tab is kept in `?tab=` so deep links work. Each tab is its own component; only the active
 * one is mounted, so its queries run when it is opened.
 */
export function CaseWorkspace({
  orgId,
  inv,
  can,
  pending,
  onUpdate,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
  pending: boolean;
  onUpdate: (body: InvestigationUpdate) => void;
}) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const tab = parseCaseTab(searchParams.get("tab"));
  const select = (value: string) => {
    const next: CaseTab = parseCaseTab(value);
    const href = `${pathname}${withParams(window.location.search, { tab: next === "overview" ? undefined : next })}`;
    window.history.replaceState(null, "", href);
  };
  const props = { orgId, inv, can };

  return (
    <Tabs value={tab} onValueChange={select}>
      {/* M7 slot: the legal-hold badge of the case (phase 9). */}
      <LegalHoldBadge legalHold={inv.legal_hold} />
      <TabsList aria-label="Case sections" className="max-w-full overflow-x-auto">
        {CASE_TABS.map(([value, label]) => (
          <TabsTrigger key={value} value={value}>
            {label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value="overview">
        <OverviewTab {...props} pending={pending} onUpdate={onUpdate} />
      </TabsContent>
      <TabsContent value="evidence" className="flex flex-col gap-6">
        <CaseEvidenceTab {...props} />
        <InvestigationAnalyses orgId={orgId} investigationId={inv.id} />
      </TabsContent>
      <TabsContent value="notes">
        <NotesTab {...props} />
      </TabsContent>
      <TabsContent value="iocs">
        <CaseIocsTab {...props} />
      </TabsContent>
      <TabsContent value="attack">
        <AttackTab {...props} />
      </TabsContent>
      <TabsContent value="timeline">
        <CaseTimeline {...props} />
      </TabsContent>
      <TabsContent value="ai">
        <CaseAiTab orgId={orgId} inv={inv} />
      </TabsContent>
      <TabsContent value="reports">
        <CaseReportsPanel orgId={orgId} investigationId={inv.id} can={can} archived={inv.status === "archived"} />
      </TabsContent>
    </Tabs>
  );
}
