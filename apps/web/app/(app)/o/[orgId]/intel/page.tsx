"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { MitreNoticeFooter } from "@/components/ti/attack-chips";
import { type LookupOutcome, LookupForm, NormalizationReport } from "@/components/ti/lookup-form";
import { RecentRuns } from "@/components/ti/recent-runs";
import { RunResults } from "@/components/ti/run-results";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useOrg } from "@/lib/org-context";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** IOC lookup: manual values → normalization report → run progress → attributed results. */
export default function ThreatIntelPage() {
  return (
    <>
      <PageHeader
        title="Threat Intel"
        description="Look up indicators with your organization's enabled providers. Every answer is attributed to its provider and dated."
      />
      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
        <Lookup />
      </Suspense>
      <MitreNoticeFooter className="mt-8" />
    </>
  );
}

function Lookup() {
  const { orgId } = useOrg();
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const fromUrl = searchParams.get("run");
  const runId = fromUrl && UUID.test(fromUrl) ? fromUrl : null;
  const [outcome, setOutcome] = useState<LookupOutcome | null>(null);

  const selectRun = (id: string | null) => {
    const params = new URLSearchParams(window.location.search);
    if (id) params.set("run", id);
    else params.delete("run");
    const query = params.toString();
    window.history.pushState(null, "", query ? `${pathname}?${query}` : pathname);
  };

  return (
    <div className="flex flex-col gap-6">
      <Alert>
        <AlertDescription>
          Enabled providers receive the indicators you look up. Private IPs, internal names, URL query strings, emails
          (except MISP), file paths and registry keys are never sent. Answers are the providers&apos; own statements,
          not our assessment.
        </AlertDescription>
      </Alert>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Look up indicators</CardTitle>
        </CardHeader>
        <CardContent>
          <LookupForm
            orgId={orgId}
            onDone={(next) => {
              setOutcome(next);
              selectRun(next.runId);
            }}
          />
        </CardContent>
      </Card>
      {outcome && (
        <section className="flex flex-col gap-2">
          <h2 className="text-sm font-medium">Normalization</h2>
          <NormalizationReport outcome={outcome} />
        </section>
      )}
      {runId && (
        <section className="flex flex-col gap-2">
          <h2 className="text-sm font-medium">Results</h2>
          <RunResults key={runId} orgId={orgId} runId={runId} />
        </section>
      )}
      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium">Recent runs</h2>
        <RecentRuns
          orgId={orgId}
          selected={runId}
          onSelect={(id) => {
            setOutcome(null);
            selectRun(id);
          }}
        />
      </section>
    </div>
  );
}
