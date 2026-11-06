"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { RunView } from "@/components/ai/run-view";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { childFlags, isUuid, routeForTask, runTargetHref, runTargetText, taskLabel } from "@/lib/ai";
import { ANALYZER_ROUTES } from "@/lib/analysis";
import { ApiError, api, unwrap } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useAiRun } from "@/lib/use-ai";

/** One AI run with its full output view. */
export default function AiRunPage() {
  const { runId } = useParams<{ runId: string }>();
  const { orgId } = useOrg();
  const back = orgPath(orgId, "ai-analyst");
  const valid = isUuid(runId);
  const run = useAiRun(orgId, valid ? runId : null);
  const detail = run.data;
  const lookupJob = detail?.job_id && !routeForTask(detail.task) ? detail.job_id : null;
  // The task alone does not say whether the job is a PCAP or a static analysis: look it up.
  const job = useQuery({
    queryKey: ["org", orgId, "analysis", lookupJob ?? ""],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}", {
          params: { path: { org_id: orgId, job_id: lookupJob ?? "" } },
        }),
      ),
    enabled: lookupJob !== null,
    staleTime: 5 * 60_000,
  });

  if (!valid || (run.error instanceof ApiError && (run.error.status === 404 || run.error.status === 422))) {
    return <NotFoundCard title="AI run not found" backHref={back} backLabel="AI Analyst" />;
  }
  const route = detail
    ? (routeForTask(detail.task) ?? (job.data ? ANALYZER_ROUTES[job.data.analyzer] : null))
    : null;
  const target = detail ? runTargetHref(orgId, detail, route) : null;

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> AI Analyst
      </Link>
      <PageHeader
        title={detail ? taskLabel(detail.task) : "AI run"}
        description={detail ? `Requested by ${detail.requested_by_name}` : undefined}
        actions={
          target && detail ? (
            <Link href={target} className="text-sm underline underline-offset-4">
              Open {runTargetText(detail).toLowerCase()}
            </Link>
          ) : undefined
        }
      />
      <RunView
        orgId={orgId}
        runId={runId}
        variant={detail?.task === "incident_summary" ? "incident" : "job"}
        extraFlags={(r) => childFlags(r.child_runs)}
      />
    </>
  );
}
