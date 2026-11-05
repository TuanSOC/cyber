"use client";

import { ShieldOff } from "lucide-react";
import Link from "next/link";

import { SHARE_POLICY_ANCHOR, caseTabHref, isPolicyBlocked, policyBlockedReason, shareReasonText } from "@/lib/case";
import { useAnalysisJob } from "@/lib/use-analysis-job";

/**
 * The "blocked by policy" state of an AI or threat-intel request (`409 policy_blocked`, M6):
 * the reason and a link to the case's share-policy card. Renders nothing for other errors, so a
 * call site can place it next to its generic error text.
 */
export function PolicyBlocked({
  orgId,
  error,
  reason,
  investigationId,
  jobId,
  what = "This request",
}: {
  orgId: string;
  /** The failed request's error; nothing is rendered unless it is `policy_blocked`. */
  error?: unknown;
  /** A reason already known (e.g. from `share_policy.reasons`) when there is no error object. */
  reason?: string | null;
  investigationId?: string | null;
  /** When only the job is known, the case is looked up from it for the link. */
  jobId?: string | null;
  what?: string;
}) {
  if (error !== undefined && !isPolicyBlocked(error)) return null;
  const text = shareReasonText(error !== undefined ? policyBlockedReason(error) : (reason ?? null));
  if (investigationId) {
    return <PolicyBlockedNotice what={what} reason={text} target={caseTabHref(orgId, investigationId, "overview", SHARE_POLICY_ANCHOR)} />;
  }
  if (jobId) return <JobPolicyBlocked orgId={orgId} jobId={jobId} what={what} reason={text} />;
  return <PolicyBlockedNotice what={what} reason={text} target={null} />;
}

function JobPolicyBlocked({ orgId, jobId, what, reason }: { orgId: string; jobId: string; what: string; reason: string }) {
  const job = useAnalysisJob(orgId, jobId);
  const inv = job.data?.investigation_id;
  return (
    <PolicyBlockedNotice what={what} reason={reason} target={inv ? caseTabHref(orgId, inv, "overview", SHARE_POLICY_ANCHOR) : null} />
  );
}

/** Presentational part (no data fetching); `target` is an internal case link built from ids. */
export function PolicyBlockedNotice({ what, reason, target }: { what: string; reason: string; target: string | null }) {
  return (
    <div className="flex items-start gap-2 rounded-md border bg-muted/40 p-3 text-sm" role="alert" data-policy-blocked="">
      <ShieldOff className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="flex flex-col gap-1">
        <p className="font-medium">{what} is blocked by the share policy.</p>
        <p className="text-muted-foreground">{reason} No data was sent.</p>
        {target ? (
          <Link href={target} className="w-fit text-xs underline underline-offset-4">
            Open the case share policy
          </Link>
        ) : (
          <p className="text-xs text-muted-foreground">The share policy is on the case page (Overview tab).</p>
        )}
      </div>
    </div>
  );
}
