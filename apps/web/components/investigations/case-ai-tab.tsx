"use client";

import { IncidentCard } from "@/components/ai/incident-card";
import { PolicyBlocked } from "@/components/ai/policy-blocked";
import type { Investigation } from "@/lib/case";

/**
 * AI tab: the M5 incident card. While the share policy blocks AI, the "blocked by policy"
 * state is shown first (earlier runs stay readable; new runs are refused by the API).
 */
export function CaseAiTab({ orgId, inv }: { orgId: string; inv: Investigation }) {
  const policy = inv.share_policy;
  const reason = policy.reasons.find((r) => r === "tlp_red" || r.includes("ai")) ?? policy.reasons[0] ?? null;
  return (
    <div className="flex flex-col gap-4">
      {policy.ai_blocked ? (
        <PolicyBlocked orgId={orgId} reason={reason} investigationId={inv.id} what="AI analysis of this case" />
      ) : null}
      <IncidentCard orgId={orgId} investigationId={inv.id} />
    </div>
  );
}
