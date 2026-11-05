"use client";

import { useQuery } from "@tanstack/react-query";

import { OrgLegalHolds } from "@/components/legal-holds/org-legal-holds";
import { QueryError } from "@/components/query-error";
import { RetentionPolicyCard } from "@/components/retention/retention-policy-card";
import { RetentionPreviewCard } from "@/components/retention/retention-preview";
import { RetentionRunsCard } from "@/components/retention/retention-runs";
import { DEFAULT_DELAY_DAYS } from "@/lib/legal-holds";
import { useOrg } from "@/lib/org-context";
import { fetchPolicy, retentionKeys } from "@/lib/retention";

export default function RetentionSettingsPage() {
  const { orgId, orgName, can } = useOrg();
  const policy = useQuery({
    queryKey: retentionKeys.policy(orgId),
    queryFn: () => fetchPolicy(orgId),
    enabled: can("org.read"),
  });

  if (!can("org.read")) {
    return <p className="text-sm text-muted-foreground">You cannot view this organization&apos;s retention policy.</p>;
  }
  const editable = can("org.update");
  const p = policy.data;

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      {policy.isError ? (
        <QueryError error={policy.error} onRetry={() => void policy.refetch()} />
      ) : p ? (
        <>
          <RetentionPolicyCard
            key={`${p.updated_at ?? "default"}:${p.enforce}:${p.pending_enforce}`}
            orgId={orgId}
            orgName={orgName}
            policy={p}
            editable={editable}
          />
          {editable && <RetentionPreviewCard orgId={orgId} policy={p} />}
        </>
      ) : (
        <p className="text-sm text-muted-foreground">Loading retention policy…</p>
      )}
      {can("audit.read") && <RetentionRunsCard orgId={orgId} canStart={editable} />}
      {can("investigation.read") && (
        <OrgLegalHolds orgId={orgId} canManage={editable} delayDays={p?.delay_days ?? DEFAULT_DELAY_DAYS} />
      )}
    </div>
  );
}
