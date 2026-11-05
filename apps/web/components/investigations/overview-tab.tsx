"use client";

import { RelatedCasesCard } from "@/components/correlation/related-cases-card";
import { CaseTlpCard } from "@/components/investigations/case-tlp-card";
import { CaseHoldCard } from "@/components/legal-holds/case-hold-card";
import { SharePolicyCard } from "@/components/investigations/share-policy-card";
import { StatusHistory } from "@/components/investigations/status-history";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Investigation, InvestigationUpdate } from "@/lib/case";
import { STATUS_LABELS } from "@/lib/format";
import type { Permission } from "@/lib/roles";

/** Overview tab: description, status with history, TLP and the share policy. */
export function OverviewTab({
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
  const archived = inv.status === "archived";
  const canWrite = can("investigation.write") && !archived;
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,24rem)]">
      <div className="flex min-w-0 flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Case</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className="text-sm">
              Status: <span className="font-medium">{STATUS_LABELS[inv.status]}</span>
              {archived ? <span className="ml-2 text-muted-foreground">(read-only)</span> : null}
            </p>
            {inv.description ? (
              <p className="max-w-3xl text-sm whitespace-pre-wrap text-muted-foreground">{inv.description}</p>
            ) : null}
            <StatusHistory orgId={orgId} investigationId={inv.id} />
          </CardContent>
        </Card>
        {/* M7 slot: related cases (phase 8). */}
        <RelatedCasesCard orgId={orgId} investigationId={inv.id} />
      </div>
      <div className="flex min-w-0 flex-col gap-6">
        {/* M7 slot: the case's legal hold (phase 9). */}
        <CaseHoldCard orgId={orgId} investigationId={inv.id} legalHold={inv.legal_hold} can={can} />
        <CaseTlpCard
          tlp={inv.tlp}
          canWrite={canWrite}
          canDowngrade={can("org.update")}
          pending={pending}
          onSave={(tlp, ack) => onUpdate(ack ? { tlp, acknowledge_tlp_downgrade: true } : { tlp })}
        />
        <SharePolicyCard
          flags={{ ai_excluded: inv.ai_excluded, ti_excluded: inv.ti_excluded }}
          policy={inv.share_policy}
          tlpRed={inv.tlp === "red"}
          canTurnOn={can("investigation.write")}
          canTurnOff={can("integrations.manage")}
          readOnly={archived}
          pending={pending}
          onChange={(next) => {
            const body: InvestigationUpdate = {};
            if (next.ai_excluded !== inv.ai_excluded) body.ai_excluded = next.ai_excluded;
            if (next.ti_excluded !== inv.ti_excluded) body.ti_excluded = next.ti_excluded;
            if (Object.keys(body).length > 0) onUpdate(body);
          }}
        />
      </div>
    </div>
  );
}
