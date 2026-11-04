"use client";

import { useState } from "react";

import { QueryError } from "@/components/query-error";
import { IntegrationCard } from "@/components/ti/integration-card";
import { TiSettingsCard } from "@/components/ti/ti-settings-card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useOrg } from "@/lib/org-context";
import { type IntegrationPage, visibleIntegrations } from "@/lib/ti";
import { useIntegrations } from "@/lib/use-ti";
import { useNow } from "@/lib/use-now";

const VERIFY_POLL_MS = 2_000;
const VERIFY_WAIT_MS = 60_000;

/** A queued key check: the `verified_at` seen when it was queued, and when. */
type Pending = { since: string | null; at: number };

function stillChecking(pending: Pending | undefined, verifiedAt: string | null, now: number): boolean {
  return pending !== undefined && pending.since === verifiedAt && now - pending.at < VERIFY_WAIT_MS;
}

/** Threat intel providers of the org (keys are write-only) and the TI settings. */
export default function IntegrationsPage() {
  const { orgId, can } = useOrg();
  const canManage = can("integrations.manage");
  const [pending, setPending] = useState<Record<string, Pending>>({});
  const anyPending = Object.keys(pending).length > 0;
  const now = useNow(anyPending, 1_000);

  const integrations = useIntegrations(orgId, (data: IntegrationPage | undefined) => {
    const t = Date.now();
    const waiting = (data?.items ?? []).some((i) => stillChecking(pending[i.name], i.verified_at, t));
    return waiting ? VERIFY_POLL_MS : false;
  });

  const items = visibleIntegrations(integrations.data?.items ?? []);

  return (
    <div className="flex flex-col gap-6">
      <Alert>
        <AlertTitle>What providers receive</AlertTitle>
        <AlertDescription>
          Enabled providers receive the indicators you enrich. Private IPs, internal names, URL query strings, emails
          (except MISP), file paths and registry keys are never sent. Keys are write-only: after saving, only the last
          four characters are shown.
        </AlertDescription>
      </Alert>
      {!canManage && (
        <p className="text-sm text-muted-foreground">
          Only owners and admins can store keys, enable providers or change these settings.
        </p>
      )}
      {integrations.data && !integrations.data.ti_enabled && (
        <Alert>
          <AlertTitle>Threat intelligence is turned off</AlertTitle>
          <AlertDescription>This deployment has threat intel disabled; providers cannot be used.</AlertDescription>
        </Alert>
      )}
      <TiSettingsCard orgId={orgId} canManage={canManage} />
      {integrations.isError && <QueryError error={integrations.error} onRetry={() => void integrations.refetch()} />}
      {integrations.isPending && <p className="text-sm text-muted-foreground">Loading providers…</p>}
      <div className="grid gap-4 xl:grid-cols-2">
        {items.map((integration) => (
          <IntegrationCard
            key={integration.name}
            orgId={orgId}
            integration={integration}
            canManage={canManage}
            checking={stillChecking(pending[integration.name], integration.verified_at, now)}
            onVerifyStarted={(since) =>
              setPending((current) => ({ ...current, [integration.name]: { since, at: Date.now() } }))
            }
          />
        ))}
      </div>
    </div>
  );
}
