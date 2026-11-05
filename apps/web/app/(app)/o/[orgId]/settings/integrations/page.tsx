"use client";

import { useState } from "react";

import { AiOrgSettingsCard } from "@/components/ai-settings/ai-org-settings-card";
import { AiProviderCard } from "@/components/ai-settings/ai-provider-card";
import { QueryError } from "@/components/query-error";
import { IntegrationCard } from "@/components/ti/integration-card";
import { TiSettingsCard } from "@/components/ti/ti-settings-card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { type AiProviderPage, visibleAiProviders } from "@/lib/ai-settings";
import { useOrg } from "@/lib/org-context";
import { type IntegrationPage, visibleIntegrations } from "@/lib/ti";
import { useAiProviders } from "@/lib/use-ai-settings";
import { useIntegrations } from "@/lib/use-ti";
import { useNow } from "@/lib/use-now";

const VERIFY_POLL_MS = 2_000;
const VERIFY_WAIT_MS = 60_000;

/** A queued key check: the `verified_at` seen when it was queued, and when. */
type Pending = { since: string | null; at: number };

function stillChecking(pending: Pending | undefined, verifiedAt: string | null, now: number): boolean {
  return pending !== undefined && pending.since === verifiedAt && now - pending.at < VERIFY_WAIT_MS;
}

/** Threat intel and AI providers of the org (keys are write-only) and their settings. */
export default function IntegrationsPage() {
  const { orgId, can } = useOrg();
  const canManage = can("integrations.manage");
  const [pending, setPending] = useState<Record<string, Pending>>({});
  const [aiPending, setAiPending] = useState<Record<string, Pending>>({});
  const anyPending = Object.keys(pending).length > 0 || Object.keys(aiPending).length > 0;
  const now = useNow(anyPending, 1_000);

  const integrations = useIntegrations(orgId, (data: IntegrationPage | undefined) => {
    const t = Date.now();
    const waiting = (data?.items ?? []).some((i) => stillChecking(pending[i.name], i.verified_at, t));
    return waiting ? VERIFY_POLL_MS : false;
  });
  const aiProviders = useAiProviders(orgId, (data: AiProviderPage | undefined) => {
    const t = Date.now();
    const waiting = (data?.items ?? []).some((p) => stillChecking(aiPending[p.name], p.verified_at, t));
    return waiting ? VERIFY_POLL_MS : false;
  });

  const items = visibleIntegrations(integrations.data?.items ?? []);
  const aiItems = visibleAiProviders(aiProviders.data?.items ?? []);

  return (
    <div className="flex flex-col gap-10">
      {!canManage && (
        <p className="text-sm text-muted-foreground">
          Only owners and admins can store keys, enable providers or change these settings.
        </p>
      )}

      <section className="flex flex-col gap-6" aria-labelledby="ti-providers-title">
        <h2 id="ti-providers-title" className="text-lg font-semibold">
          Threat intelligence providers
        </h2>
        <Alert>
          <AlertTitle>What providers receive</AlertTitle>
          <AlertDescription>
            Enabled providers receive the indicators you enrich. Private IPs, internal names, URL query strings, emails
            (except MISP), file paths and registry keys are never sent. Keys are write-only: after saving, only the last
            four characters are shown.
          </AlertDescription>
        </Alert>
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
      </section>

      <section className="flex flex-col gap-6" aria-labelledby="ai-analysis-title">
        <h2 id="ai-analysis-title" className="text-lg font-semibold">
          AI analysis
        </h2>
        <Alert>
          <AlertTitle>What AI providers receive</AlertTitle>
          <AlertDescription>
            AI analysis is off until an admin turns it on with the privacy acknowledgement. Each analysis sends evidence
            excerpts of the selected job or investigation to the chosen provider, with internal names pseudonymized by
            default. Keys are write-only: after saving, only the last four characters are shown.
          </AlertDescription>
        </Alert>
        {aiProviders.data && !aiProviders.data.platform_ai_enabled && (
          <Alert>
            <AlertTitle>AI analysis is turned off on this deployment</AlertTitle>
            <AlertDescription>An operator must set AI_ENABLED=true before any provider can be used.</AlertDescription>
          </Alert>
        )}
        <AiOrgSettingsCard orgId={orgId} canManage={canManage} providers={aiItems} />
        {aiProviders.isError && <QueryError error={aiProviders.error} onRetry={() => void aiProviders.refetch()} />}
        {aiProviders.isPending && <p className="text-sm text-muted-foreground">Loading AI providers…</p>}
        <div className="grid gap-4 xl:grid-cols-2">
          {aiItems.map((provider) => (
            <AiProviderCard
              key={provider.name}
              orgId={orgId}
              provider={provider}
              canManage={canManage}
              checking={stillChecking(aiPending[provider.name], provider.verified_at, now)}
              onVerifyStarted={(since) =>
                setAiPending((current) => ({ ...current, [provider.name]: { since, at: Date.now() } }))
              }
            />
          ))}
        </div>
      </section>
    </div>
  );
}
