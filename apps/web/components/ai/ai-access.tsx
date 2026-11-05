"use client";

import Link from "next/link";

import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { AiProvider, AiProviderName } from "@/lib/ai";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useAiProviders, useAiSettings } from "@/lib/use-ai";

/**
 * What the current member may do with AI here: viewers read outputs but never start runs
 * (no `evidence.write`); when the org has AI off, run controls are replaced by a notice.
 */
export function useAiAccess(orgId: string) {
  const { can } = useOrg();
  const settings = useAiSettings(orgId);
  const data = settings.data;
  const enabled = data ? data.ai_enabled && data.platform_ai_enabled : undefined;
  return {
    settings,
    enabled,
    canRun: can("evidence.write"),
    canManage: can("integrations.manage"),
    platformOff: data ? !data.platform_ai_enabled : false,
  };
}

export function AiOffNotice({
  orgId,
  canManage,
  platformOff = false,
}: {
  orgId: string;
  canManage: boolean;
  platformOff?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-md border px-3 py-2 text-sm">
      <span className="font-medium">AI is off for this organization</span>
      <span className="text-xs text-muted-foreground">
        {platformOff
          ? "AI analysis is not enabled on this CyberLab deployment."
          : canManage
            ? "An admin turns it on, with the privacy acknowledgement and a provider, under Integrations."
            : "An admin of the organization can turn it on under Integrations."}
      </span>
      {canManage && !platformOff && (
        <Link
          href={orgPath(orgId, "settings/integrations")}
          className="self-start text-xs text-primary underline-offset-4 hover:underline"
        >
          Open Integrations
        </Link>
      )}
    </div>
  );
}

export function NoRunPermissionNote() {
  return <p className="text-xs text-muted-foreground">Viewers can read AI analyses but cannot start them.</p>;
}

export type ProviderChoice = { provider?: AiProviderName; model?: string };

const DEFAULT = "default";

function usable(providers: readonly AiProvider[] | undefined): AiProvider[] {
  return (providers ?? []).filter((p) => p.enabled && p.available);
}

/** Provider and model: the org default, or an override among the enabled providers. */
export function ProviderOverride({
  orgId,
  value,
  onChange,
  defaultProvider,
}: {
  orgId: string;
  value: ProviderChoice;
  onChange: (value: ProviderChoice) => void;
  defaultProvider: AiProviderName | null | undefined;
}) {
  const providers = useAiProviders(orgId);
  const options = usable(providers.data?.items);
  const current = options.find((p) => p.name === value.provider);
  const fallback = options.find((p) => p.name === defaultProvider);
  const defaultLabel = fallback
    ? `Org default (${fallback.label} · ${fallback.model ?? fallback.default_model})`
    : "Org default";

  if (options.length === 0) {
    return providers.isSuccess ? (
      <p className="text-xs text-muted-foreground">No AI provider is enabled for this organization.</p>
    ) : null;
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Label className="text-xs text-muted-foreground">Provider</Label>
      <Select
        value={value.provider ?? DEFAULT}
        onValueChange={(next) => onChange(next === DEFAULT ? {} : { provider: next as AiProviderName })}
      >
        <SelectTrigger className="h-7 w-64 text-xs" aria-label="AI provider">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={DEFAULT}>{defaultLabel}</SelectItem>
          {options.map((p) => (
            <SelectItem key={p.name} value={p.name}>
              {p.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {current && (
        <Select
          value={value.model ?? DEFAULT}
          onValueChange={(next) => onChange({ provider: current.name, model: next === DEFAULT ? undefined : next })}
        >
          <SelectTrigger className="h-7 w-64 text-xs" aria-label="AI model">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={DEFAULT}>Configured model ({current.model ?? current.default_model})</SelectItem>
            {current.models.map((m) => (
              <SelectItem key={m.id} value={m.id}>
                {m.label}
                {m.verified ? "" : " (unverified)"}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  );
}
