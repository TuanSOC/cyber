"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { type FormEvent, useRef, useState } from "react";
import { toast } from "sonner";

import { When } from "@/components/analysis/result-parts";
import { ConfirmButton } from "@/components/confirm-button";
import { TermsAckForm } from "@/components/ti/terms-ack";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, api, ensureOk, unwrap } from "@/lib/api";
import {
  INTEGRATION_STATE_LABELS,
  type Integration,
  TI_IOC_TYPE_LABELS,
  effectiveLimits,
  integrationState,
  mispUrlHint,
  needsTermsAck,
  parseLimit,
  providerLabel,
  tiErrorMessage,
  verifyErrorText,
} from "@/lib/ti";
import { tiKeys } from "@/lib/use-ti";
import { cn } from "@/lib/utils";

type IntegrationBody = {
  enabled?: boolean;
  acknowledge_terms?: boolean;
  limits?: { per_minute?: number | null; per_day?: number | null };
};

/** Status badge: our configuration state (not a statement about any indicator). */
export function IntegrationStatusBadge({ integration }: { integration: Integration }) {
  const state = integrationState(integration);
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        state === "invalid" || state === "error" ? "border-destructive/40 text-destructive" : "border-border",
        state === "not_configured" && "text-muted-foreground",
      )}
    >
      {INTEGRATION_STATE_LABELS[state]}
      {(state === "invalid" || state === "error") && integration.last_error_code
        ? ` · ${integration.last_error_code}`
        : ""}
    </span>
  );
}

function limitText(value: number | null, unit: string): string {
  return value === null ? `no ${unit} cap` : `${value} / ${unit}`;
}

/**
 * One provider: status, key (shown only as ••••last4), verification, terms, limits and notes.
 * Edit controls render only with `integrations.manage` (the API enforces it regardless).
 */
export function IntegrationCard({
  orgId,
  integration: i,
  canManage,
  checking = false,
  onVerifyStarted,
}: {
  orgId: string;
  integration: Integration;
  canManage: boolean;
  /** A verification was queued and its answer is awaited. */
  checking?: boolean;
  onVerifyStarted?: (since: string | null) => void;
}) {
  const limits = effectiveLimits(i);
  const editable = canManage && i.available;
  return (
    <Card data-provider={i.name}>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">{providerLabel(i.name)}</CardTitle>
          <div className="flex items-center gap-2">
            {checking && (
              <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                <Loader2 className="size-3 animate-spin motion-reduce:animate-none" aria-hidden /> checking…
              </span>
            )}
            <IntegrationStatusBadge integration={i} />
          </div>
        </div>
        <CardDescription>
          {i.supported_types.map((t) => TI_IOC_TYPE_LABELS[t] ?? t).join(" · ")}
          {!i.available && " · not available on this deployment"}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 text-sm">
        <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1">
          <dt className="text-muted-foreground">Key</dt>
          <dd className="font-mono text-xs">{i.configured && i.key_last4 ? `••••${i.key_last4}` : "not stored"}</dd>
          <dt className="text-muted-foreground">Enabled</dt>
          <dd>{i.enabled ? "yes" : "no"}</dd>
          <dt className="text-muted-foreground">Last check</dt>
          <dd>
            <When iso={i.verified_at} />
          </dd>
          {i.last_error_code && (
            <>
              <dt className="text-muted-foreground">Last error</dt>
              <dd>
                <span className="font-mono text-xs">{i.last_error_code}</span>{" "}
                <span className="text-muted-foreground">{verifyErrorText(i.last_error_code)}</span>
              </dd>
            </>
          )}
          <dt className="text-muted-foreground">Terms</dt>
          <dd>
            {i.terms_ack_at ? (
              <>
                terms acknowledged on <When iso={i.terms_ack_at} />
              </>
            ) : (
              <span className="text-muted-foreground">not acknowledged yet</span>
            )}
          </dd>
          {i.needs_base_url && (
            <>
              <dt className="text-muted-foreground">Server URL</dt>
              <dd className="font-mono text-xs break-all">{i.base_url ?? "—"}</dd>
            </>
          )}
          <dt className="text-muted-foreground">Limits</dt>
          <dd>
            {limitText(limits.per_minute, "minute")} · {limitText(limits.per_day, "day")}
            <span className="text-muted-foreground">
              {" "}
              (maximum {limitText(i.ceilings.per_minute, "minute")} · {limitText(i.ceilings.per_day, "day")})
            </span>
          </dd>
        </dl>
        <div className="flex flex-col gap-1 text-xs text-muted-foreground">
          <p>{i.tos_note}</p>
          <p>{i.privacy_note}</p>
        </div>
        {editable && (
          <ManageControls orgId={orgId} integration={i} onVerifyStarted={onVerifyStarted ?? (() => undefined)} />
        )}
      </CardContent>
    </Card>
  );
}

function ManageControls({
  orgId,
  integration: i,
  onVerifyStarted,
}: {
  orgId: string;
  integration: Integration;
  onVerifyStarted: (since: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [ackOpen, setAckOpen] = useState(false);
  const [ackChecked, setAckChecked] = useState(false);
  const refresh = () => queryClient.invalidateQueries({ queryKey: tiKeys.integrations(orgId) });

  const update = useMutation({
    mutationFn: async (body: IntegrationBody) =>
      unwrap(
        await api.PUT("/api/v1/orgs/{org_id}/integrations/{provider}", {
          params: { path: { org_id: orgId, provider: i.name } },
          // `acknowledge_terms` is required by the generated type (it has a server default).
          body: { acknowledge_terms: false, ...body },
        }),
      ),
    onSuccess: async () => {
      await refresh();
    },
    onError: (error) => toast.error(tiErrorMessage(error)),
  });

  const verify = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/integrations/{provider}/verify", {
          params: { path: { org_id: orgId, provider: i.name } },
        }),
      ),
    onSuccess: () => {
      onVerifyStarted(i.verified_at);
      toast.success(`Checking the ${providerLabel(i.name)} key…`);
    },
    onError: (error) => toast.error(tiErrorMessage(error)),
  });

  const remove = useMutation({
    mutationFn: async () =>
      ensureOk(
        await api.DELETE("/api/v1/orgs/{org_id}/integrations/{provider}/key", {
          params: { path: { org_id: orgId, provider: i.name } },
        }),
      ),
    onSuccess: async () => {
      await refresh();
      toast.success(`${providerLabel(i.name)} key removed; the provider is disabled.`);
    },
    onError: (error) => toast.error(tiErrorMessage(error)),
  });

  const enable = () => {
    if (needsTermsAck(i)) {
      setAckChecked(false);
      setAckOpen(true);
      return;
    }
    update.mutate({ enabled: true }, { onSuccess: () => toast.success(`${providerLabel(i.name)} enabled`) });
  };

  return (
    <div className="flex flex-col gap-4 border-t pt-4">
      <div className="flex flex-wrap items-center gap-2">
        {i.enabled ? (
          <Button
            size="sm"
            variant="outline"
            disabled={update.isPending}
            onClick={() =>
              update.mutate({ enabled: false }, { onSuccess: () => toast.success(`${providerLabel(i.name)} disabled`) })
            }
          >
            Disable
          </Button>
        ) : (
          <Button size="sm" disabled={update.isPending || !i.configured} onClick={enable}>
            Enable
          </Button>
        )}
        {i.configured && (
          <Button size="sm" variant="outline" disabled={verify.isPending} onClick={() => verify.mutate()}>
            <RefreshCw className="size-4" aria-hidden /> Verify
          </Button>
        )}
        {i.configured && (
          <ConfirmButton
            size="sm"
            variant="outline"
            title={`Remove the ${providerLabel(i.name)} key?`}
            description="The stored key is deleted and the provider is disabled. Past results stay in the history."
            confirmLabel="Remove key"
            pending={remove.isPending}
            onConfirm={() => remove.mutate()}
          >
            <Trash2 className="size-4" aria-hidden /> Remove key
          </ConfirmButton>
        )}
        {!i.configured && <span className="text-xs text-muted-foreground">Store a key before enabling.</span>}
      </div>

      <KeyForm orgId={orgId} integration={i} onSaved={(since) => onVerifyStarted(since)} />
      <LimitsForm integration={i} pending={update.isPending} onSave={(limits) => update.mutate({ limits })} />

      <Dialog open={ackOpen} onOpenChange={setAckOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enable {providerLabel(i.name)}?</DialogTitle>
            <DialogDescription>Enabling a provider for the first time needs your acknowledgement.</DialogDescription>
          </DialogHeader>
          <TermsAckForm
            integration={i}
            checked={ackChecked}
            onCheckedChange={setAckChecked}
            pending={update.isPending}
            onCancel={() => setAckOpen(false)}
            onConfirm={() =>
              update.mutate(
                { enabled: true, acknowledge_terms: true },
                {
                  onSuccess: () => {
                    setAckOpen(false);
                    toast.success(`${providerLabel(i.name)} enabled`);
                  },
                },
              )
            }
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * Write-only key entry. The key lives only in the (uncontrolled) password input until submit:
 * never in React state, the query cache, a mutation's variables or storage. The input is
 * cleared right after the request, whatever its outcome, and is never pre-filled.
 */
export function KeyForm({
  orgId,
  integration: i,
  onSaved,
}: {
  orgId: string;
  integration: Pick<Integration, "name" | "configured" | "needs_base_url" | "base_url" | "verified_at">;
  onSaved: (since: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const keyRef = useRef<HTMLInputElement>(null);
  const [baseUrl, setBaseUrl] = useState(i.base_url ?? "");
  const [urlError, setUrlError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const inputId = `key-${i.name}`;
  const urlId = `url-${i.name}`;
  const urlChanged = i.needs_base_url && baseUrl.trim() !== (i.base_url ?? "");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = keyRef.current;
    if (!input) return;
    setFormError(null);
    setUrlError(null);
    if (i.needs_base_url) {
      const hint = mispUrlHint(baseUrl);
      if (hint) {
        setUrlError(hint);
        return;
      }
    }
    if (input.value.trim() === "") {
      setFormError(urlChanged ? "Changing the MISP URL requires entering the key again." : "Enter the API key.");
      return;
    }
    setPending(true);
    try {
      const result = await api.PUT("/api/v1/orgs/{org_id}/integrations/{provider}", {
        params: { path: { org_id: orgId, provider: i.name } },
        body: {
          api_key: input.value,
          acknowledge_terms: false,
          ...(i.needs_base_url ? { base_url: baseUrl.trim() } : {}),
        },
      });
      input.value = "";
      unwrap(result);
      await queryClient.invalidateQueries({ queryKey: tiKeys.integrations(orgId) });
      toast.success(i.configured ? "Key replaced; checking it…" : "Key stored; checking it…");
      onSaved(i.verified_at);
    } catch (error) {
      input.value = "";
      if (error instanceof ApiError && (error.code === "misp_url_invalid" || error.code === "misp_url_required")) {
        setUrlError(tiErrorMessage(error));
      } else {
        setFormError(tiErrorMessage(error));
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="flex flex-col gap-2" onSubmit={submit} autoComplete="off">
      {i.needs_base_url && (
        <div className="flex flex-col gap-1">
          <Label htmlFor={urlId}>MISP server URL</Label>
          <Input
            id={urlId}
            type="url"
            inputMode="url"
            placeholder="https://misp.example.org"
            maxLength={2048}
            value={baseUrl}
            aria-invalid={urlError ? true : undefined}
            onChange={(event) => setBaseUrl(event.target.value)}
          />
          {urlError && <span className="text-xs text-destructive">{urlError} (misp_url_invalid)</span>}
          {urlChanged && i.configured && (
            <span className="text-xs text-muted-foreground">Changing the URL requires entering the key again.</span>
          )}
        </div>
      )}
      <Label htmlFor={inputId}>{i.configured ? "Replace key" : "API key"}</Label>
      <div className="flex flex-wrap gap-2">
        <Input
          ref={keyRef}
          id={inputId}
          name={`ti-key-${i.name}`}
          type="password"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          maxLength={256}
          defaultValue=""
          placeholder={i.configured ? "New key (replaces the stored one)" : "Paste the provider API key"}
          className="max-w-sm font-mono"
          data-1p-ignore
          data-lpignore="true"
        />
        <Button type="submit" size="sm" variant="secondary" disabled={pending}>
          <KeyRound className="size-4" aria-hidden /> {i.configured ? "Replace key" : "Save key"}
        </Button>
      </div>
      {formError && <span className="text-xs text-destructive">{formError}</span>}
      <span className="text-xs text-muted-foreground">
        The key is encrypted for the enrichment worker and never shown again; only its last four characters are kept
        for display.
      </span>
    </form>
  );
}

function LimitsForm({
  integration: i,
  pending,
  onSave,
}: {
  integration: Integration;
  pending: boolean;
  onSave: (limits: { per_minute?: number | null; per_day?: number | null }) => void;
}) {
  const [perMinute, setPerMinute] = useState(i.limits?.per_minute != null ? String(i.limits.per_minute) : "");
  const [perDay, setPerDay] = useState(i.limits?.per_day != null ? String(i.limits.per_day) : "");
  const minute = parseLimit(perMinute, i.ceilings.per_minute);
  const day = parseLimit(perDay, i.ceilings.per_day);
  const invalid = Boolean(minute.error || day.error);
  const defaults = effectiveLimits({ limits: null, default_limits: i.default_limits });

  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (invalid) return;
        const limits: { per_minute?: number; per_day?: number } = {};
        if (minute.value !== null) limits.per_minute = minute.value;
        if (day.value !== null) limits.per_day = day.value;
        onSave(limits);
      }}
    >
      <span className="text-sm font-medium">Own limits (optional, lower than the maximum)</span>
      <div className="flex flex-wrap items-start gap-2">
        <div className="flex flex-col gap-1">
          <Label htmlFor={`lim-min-${i.name}`} className="text-xs text-muted-foreground">
            Per minute
          </Label>
          <Input
            id={`lim-min-${i.name}`}
            className="w-28"
            inputMode="numeric"
            placeholder={defaults.per_minute === null ? "—" : String(defaults.per_minute)}
            value={perMinute}
            aria-invalid={minute.error ? true : undefined}
            onChange={(event) => setPerMinute(event.target.value)}
          />
          {minute.error && <span className="text-xs text-destructive">{minute.error}</span>}
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor={`lim-day-${i.name}`} className="text-xs text-muted-foreground">
            Per day
          </Label>
          <Input
            id={`lim-day-${i.name}`}
            className="w-28"
            inputMode="numeric"
            placeholder={defaults.per_day === null ? "—" : String(defaults.per_day)}
            value={perDay}
            aria-invalid={day.error ? true : undefined}
            onChange={(event) => setPerDay(event.target.value)}
          />
          {day.error && <span className="text-xs text-destructive">{day.error}</span>}
        </div>
        <Button type="submit" size="sm" variant="outline" className="mt-5" disabled={pending || invalid}>
          Save limits
        </Button>
      </div>
    </form>
  );
}
