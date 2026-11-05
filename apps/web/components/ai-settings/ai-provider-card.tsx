"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { type FormEvent, useRef, useState } from "react";
import { toast } from "sonner";

import { type AiAckState, AiTermsAckForm } from "@/components/ai-settings/ai-terms-ack";
import { When } from "@/components/analysis/result-parts";
import { ConfirmButton } from "@/components/confirm-button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  AI_PROVIDER_STATE_LABELS,
  type AiProvider,
  type AiProviderUpdateBody,
  aiErrorMessage,
  aiKeyErrorMessage,
  aiProviderState,
  aiVerifyErrorText,
  canEnable,
  effectiveModel,
  modelOptionLabel,
  needsPaidTierAck,
  needsTermsAck,
  unavailableText,
} from "@/lib/ai-settings";
import { api, ensureOk, unwrap } from "@/lib/api";
import { aiSettingsKeys, storeAiKey } from "@/lib/use-ai-settings";
import { cn } from "@/lib/utils";

/** Status badge: our configuration state of the key (not a statement about any evidence). */
export function AiProviderStatusBadge({
  provider,
}: {
  provider: Pick<AiProvider, "configured" | "platform_key" | "verify_status" | "last_error_code">;
}) {
  const state = aiProviderState(provider);
  const failed = state === "invalid" || state === "error";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        failed ? "border-destructive/40 text-destructive" : "border-border",
        state === "not_configured" && "text-muted-foreground",
      )}
    >
      {AI_PROVIDER_STATE_LABELS[state]}
      {failed && provider.last_error_code ? ` · ${provider.last_error_code}` : ""}
    </span>
  );
}

function keyText(p: AiProvider): string {
  if (p.configured) return p.key_last4 ? `configured · ••••${p.key_last4}` : "configured";
  return p.platform_key ? "platform dev key" : "not stored";
}

/**
 * One AI provider: status, key (shown only as configured · ••••last4), model, verification,
 * terms and notes. Edit controls render only with `integrations.manage` and when the provider
 * is available on this deployment (the API enforces both regardless).
 */
export function AiProviderCard({
  orgId,
  provider: p,
  canManage,
  checking = false,
  onVerifyStarted,
}: {
  orgId: string;
  provider: AiProvider;
  canManage: boolean;
  /** A verification was queued and its answer is awaited. */
  checking?: boolean;
  onVerifyStarted?: (since: string | null) => void;
}) {
  const model = effectiveModel(p);
  const editable = canManage && p.available;
  return (
    <Card data-ai-provider={p.name}>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">{p.label}</CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            {checking && (
              <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                <Loader2 className="size-3 animate-spin motion-reduce:animate-none" aria-hidden /> checking…
              </span>
            )}
            {p.platform_key && (
              <span className="inline-flex items-center rounded-md border border-dashed px-2 py-0.5 text-xs whitespace-nowrap">
                {p.configured ? "Platform dev key available" : "Platform dev key in use"}
              </span>
            )}
            <AiProviderStatusBadge provider={p} />
          </div>
        </div>
        <CardDescription>
          AI analysis provider{!p.available && " · not available on this deployment"}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 text-sm">
        {!p.available && (
          <Alert variant={p.unavailable_reason === "gemini_billing_required" ? "destructive" : "default"}>
            <AlertTriangle aria-hidden />
            <AlertTitle>Unavailable</AlertTitle>
            <AlertDescription>{unavailableText(p.unavailable_reason)}</AlertDescription>
          </Alert>
        )}
        <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1">
          <dt className="text-muted-foreground">Key</dt>
          <dd className="font-mono text-xs">{keyText(p)}</dd>
          <dt className="text-muted-foreground">Enabled</dt>
          <dd>{p.enabled ? "yes" : "no"}</dd>
          <dt className="text-muted-foreground">Model</dt>
          <dd>{model ? modelOptionLabel(model) : (p.model ?? p.default_model)}</dd>
          <dt className="text-muted-foreground">Requests</dt>
          <dd>
            {(p.limits?.per_minute ?? p.default_limits.per_minute).toLocaleString("en-US")} / minute{" "}
            <span className="text-muted-foreground">
              (maximum {p.ceilings.per_minute.toLocaleString("en-US")}
              {p.limits ? "; own limit" : ""})
            </span>
          </dd>
          <dt className="text-muted-foreground">Last check</dt>
          <dd>
            <When iso={p.verified_at} />
          </dd>
          {p.last_error_code && (
            <>
              <dt className="text-muted-foreground">Last error</dt>
              <dd>
                <span className="font-mono text-xs">{p.last_error_code}</span>{" "}
                <span className="text-muted-foreground">{aiVerifyErrorText(p.last_error_code)}</span>
              </dd>
            </>
          )}
          <dt className="text-muted-foreground">Terms</dt>
          <dd>
            {p.terms_ack_at ? (
              <>
                acknowledged on <When iso={p.terms_ack_at} />
              </>
            ) : (
              <span className="text-muted-foreground">not acknowledged yet</span>
            )}
          </dd>
          {p.requires_paid_tier_ack && (
            <>
              <dt className="text-muted-foreground">Paid tier</dt>
              <dd>
                {p.paid_tier_ack_at ? (
                  <>
                    attested on <When iso={p.paid_tier_ack_at} />
                  </>
                ) : (
                  <span className="text-muted-foreground">not attested yet</span>
                )}
              </dd>
            </>
          )}
        </dl>
        <div className="flex flex-col gap-1 text-xs text-muted-foreground">
          <p>{p.tos_note}</p>
          <p>{p.privacy_note}</p>
          <p>Prices ({p.price_version}) are estimates; providers change them.</p>
        </div>
        {editable && (
          <ManageControls orgId={orgId} provider={p} onVerifyStarted={onVerifyStarted ?? (() => undefined)} />
        )}
      </CardContent>
    </Card>
  );
}

function ManageControls({
  orgId,
  provider: p,
  onVerifyStarted,
}: {
  orgId: string;
  provider: AiProvider;
  onVerifyStarted: (since: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [ackOpen, setAckOpen] = useState(false);
  const [ack, setAck] = useState<AiAckState>({ terms: false, paidTier: false });
  const refresh = () => queryClient.invalidateQueries({ queryKey: aiSettingsKeys.providers(orgId) });
  const path = { org_id: orgId, provider: p.name };

  // Bodies never carry a key (the key form sends it outside any mutation).
  const update = useMutation({
    mutationFn: async (body: AiProviderUpdateBody) =>
      unwrap(await api.PUT("/api/v1/orgs/{org_id}/ai/providers/{provider}", { params: { path }, body })),
    onSuccess: async () => {
      await refresh();
    },
  });

  const verify = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/api/v1/orgs/{org_id}/ai/providers/{provider}/verify", { params: { path } })),
    onSuccess: () => {
      onVerifyStarted(p.verified_at);
      toast.success(`Checking the ${p.label} key…`);
    },
    onError: (error) => toast.error(aiErrorMessage(error)),
  });

  const remove = useMutation({
    mutationFn: async () =>
      ensureOk(await api.DELETE("/api/v1/orgs/{org_id}/ai/providers/{provider}/key", { params: { path } })),
    onSuccess: async () => {
      await refresh();
      toast.success(`${p.label} key removed; the provider is disabled.`);
    },
    onError: (error) => toast.error(aiErrorMessage(error)),
  });

  const enable = () => {
    if (needsTermsAck(p) || needsPaidTierAck(p)) {
      update.reset();
      setAck({ terms: false, paidTier: false });
      setAckOpen(true);
      return;
    }
    update.mutate(
      { enabled: true },
      {
        onSuccess: () => toast.success(`${p.label} enabled`),
        onError: (error) => toast.error(aiErrorMessage(error)),
      },
    );
  };

  const models = p.models;
  const currentModel = p.model ?? p.default_model;

  return (
    <div className="flex flex-col gap-4 border-t pt-4">
      <div className="flex flex-wrap items-center gap-2">
        {p.enabled ? (
          <Button
            size="sm"
            variant="outline"
            disabled={update.isPending}
            onClick={() =>
              update.mutate(
                { enabled: false },
                {
                  onSuccess: () => toast.success(`${p.label} disabled`),
                  onError: (error) => toast.error(aiErrorMessage(error)),
                },
              )
            }
          >
            Disable
          </Button>
        ) : (
          <Button size="sm" disabled={update.isPending || !canEnable(p)} onClick={enable}>
            Enable
          </Button>
        )}
        {p.configured && (
          <Button size="sm" variant="outline" disabled={verify.isPending} onClick={() => verify.mutate()}>
            <RefreshCw className="size-4" aria-hidden /> Verify
          </Button>
        )}
        {p.configured && (
          <ConfirmButton
            size="sm"
            variant="outline"
            title={`Remove the ${p.label} key?`}
            description="The stored key is deleted and the provider is disabled. Past analyses stay in the history."
            confirmLabel="Remove key"
            pending={remove.isPending}
            onConfirm={() => remove.mutate()}
          >
            <Trash2 className="size-4" aria-hidden /> Remove key
          </ConfirmButton>
        )}
        {!canEnable(p) && <span className="text-xs text-muted-foreground">Store a key before enabling.</span>}
      </div>

      <div className="flex flex-col gap-1">
        <Label htmlFor={`ai-model-${p.name}`}>Model</Label>
        <Select
          value={currentModel}
          disabled={update.isPending}
          onValueChange={(model) =>
            update.mutate(
              { model },
              {
                onSuccess: () => toast.success(`${p.label} model saved`),
                onError: (error) => toast.error(aiErrorMessage(error)),
              },
            )
          }
        >
          <SelectTrigger id={`ai-model-${p.name}`} className="w-full max-w-md" aria-label={`${p.label} model`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {models.map((m) => (
              <SelectItem key={m.id} value={m.id}>
                {modelOptionLabel(m)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground">
          Only models in the allowed list can be chosen; &quot;unverified&quot; ids are not yet confirmed by the
          provider&apos;s model list.
        </span>
      </div>

      <AiLimitForm
        provider={p}
        pending={update.isPending}
        onSave={(limits) =>
          update.mutate(
            { limits },
            {
              onSuccess: () => toast.success(`${p.label} request limit saved`),
              onError: (error) => toast.error(aiErrorMessage(error)),
            },
          )
        }
      />

      <AiKeyForm
        orgId={orgId}
        provider={p}
        onSaved={(verifyQueued) => {
          if (verifyQueued) onVerifyStarted(p.verified_at);
        }}
      />

      <Dialog open={ackOpen} onOpenChange={setAckOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enable {p.label}?</DialogTitle>
            <DialogDescription>Enabling this provider for the first time needs your acknowledgement.</DialogDescription>
          </DialogHeader>
          <AiTermsAckForm
            provider={p}
            ack={ack}
            onAckChange={setAck}
            pending={update.isPending}
            error={update.isError ? aiErrorMessage(update.error) : null}
            onCancel={() => setAckOpen(false)}
            onConfirm={() =>
              update.mutate(
                {
                  enabled: true,
                  acknowledge_terms: ack.terms || !needsTermsAck(p),
                  ...(needsPaidTierAck(p) ? { acknowledge_paid_tier: ack.paidTier } : {}),
                },
                {
                  onSuccess: () => {
                    setAckOpen(false);
                    toast.success(`${p.label} enabled`);
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

/** The org's own per-minute request limit (empty: the provider default), at most the maximum. */
function AiLimitForm({
  provider: p,
  pending,
  onSave,
}: {
  provider: AiProvider;
  pending: boolean;
  onSave: (limits: { per_minute?: number }) => void;
}) {
  const [value, setValue] = useState(p.limits?.per_minute != null ? String(p.limits.per_minute) : "");
  const text = value.trim();
  const parsed = text === "" ? null : Number(text);
  const error =
    parsed !== null && (!Number.isInteger(parsed) || parsed < 1)
      ? "A whole number of at least 1."
      : parsed !== null && parsed > p.ceilings.per_minute
        ? `At most ${p.ceilings.per_minute.toLocaleString("en-US")}.`
        : null;
  const inputId = `ai-limit-${p.name}`;
  return (
    <form
      className="flex flex-col gap-1"
      onSubmit={(event) => {
        event.preventDefault();
        if (error) return;
        onSave(parsed === null ? {} : { per_minute: parsed });
      }}
    >
      <Label htmlFor={inputId}>Requests per minute (optional, own limit)</Label>
      <div className="flex flex-wrap items-start gap-2">
        <Input
          id={inputId}
          className="w-28"
          inputMode="numeric"
          placeholder={String(p.default_limits.per_minute)}
          value={value}
          aria-invalid={error ? true : undefined}
          onChange={(event) => setValue(event.target.value)}
        />
        <Button type="submit" size="sm" variant="outline" disabled={pending || Boolean(error)}>
          Save limit
        </Button>
      </div>
      {error && <span className="text-xs text-destructive">{error}</span>}
    </form>
  );
}

/**
 * Write-only key entry. The key lives only in the (uncontrolled) password input until submit:
 * never in React state, the query cache, a mutation's variables, toasts or storage. The input
 * is cleared right after the request, whatever its outcome, and is never pre-filled.
 */
export function AiKeyForm({
  orgId,
  provider: p,
  onSaved,
}: {
  orgId: string;
  provider: Pick<AiProvider, "name" | "configured">;
  onSaved: (verifyQueued: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const keyRef = useRef<HTMLInputElement>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const inputId = `ai-key-${p.name}`;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = keyRef.current;
    if (!input) return;
    setFormError(null);
    if (input.value.trim() === "") {
      setFormError("Enter the API key.");
      return;
    }
    setPending(true);
    try {
      const { verifyQueued } = await storeAiKey({ orgId, provider: p.name, input, queryClient });
      toast.success(
        `${p.configured ? "Key replaced" : "Key stored"}${verifyQueued ? "; checking it…" : "; use Verify to check it."}`,
      );
      onSaved(verifyQueued);
    } catch (error) {
      input.value = "";
      setFormError(aiKeyErrorMessage(error));
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="flex flex-col gap-2" onSubmit={submit} autoComplete="off">
      <Label htmlFor={inputId}>{p.configured ? "Replace key" : "API key"}</Label>
      <div className="flex flex-wrap gap-2">
        <Input
          ref={keyRef}
          id={inputId}
          name={`ai-key-${p.name}`}
          type="password"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          maxLength={256}
          defaultValue=""
          placeholder={p.configured ? "New key (replaces the stored one)" : "Paste the provider API key"}
          className="max-w-sm font-mono"
          data-1p-ignore
          data-lpignore="true"
        />
        <Button type="submit" size="sm" variant="secondary" disabled={pending}>
          <KeyRound className="size-4" aria-hidden /> {p.configured ? "Replace key" : "Save key"}
        </Button>
      </div>
      {formError && (
        <span className="text-xs text-destructive" role="alert">
          {formError}
        </span>
      )}
      <span className="text-xs text-muted-foreground">
        The key is encrypted for the analyst worker and never shown again; only its last four characters are kept for
        display.
      </span>
    </form>
  );
}
