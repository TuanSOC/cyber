"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";
import { type KeyboardEvent, useState } from "react";
import { toast } from "sonner";

import { AiPrivacyAckForm } from "@/components/ai-settings/ai-privacy-ack";
import { AiUsageView } from "@/components/ai-settings/ai-usage";
import { When } from "@/components/analysis/result-parts";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  AI_MAX_LIST_ENTRIES,
  BUDGET_LABELS,
  BUDGET_ORDER,
  INCLUSION_LABELS,
  INCLUSION_ORDER,
  PSEUDONYMIZED_KINDS,
  type AiBudgetKey,
  type AiInclusions,
  type AiProvider,
  type AiSettings,
  type AiSettingsUpdate,
  addEntries,
  aiErrorMessage,
  fieldErrors,
  formatTokens,
  hasErrorCode,
  needsPrivacyAck,
  normalizeCidr,
  normalizeSuffix,
  parseBudget,
  usableAiProviders,
} from "@/lib/ai-settings";
import { api, unwrap } from "@/lib/api";
import { aiSettingsKeys, useAiSettings, useAiUsage, useMemberName } from "@/lib/use-ai-settings";

const PLATFORM_DEFAULT = "__platform__";

/** The org's AI analysis settings (admins edit, others read) and today's usage. */
export function AiOrgSettingsCard({
  orgId,
  canManage,
  providers,
}: {
  orgId: string;
  canManage: boolean;
  providers: readonly AiProvider[];
}) {
  const settings = useAiSettings(orgId);
  const usage = useAiUsage(orgId);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">AI analysis settings</CardTitle>
        <CardDescription>
          Opt-in per organization. When on, analysts can ask an AI provider to interpret the cited evidence of a job or
          investigation. CyberLab never acts on AI output.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6 text-sm">
        {settings.isPending ? (
          <p className="text-muted-foreground">Loading…</p>
        ) : settings.isError ? (
          <QueryError error={settings.error} onRetry={() => void settings.refetch()} />
        ) : (
          <AiOrgSettingsPanel orgId={orgId} settings={settings.data} canManage={canManage} providers={providers} />
        )}
        <section className="flex flex-col gap-2 border-t pt-4" aria-labelledby="ai-usage-title">
          <h3 id="ai-usage-title" className="font-medium">
            Usage today
          </h3>
          {usage.isPending ? (
            <p className="text-muted-foreground">Loading usage…</p>
          ) : usage.isError ? (
            <QueryError error={usage.error} onRetry={() => void usage.refetch()} />
          ) : (
            <AiUsageView usage={usage.data} providers={providers} />
          )}
        </section>
      </CardContent>
    </Card>
  );
}

function useSaveSettings(orgId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: AiSettingsUpdate) =>
      unwrap(await api.PUT("/api/v1/orgs/{org_id}/ai/settings", { params: { path: { org_id: orgId } }, body })),
    onSuccess: async (out) => {
      queryClient.setQueryData(aiSettingsKeys.settings(orgId), out);
      await queryClient.invalidateQueries({ queryKey: aiSettingsKeys.usage(orgId) });
    },
  });
}

function inclusionsOf(s: AiInclusions): AiInclusions {
  return {
    pseudonymize_internal: s.pseudonymize_internal,
    include_strings: s.include_strings,
    include_ti: s.include_ti,
    include_case_text: s.include_case_text,
  };
}

/** Settings body (read-only without `integrations.manage`). Exported for component tests. */
export function AiOrgSettingsPanel({
  orgId,
  settings: s,
  canManage,
  providers,
}: {
  orgId: string;
  settings: AiSettings;
  canManage: boolean;
  providers: readonly AiProvider[];
}) {
  const save = useSaveSettings(orgId);
  // A change that widens the disclosure, waiting for the privacy acknowledgement (RT22).
  const [pendingChange, setPendingChange] = useState<AiSettingsUpdate | null>(null);
  const [ackChecked, setAckChecked] = useState(false);
  const ackBy = useMemberName(orgId, s.privacy_ack_by);
  const editable = canManage;

  const apply = (change: AiSettingsUpdate, done: string) => {
    if (needsPrivacyAck(s, change)) {
      save.reset();
      setAckChecked(false);
      setPendingChange(change);
      return;
    }
    save.mutate(change, {
      onSuccess: () => toast.success(done),
      onError: (error) => {
        if (hasErrorCode(error, "privacy_not_acknowledged")) {
          setAckChecked(false);
          setPendingChange(change);
        }
      },
    });
  };

  const next: AiInclusions = { ...inclusionsOf(s), ...pick(pendingChange) };
  const turningOn = pendingChange?.ai_enabled === true;
  const sectionError = save.isError && pendingChange === null ? aiErrorMessage(save.error) : null;

  return (
    <div className="flex flex-col gap-6">
      <section className="flex flex-col gap-2" aria-labelledby="ai-enable-title">
        <h3 id="ai-enable-title" className="font-medium">
          AI analysis for this organization
        </h3>
        <p data-testid="ai-enabled-state">
          {s.ai_enabled ? "On: analysts can run AI analyses." : "Off: no evidence is sent to any AI provider."}
        </p>
        {!s.platform_ai_enabled && (
          <p className="text-muted-foreground">AI analysis is turned off on this deployment (AI_ENABLED=false).</p>
        )}
        <p className="text-muted-foreground">
          {s.privacy_ack_at ? (
            <>
              Privacy notice acknowledged on <When iso={s.privacy_ack_at} /> by {ackBy ?? "a member"}.
            </>
          ) : (
            "The privacy notice has not been acknowledged yet."
          )}
        </p>
        {editable && (
          <div className="flex flex-wrap gap-2">
            {s.ai_enabled ? (
              <Button
                size="sm"
                variant="outline"
                disabled={save.isPending}
                onClick={() => apply({ ai_enabled: false }, "AI analysis turned off")}
              >
                Turn off AI analysis
              </Button>
            ) : (
              <Button
                size="sm"
                disabled={save.isPending || !s.platform_ai_enabled}
                onClick={() => apply({ ai_enabled: true }, "AI analysis turned on")}
              >
                Turn on AI analysis…
              </Button>
            )}
          </div>
        )}
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="ai-inclusions-title">
        <h3 id="ai-inclusions-title" className="font-medium">
          What is sent
        </h3>
        <ul className="flex flex-col gap-2">
          {INCLUSION_ORDER.map((key) => (
            <li key={key} className="flex items-start gap-2">
              {editable ? (
                <input
                  id={`ai-${key}`}
                  type="checkbox"
                  className="mt-0.5 size-4 accent-primary"
                  checked={s[key]}
                  disabled={save.isPending}
                  onChange={(event) => {
                    const change: AiSettingsUpdate = {};
                    change[key] = event.target.checked;
                    apply(change, `${INCLUSION_LABELS[key].label}: ${event.target.checked ? "on" : "off"}`);
                  }}
                />
              ) : (
                <span className="w-8 shrink-0 text-xs font-medium" data-testid={`ai-${key}-value`}>
                  {s[key] ? "on" : "off"}
                </span>
              )}
              <label htmlFor={editable ? `ai-${key}` : undefined} className="flex flex-col">
                <span>{INCLUSION_LABELS[key].label}</span>
                <span className="text-xs text-muted-foreground">{INCLUSION_LABELS[key].hint}</span>
              </label>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">
          Turning strings or case text on, or pseudonymization off, sends more data and asks for the privacy
          acknowledgement again.
        </p>
        <DefaultProvider
          value={s.default_provider}
          providers={providers}
          editable={editable}
          pending={save.isPending}
          onChange={(provider) => apply({ default_provider: provider }, "Default provider saved")}
        />
        {sectionError && (
          <p className="text-xs text-destructive" role="alert">
            {sectionError}
          </p>
        )}
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="ai-lists-title">
        <h3 id="ai-lists-title" className="font-medium">
          Internal networks and domains
        </h3>
        <div className="text-xs text-muted-foreground">
          <p>Pseudonymization recognizes as internal:</p>
          <ul className="list-disc pl-5">
            {PSEUDONYMIZED_KINDS.map((kind) => (
              <li key={kind}>{kind}</li>
            ))}
          </ul>
          <p>Add your organization&apos;s address ranges and domain suffixes; other names are sent as they are.</p>
        </div>
        {editable ? (
          <ListsForm key={s.updated_at ?? "new"} orgId={orgId} settings={s} />
        ) : (
          <div className="flex flex-col gap-2">
            <ReadOnlyList label="Internal CIDRs" values={s.internal_cidrs} />
            <ReadOnlyList label="Internal domain suffixes" values={s.internal_suffixes} />
          </div>
        )}
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="ai-budgets-title">
        <h3 id="ai-budgets-title" className="font-medium">
          Budgets
        </h3>
        {editable ? (
          <BudgetsForm key={s.updated_at ?? "new"} orgId={orgId} settings={s} />
        ) : (
          <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1">
            {BUDGET_ORDER.map((key) => (
              <BudgetRow key={key} name={key} value={s[key]} ceiling={s.ceilings[key]} />
            ))}
          </dl>
        )}
      </section>

      <Dialog open={pendingChange !== null} onOpenChange={(open) => !open && setPendingChange(null)}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{turningOn ? "Turn on AI analysis?" : "Send more data to AI providers?"}</DialogTitle>
            <DialogDescription>
              {turningOn
                ? "Evidence excerpts leave CyberLab for the AI provider whenever an analysis runs."
                : "This change widens what leaves CyberLab, so it needs your acknowledgement again."}
            </DialogDescription>
          </DialogHeader>
          <AiPrivacyAckForm
            next={next}
            notice={s.privacy_notice}
            checked={ackChecked}
            onCheckedChange={setAckChecked}
            pending={save.isPending}
            confirmLabel={turningOn ? "Acknowledge and turn on" : "Acknowledge and save"}
            error={save.isError ? aiErrorMessage(save.error) : null}
            onCancel={() => setPendingChange(null)}
            onConfirm={() => {
              if (!pendingChange) return;
              save.mutate(
                { ...pendingChange, acknowledge_privacy: true },
                {
                  onSuccess: () => {
                    setPendingChange(null);
                    toast.success(turningOn ? "AI analysis turned on" : "Settings saved");
                  },
                },
              );
            }}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

function pick(change: AiSettingsUpdate | null): Partial<AiInclusions> {
  const out: Partial<AiInclusions> = {};
  if (!change) return out;
  for (const key of INCLUSION_ORDER) {
    const value = change[key];
    if (typeof value === "boolean") out[key] = value;
  }
  return out;
}

function DefaultProvider({
  value,
  providers,
  editable,
  pending,
  onChange,
}: {
  value: AiSettings["default_provider"];
  providers: readonly AiProvider[];
  editable: boolean;
  pending: boolean;
  onChange: (provider: AiSettings["default_provider"]) => void;
}) {
  const usable = usableAiProviders(providers);
  const label = (name: string | null) =>
    name === null ? "Platform default" : (providers.find((p) => p.name === name)?.label ?? name);
  if (!editable) {
    return (
      <p className="text-muted-foreground">
        Default provider for new analyses: <span className="text-foreground">{label(value)}</span>
      </p>
    );
  }
  const options = usable.map((p) => p.name).filter((name) => name !== value);
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor="ai-default-provider">Default provider for new analyses</Label>
      <Select
        value={value ?? PLATFORM_DEFAULT}
        disabled={pending}
        onValueChange={(next) => onChange(next === PLATFORM_DEFAULT ? null : (next as AiProvider["name"]))}
      >
        <SelectTrigger id="ai-default-provider" className="w-64">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={PLATFORM_DEFAULT}>Platform default</SelectItem>
          {value !== null && <SelectItem value={value}>{label(value)}</SelectItem>}
          {options.map((name) => (
            <SelectItem key={name} value={name}>
              {label(name)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {usable.length === 0 && (
        <span className="text-xs text-muted-foreground">Enable a provider below before choosing a default.</span>
      )}
    </div>
  );
}

function ReadOnlyList({ label, values }: { label: string; values: readonly string[] }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-muted-foreground">{label}</span>
      {values.length === 0 ? (
        <span className="text-xs text-muted-foreground">none</span>
      ) : (
        <ul className="flex flex-wrap gap-1">
          {values.map((v) => (
            <li key={v} className="rounded border px-1.5 font-mono text-xs">
              {v}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ListsForm({ orgId, settings: s }: { orgId: string; settings: AiSettings }) {
  const save = useSaveSettings(orgId);
  const [cidrs, setCidrs] = useState<string[]>(s.internal_cidrs);
  const [suffixes, setSuffixes] = useState<string[]>(s.internal_suffixes);
  const changed =
    cidrs.join("\n") !== s.internal_cidrs.join("\n") || suffixes.join("\n") !== s.internal_suffixes.join("\n");
  const cidrErrors = fieldErrors(save.error, "internal_cidrs");
  const suffixErrors = fieldErrors(save.error, "internal_suffixes");
  const generalError =
    save.isError && cidrErrors.length + suffixErrors.length === 0 ? aiErrorMessage(save.error) : null;

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(
          { internal_cidrs: cidrs, internal_suffixes: suffixes },
          { onSuccess: () => toast.success("Internal networks and domains saved") },
        );
      }}
    >
      <TagInput
        id="ai-cidrs"
        label="Internal CIDRs"
        placeholder="10.20.0.0/16, 2001:db8::/32"
        values={cidrs}
        onChange={setCidrs}
        normalize={normalizeCidr}
        serverErrors={cidrErrors}
      />
      <TagInput
        id="ai-suffixes"
        label="Internal domain suffixes"
        placeholder="corp.example.org"
        values={suffixes}
        onChange={setSuffixes}
        normalize={normalizeSuffix}
        serverErrors={suffixErrors}
      />
      {generalError && (
        <span className="text-xs text-destructive" role="alert">
          {generalError}
        </span>
      )}
      <Button type="submit" size="sm" variant="outline" className="self-start" disabled={save.isPending || !changed}>
        Save networks and domains
      </Button>
    </form>
  );
}

/** A list of validated entries: type or paste (comma / space / newline separated), Enter or Add. */
export function TagInput({
  id,
  label,
  placeholder,
  values,
  onChange,
  normalize,
  serverErrors = [],
}: {
  id: string;
  label: string;
  placeholder: string;
  values: readonly string[];
  onChange: (values: string[]) => void;
  normalize: (raw: string) => { value: string } | { error: string };
  serverErrors?: readonly string[];
}) {
  const [text, setText] = useState("");
  const [errors, setErrors] = useState<string[]>([]);
  const add = () => {
    const result = addEntries(values, text, normalize);
    setErrors(result.errors);
    if (result.list.length !== values.length) onChange(result.list);
    if (result.errors.length === 0) setText("");
  };
  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      add();
    }
  };
  const shown = [...errors, ...serverErrors];
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor={id}>
        {label}{" "}
        <span className="font-normal text-muted-foreground">
          ({values.length}/{AI_MAX_LIST_ENTRIES})
        </span>
      </Label>
      {values.length > 0 && (
        <ul className="flex flex-wrap gap-1" aria-label={label}>
          {values.map((v) => (
            <li key={v} className="inline-flex items-center gap-1 rounded border py-0.5 pr-0.5 pl-1.5 font-mono text-xs">
              {v}
              <button
                type="button"
                className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                aria-label={`Remove ${v}`}
                onClick={() => onChange(values.filter((x) => x !== v))}
              >
                <X className="size-3" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap gap-2">
        <Input
          id={id}
          className="max-w-sm font-mono text-xs"
          placeholder={placeholder}
          value={text}
          maxLength={4096}
          aria-invalid={shown.length > 0 ? true : undefined}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={onKeyDown}
        />
        <Button type="button" size="sm" variant="outline" disabled={text.trim() === ""} onClick={add}>
          Add
        </Button>
      </div>
      {shown.map((error, index) => (
        <span key={`${index}-${error}`} className="text-xs text-destructive">
          {error}
        </span>
      ))}
    </div>
  );
}

function BudgetRow({ name, value, ceiling }: { name: AiBudgetKey; value: number; ceiling: number }) {
  return (
    <>
      <dt className="text-muted-foreground">{BUDGET_LABELS[name].label}</dt>
      <dd>
        {formatTokens(value)} tokens <span className="text-muted-foreground">(maximum {formatTokens(ceiling)})</span>
      </dd>
    </>
  );
}

/** Budgets within the operator ceilings; `budget_above_ceiling` from the API is shown inline. */
export function BudgetsForm({ orgId, settings: s }: { orgId: string; settings: AiSettings }) {
  const save = useSaveSettings(orgId);
  const [text, setText] = useState<Record<AiBudgetKey, string>>({
    daily_token_budget: String(s.daily_token_budget),
    run_token_cap: String(s.run_token_cap),
    incident_token_cap: String(s.incident_token_cap),
  });
  const parsed = Object.fromEntries(
    BUDGET_ORDER.map((key) => [key, parseBudget(text[key], s.ceilings[key])]),
  ) as Record<AiBudgetKey, ReturnType<typeof parseBudget>>;
  const invalid = BUDGET_ORDER.some((key) => parsed[key].error !== null);
  const serverError = save.isError
    ? hasErrorCode(save.error, "budget_above_ceiling")
      ? "A budget is above the operator ceiling (budget_above_ceiling)."
      : aiErrorMessage(save.error)
    : null;

  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (invalid) return;
        const body: AiSettingsUpdate = {};
        for (const key of BUDGET_ORDER) {
          const value = parsed[key].value;
          if (value !== null && value !== s[key]) body[key] = value;
        }
        if (Object.keys(body).length === 0) return;
        save.mutate(body, { onSuccess: () => toast.success("Budgets saved") });
      }}
    >
      <div className="flex flex-wrap items-start gap-3">
        {BUDGET_ORDER.map((key) => (
          <div key={key} className="flex flex-col gap-1">
            <Label htmlFor={`ai-${key}`} className="text-xs text-muted-foreground">
              {BUDGET_LABELS[key].label}
            </Label>
            <Input
              id={`ai-${key}`}
              className="w-40 tabular-nums"
              inputMode="numeric"
              value={text[key]}
              aria-invalid={parsed[key].error ? true : undefined}
              onChange={(event) => setText((current) => ({ ...current, [key]: event.target.value }))}
            />
            <span className="text-xs text-muted-foreground">
              maximum {formatTokens(s.ceilings[key])} · {BUDGET_LABELS[key].hint}
            </span>
            {parsed[key].error && <span className="text-xs text-destructive">{parsed[key].error}</span>}
          </div>
        ))}
      </div>
      {serverError && (
        <span className="text-xs text-destructive" role="alert">
          {serverError}
        </span>
      )}
      <Button type="submit" size="sm" variant="outline" className="self-start" disabled={save.isPending || invalid}>
        Save budgets
      </Button>
    </form>
  );
}
