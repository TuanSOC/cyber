"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { toast } from "sonner";

import { EnforceAcknowledgement } from "@/components/retention/enforce-acknowledgement";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { errorMessage } from "@/lib/api";
import { apiErrorText } from "@/lib/http-errors";
import {
  MAX_DAYS,
  RETENTION_FIELDS,
  RETENTION_FIELD_TEXT,
  type RetentionDraft,
  type RetentionField,
  type RetentionPolicy,
  type RetentionPolicyIn,
  addDays,
  checkDays,
  draftEquals,
  enforceState,
  formatDay,
  formatDays,
  loweredFields,
  loweringNotice,
  parseDays,
  pendingValue,
  policyBody,
  retentionKeys,
  putPolicy,
  targetValues,
} from "@/lib/retention";

/** One field of the form: "keep forever" or a number of days. */
export type FieldDraft = { forever: boolean; raw: string };
export type PolicyDraft = Record<RetentionField, FieldDraft>;

export function draftFromPolicy(policy: RetentionPolicy): PolicyDraft {
  const target = targetValues(policy);
  const out = {} as PolicyDraft;
  for (const field of RETENTION_FIELDS) {
    const value = target[field];
    out[field] = { forever: value === null, raw: value === null ? "" : String(value) };
  }
  return out;
}

/** The draft as values plus a reason per invalid field. */
export function draftValues(
  draft: PolicyDraft,
  floors: RetentionPolicy["floors"],
): { values: RetentionDraft; errors: Partial<Record<RetentionField, string>> } {
  const values = {} as RetentionDraft;
  const errors: Partial<Record<RetentionField, string>> = {};
  for (const field of RETENTION_FIELDS) {
    const { forever, raw } = draft[field];
    if (forever) {
      values[field] = null;
      continue;
    }
    const days = parseDays(raw);
    if (days === null) {
      errors[field] = "Enter a number of days, or choose keep forever.";
      values[field] = null;
      continue;
    }
    values[field] = days;
    const problem = Number.isNaN(days) ? "Whole days only." : checkDays(days, floors[field]);
    if (problem) errors[field] = problem;
  }
  return { values, errors };
}

/** One policy field: current, pending with its date, the floor, and the input (pure). */
export function PolicyFieldRow({
  field,
  policy,
  draft,
  error,
  editable,
  onChange,
}: {
  field: RetentionField;
  policy: RetentionPolicy;
  draft: FieldDraft;
  error?: string;
  editable: boolean;
  onChange: (next: FieldDraft) => void;
}) {
  const id = useId();
  const text = RETENTION_FIELD_TEXT[field];
  const pending = pendingValue(policy, field);
  const floor = policy.floors[field];
  return (
    <fieldset className="flex flex-col gap-2 rounded-lg border p-3" data-field={field}>
      <legend className="px-1 text-sm font-medium">{text.label}</legend>
      <p className="text-xs text-muted-foreground">{text.help}</p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
        <dt className="text-muted-foreground">Current</dt>
        <dd>{formatDays(policy[field])}</dd>
        {pending !== null && policy.effective_at ? (
          <>
            <dt className="text-muted-foreground">Pending</dt>
            <dd>
              {formatDays(pending)} <span className="text-muted-foreground">(takes effect on {formatDay(policy.effective_at)})</span>
            </dd>
          </>
        ) : null}
        <dt className="text-muted-foreground">Minimum</dt>
        <dd>{floor === null ? "none" : formatDays(floor)}</dd>
      </dl>
      {editable && (
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={draft.forever}
              onChange={(event) => onChange({ ...draft, forever: event.target.checked })}
            />
            Keep forever
          </label>
          <div className="flex items-center gap-2">
            <Input
              id={`${id}-days`}
              className="w-28"
              type="number"
              inputMode="numeric"
              min={floor ?? 1}
              max={MAX_DAYS}
              step={1}
              value={draft.raw}
              disabled={draft.forever}
              aria-label={`${text.label}: days`}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? `${id}-error` : undefined}
              onChange={(event) => onChange({ ...draft, raw: event.target.value })}
            />
            <span className="text-sm text-muted-foreground">days</span>
          </div>
        </div>
      )}
      {editable && error ? (
        <p id={`${id}-error`} className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}

/** The enforce switch and its state (pure). Off by default; on waits for the delay (RT1). */
export function EnforceSwitch({
  policy,
  editable,
  pending,
  onToggle,
}: {
  policy: RetentionPolicy;
  editable: boolean;
  pending: boolean;
  onToggle: (next: boolean) => void;
}) {
  const id = useId();
  const state = enforceState(policy);
  const checked = state !== "off";
  return (
    <div className="flex items-start gap-3 rounded-lg border p-3" data-enforce={state}>
      <input
        id={id}
        type="checkbox"
        role="switch"
        className="mt-1 size-4"
        checked={checked}
        aria-checked={checked}
        disabled={!editable || pending}
        aria-describedby={`${id}-help`}
        onChange={(event) => onToggle(event.target.checked)}
      />
      <div className="flex flex-col gap-1">
        <label htmlFor={id} className="flex items-center gap-2 text-sm font-medium">
          Enforce retention
          <Badge variant={state === "on" ? "destructive" : "outline"}>
            {state === "on" ? "on" : state === "pending" ? "pending" : "off (dry run)"}
          </Badge>
        </label>
        <p id={`${id}-help`} className="text-xs text-muted-foreground">
          {state === "off" &&
            "Off: scheduled runs only report what they would delete (dry runs). Nothing is deleted."}
          {state === "pending" &&
            `Turned on: enforcement begins on ${policy.enforce_effective_at ? formatDay(policy.enforce_effective_at) : "the end of the delay"}. Until then runs stay dry runs. Turning it off cancels it at once.`}
          {state === "on" &&
            "On: scheduled runs delete what the policy selects, except data under legal hold. Turning it off applies at once."}
        </p>
      </div>
    </div>
  );
}

type Confirm =
  | { kind: "lower"; body: RetentionPolicyIn; notice: string }
  | { kind: "ack"; body: RetentionPolicyIn; start: Date | null; note?: string; label: string };

/** The policy form (`org.update` edits, `org.read` views). Re-mount it when the policy changes. */
export function RetentionPolicyCard({
  orgId,
  orgName,
  policy,
  editable,
}: {
  orgId: string;
  orgName: string;
  policy: RetentionPolicy;
  editable: boolean;
}) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<PolicyDraft>(() => draftFromPolicy(policy));
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [typed, setTyped] = useState("");
  const state = enforceState(policy);
  const { values, errors } = draftValues(draft, policy.floors);
  const invalid = Object.keys(errors).length > 0;
  const changed = !draftEquals(values, targetValues(policy));

  const save = useMutation({
    mutationFn: (body: RetentionPolicyIn) => putPolicy(orgId, body),
    onSuccess: async (updated) => {
      setConfirm(null);
      setTyped("");
      queryClient.setQueryData(retentionKeys.policy(orgId), updated);
      await queryClient.invalidateQueries({ queryKey: retentionKeys.preview(orgId) });
      toast.success("Retention policy saved");
    },
    onError: (error) => toast.error(apiErrorText(error) ?? errorMessage(error)),
  });

  function submitValues() {
    if (invalid || !changed) return;
    // Newly lowered fields only: a value already pending keeps its own date.
    const target = targetValues(policy);
    const lowered = loweredFields(policy, values).filter((field) => values[field] !== target[field]);
    const now = Date.now();
    if (state !== "off") {
      // A PUT with enforce on needs the acknowledgement again (the API re-checks it).
      setConfirm({
        kind: "ack",
        body: policyBody(values, true, true),
        start: state === "pending" && policy.enforce_effective_at ? new Date(policy.enforce_effective_at) : null,
        note: lowered.length ? loweringNotice(lowered, policy.delay_days, now) : undefined,
        label: "Save values",
      });
    } else if (lowered.length) {
      setConfirm({ kind: "lower", body: policyBody(values, false), notice: loweringNotice(lowered, policy.delay_days, now) });
    } else {
      save.mutate(policyBody(values, false));
    }
  }

  function toggleEnforce(next: boolean) {
    const saved = targetValues(policy);
    if (!next) {
      save.mutate(policyBody(saved, false));
      return;
    }
    setTyped("");
    setConfirm({
      kind: "ack",
      body: policyBody(saved, true, true),
      start: addDays(Date.now(), policy.delay_days),
      label: "Turn on enforcement",
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Retention policy</CardTitle>
        <CardDescription>
          {editable
            ? `By default everything is kept forever. A lowered value, and turning enforcement on, take effect after the ${policy.delay_days}-day delay; a raised value applies at once.`
            : "Only owners and admins can change the retention policy."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            submitValues();
          }}
        >
          {RETENTION_FIELDS.map((field) => (
            <PolicyFieldRow
              key={field}
              field={field}
              policy={policy}
              draft={draft[field]}
              error={errors[field]}
              editable={editable}
              onChange={(next) => setDraft((current) => ({ ...current, [field]: next }))}
            />
          ))}
          {editable && (
            <div className="flex gap-2">
              <Button type="submit" disabled={invalid || !changed || save.isPending}>
                {save.isPending ? "Saving…" : "Save values"}
              </Button>
              {changed && (
                <Button type="button" variant="ghost" onClick={() => setDraft(draftFromPolicy(policy))}>
                  Reset
                </Button>
              )}
            </div>
          )}
        </form>
        <EnforceSwitch policy={policy} editable={editable} pending={save.isPending} onToggle={toggleEnforce} />
      </CardContent>
      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
          {confirm?.kind === "lower" && (
            <>
              <DialogHeader>
                <DialogTitle>Lower the retention period?</DialogTitle>
                <DialogDescription>{confirm.notice}</DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setConfirm(null)}>
                  Cancel
                </Button>
                <Button disabled={save.isPending} onClick={() => save.mutate(confirm.body)}>
                  Save lowered values
                </Button>
              </DialogFooter>
            </>
          )}
          {confirm?.kind === "ack" && (
            <>
              <DialogHeader>
                <DialogTitle>{state === "off" ? "Turn on retention enforcement?" : "Save values with enforcement on?"}</DialogTitle>
                <DialogDescription>This deletes data permanently. Read what is and is not deleted.</DialogDescription>
              </DialogHeader>
              <EnforceAcknowledgement
                orgName={orgName}
                typed={typed}
                onTypedChange={setTyped}
                enforcementStart={confirm.start}
                note={confirm.note}
                confirmLabel={confirm.label}
                pending={save.isPending}
                onConfirm={() => save.mutate(confirm.body)}
                onCancel={() => setConfirm(null)}
              />
            </>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
