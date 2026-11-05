"use client";

import { useId, useState } from "react";

import { Counter } from "@/components/reports/builder-fields";
import { BudgetTable, SectionCountsTable } from "@/components/reports/preview-panel";
import { TlpBadge } from "@/components/tlp/tlp-badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { errorMessage } from "@/lib/api";
import { vis } from "@/lib/report-format";
import {
  CHANGE_NOTE_MAX_CHARS,
  EXTERNAL_REVIEW_ACK,
  EXTERNAL_REVIEW_WARNING,
  PROFILE_TEXT,
  type ReportFinalize,
  type ReportProfile,
  type ReportVersion,
  type SectionCount,
  hasCode,
  reportErrorText,
  sectionCountsOf,
  sectionUnitsOf,
} from "@/lib/reports";
import { TLP_LABELS, type Tlp, isDowngrade } from "@/lib/tlp";

export type FinalizeOptions = Omit<ReportFinalize, "revision">;

export type FinalizeSummary = {
  tlp: Tlp;
  caseTlp: Tlp | null;
  profile: ReportProfile;
  distribution: string;
  nextVersion: number;
  counts: Record<string, SectionCount> | null;
};

/** The body of the finalize confirmation (also rendered alone in tests). */
export function FinalizeForm({
  summary,
  canDowngrade,
  blockers,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  summary: FinalizeSummary;
  canDowngrade: boolean;
  blockers: readonly string[];
  pending: boolean;
  error: unknown;
  onSubmit: (options: FinalizeOptions) => void;
  onCancel: () => void;
}) {
  const id = useId();
  const [note, setNote] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [tlpAck, setTlpAck] = useState(false);
  const external = summary.profile === "external";
  const belowCase =
    hasCode(error, "tlp_below_case") || (summary.caseTlp !== null && isDowngrade(summary.tlp, summary.caseTlp));
  const units = hasCode(error, "report_too_large_to_render") || hasCode(error, "report_too_large") ? sectionUnitsOf(error) : null;
  const errorCounts = sectionCountsOf(error);
  const blocked =
    blockers.length > 0 || (external && !reviewed) || (belowCase && (!canDowngrade || !tlpAck)) || [...note].length > CHANGE_NOTE_MAX_CHARS;

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (blocked || pending) return;
        onSubmit({
          change_note: note.trim() ? note : null,
          acknowledge_external_review: external && reviewed,
          acknowledge_tlp_downgrade: belowCase && tlpAck,
        });
      }}
    >
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">Marking</dt>
        <dd>
          <TlpBadge tlp={summary.tlp} />
        </dd>
        <dt className="text-muted-foreground">Profile</dt>
        <dd>{PROFILE_TEXT[summary.profile].label}</dd>
        <dt className="text-muted-foreground">Distribution</dt>
        <dd className="break-words whitespace-pre-wrap">{summary.distribution.trim() ? vis(summary.distribution) : "—"}</dd>
      </dl>
      {summary.counts ? (
        <SectionCountsTable counts={summary.counts} />
      ) : (
        <p className="text-xs text-muted-foreground">Run a preview to see the section counts before you finalize.</p>
      )}

      <div className="flex flex-col gap-1">
        <label htmlFor={`${id}-note`} className="text-sm font-medium">
          Change note <span className="text-muted-foreground">(optional, printed in the document control)</span>
        </label>
        <Textarea
          id={`${id}-note`}
          rows={2}
          value={note}
          maxLength={CHANGE_NOTE_MAX_CHARS}
          aria-describedby={`${id}-note-count`}
          onChange={(event) => setNote(event.target.value)}
        />
        <Counter id={`${id}-note-count`} value={note} max={CHANGE_NOTE_MAX_CHARS} />
      </div>

      {external ? (
        <div className="flex flex-col gap-1 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-sm">
          <p className="text-xs">{EXTERNAL_REVIEW_WARNING}</p>
          <label className="flex items-start gap-2 font-medium">
            <input type="checkbox" className="mt-1" checked={reviewed} required onChange={(event) => setReviewed(event.target.checked)} />
            <span>{EXTERNAL_REVIEW_ACK}</span>
          </label>
        </div>
      ) : null}

      {belowCase ? (
        <div role="alert" className="flex flex-col gap-1 rounded-md border border-destructive/50 p-3 text-sm">
          <p>
            {summary.caseTlp
              ? `The case is marked ${TLP_LABELS[summary.caseTlp]}, more restrictive than this report's ${TLP_LABELS[summary.tlp]}.`
              : "The case TLP is now more restrictive than this report's TLP."}
          </p>
          {canDowngrade ? (
            <label className="flex items-start gap-2 font-medium">
              <input type="checkbox" className="mt-1" checked={tlpAck} onChange={(event) => setTlpAck(event.target.checked)} />
              <span>I confirm signing this report below the case marking. This is audited.</span>
            </label>
          ) : (
            <p className="text-xs text-muted-foreground">
              Only an admin can sign a report below the case TLP. Raise the report&apos;s TLP to {summary.caseTlp ? TLP_LABELS[summary.caseTlp] : "the case TLP"} or ask an admin.
            </p>
          )}
        </div>
      ) : null}

      {blockers.length ? (
        <ul role="alert" className="list-disc pl-5 text-sm text-destructive">
          {blockers.map((blocker) => (
            <li key={blocker}>{blocker}</li>
          ))}
        </ul>
      ) : null}

      {error && !hasCode(error, "tlp_below_case") ? (
        <div role="alert" className="flex flex-col gap-2 text-sm text-destructive">
          <p>{reportErrorText(error) ?? errorMessage(error)}</p>
          {units ? <BudgetTable units={units} highlight /> : null}
          {!units && errorCounts ? <SectionCountsTable counts={errorCounts} /> : null}
        </div>
      ) : null}

      <p className="text-sm font-medium">
        A signed, immutable version v{summary.nextVersion} will be created. The draft stays editable for the next version.
        The PDF is rendered right away; HTML and Markdown can be rendered from the version page.
      </p>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={blocked || pending}>
          {pending ? "Finalizing…" : `Finalize v${summary.nextVersion}`}
        </Button>
      </DialogFooter>
    </form>
  );
}

export function FinalizeDialog({
  open,
  onOpenChange,
  summary,
  canDowngrade,
  blockers,
  onFinalize,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  summary: FinalizeSummary;
  canDowngrade: boolean;
  blockers: readonly string[];
  onFinalize: (options: FinalizeOptions) => Promise<ReportVersion>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setError(null);
        onOpenChange(next);
      }}
    >
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Finalize version {summary.nextVersion}</DialogTitle>
          <DialogDescription>Freeze the draft into a signed snapshot. Check the summary first.</DialogDescription>
        </DialogHeader>
        {open ? (
          <FinalizeForm
            summary={summary}
            canDowngrade={canDowngrade}
            blockers={blockers}
            pending={pending}
            error={error}
            onCancel={() => onOpenChange(false)}
            onSubmit={async (options) => {
              setPending(true);
              setError(null);
              try {
                await onFinalize(options);
              } catch (caught) {
                setError(caught);
              } finally {
                setPending(false);
              }
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
