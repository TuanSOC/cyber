"use client";

import { Info } from "lucide-react";
import { type ReactNode, useState } from "react";

import { When } from "@/components/analysis/result-parts";
import { CitationChips } from "@/components/ai/citation-chip";
import { ModelText } from "@/components/ai/model-text";
import { AttackChips, MitreNotice, useAttackLookup } from "@/components/ti/attack-chips";
import { Button } from "@/components/ui/button";
import {
  type AiAttack,
  type AiClaim,
  type AiHypothesis,
  type AiNextStep,
  type AiOutput,
  type AiTimelineEntry,
  type Confidence,
  type OutputFlag,
  CONFIDENCE_LABEL,
  SECTION_COLLAPSE_AFTER,
  claimSupportText,
  flagText,
  hiddenClaimsText,
  outputTruncationNotes,
  partitionClaims,
  staleCount,
  visibleSlice,
} from "@/lib/ai";
import { cn } from "@/lib/utils";

/** Neutral confidence badge (no red / green: never a maliciousness score, RT20/RT21). */
export function ConfidenceBadge({ level, className }: { level: Confidence; className?: string }) {
  return (
    <span
      className={cn("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] text-muted-foreground", className)}
      title={`${CONFIDENCE_LABEL}: ${level}`}
    >
      <span className="sr-only">{CONFIDENCE_LABEL}: </span>
      <span aria-hidden>confidence </span>
      {level}
    </span>
  );
}

/** Output notes (flags, stale citations, display caps): fixed texts only. */
export function OutputNotes({ notes }: { notes: readonly string[] }) {
  if (notes.length === 0) return null;
  return (
    <ul className="flex flex-col gap-1">
      {notes.map((note) => (
        <li key={note} className="flex items-start gap-2 text-xs text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>{note}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * The verified output of one run, by section. Unsupported statements are collapsed behind a
 * counter (greyed when expanded); long sections collapse after 10 items with counts visible.
 * Every model string goes through `ModelText`; the only links are verified citation chips.
 */
export function AnalysisOutput({
  orgId,
  output,
  extraFlags = [],
  variant = "job",
}: {
  orgId: string;
  output: AiOutput;
  /** Flags of incident children shown on the parent (RT23). */
  extraFlags?: readonly OutputFlag[];
  variant?: "job" | "incident";
}) {
  const flags = [...new Set([...output.flags, ...extraFlags])];
  const stale = staleCount(output);
  const notes = [
    ...flags.map(flagText),
    ...(extraFlags.length ? ["Flags from the per-job digests are carried into this summary."] : []),
    ...(stale ? [`${stale} cited record${stale === 1 ? "" : "s"} changed after this analysis (marked stale).`] : []),
    ...outputTruncationNotes(output.verification.truncation),
    ...(output.verification.dropped_refs
      ? [`${output.verification.dropped_refs} references outside the sent context were dropped.`]
      : []),
    ...(output.verification.invalid_attack
      ? [`${output.verification.invalid_attack} technique ids not in the ATT&CK index were dropped.`]
      : []),
  ];
  const incident = variant === "incident";

  return (
    <div className="flex flex-col gap-5 text-sm">
      <OutputNotes notes={notes} />
      <ClaimSection title={incident ? "Summary: observed" : "Observed"} orgId={orgId} claims={output.observed} />
      <ClaimSection title="Interpretation" orgId={orgId} claims={output.interpretation} />
      {incident && <TimelineSection orgId={orgId} entries={output.timeline} />}
      <HypothesisSection orgId={orgId} hypotheses={output.hypotheses} />
      <Section title="Confidence">
        <div className="flex flex-col gap-1">
          <p className="text-xs text-muted-foreground">
            {CONFIDENCE_LABEL}: <span className="font-medium text-foreground">{output.overall_confidence.level}</span>
          </p>
          {output.overall_confidence.rationale && <ModelText value={output.overall_confidence.rationale} />}
        </div>
      </Section>
      <NextStepSection
        orgId={orgId}
        steps={output.next_steps}
        title={incident ? "Recommendations" : "Next steps"}
        commandLike={flags.includes("command_like")}
      />
      <Section title="Limitations" count={output.limitations.length} hideWhenEmpty>
        <Collapsible items={output.limitations}>
          {(items) => (
            <ul className="flex list-disc flex-col gap-1 pl-5">
              {items.map((text, index) => (
                <li key={index}>
                  <ModelText value={text} />
                </li>
              ))}
            </ul>
          )}
        </Collapsible>
      </Section>
      <AttackSection orgId={orgId} techniques={output.attack_techniques} />
      {!incident && <TimelineSection orgId={orgId} entries={output.timeline} />}
    </div>
  );
}

function Section({
  title,
  count,
  children,
  hideWhenEmpty,
}: {
  title: string;
  count?: number;
  children: ReactNode;
  hideWhenEmpty?: boolean;
}) {
  if (hideWhenEmpty && count === 0) return null;
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {title}
        {count !== undefined && <span className="ml-1 font-normal normal-case">({count})</span>}
      </h3>
      {children}
    </section>
  );
}

/** First 10 items, then "Show all n". */
function Collapsible<T>({ items, children }: { items: readonly T[]; children: (items: T[]) => ReactNode }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      {children(visibleSlice(items, expanded))}
      {items.length > SECTION_COLLAPSE_AFTER && (
        <Button variant="link" size="sm" className="h-auto self-start p-0 text-xs" onClick={() => setExpanded(!expanded)}>
          {expanded ? "Show fewer" : `Show all ${items.length}`}
        </Button>
      )}
    </>
  );
}

/** "N statements hidden: not supported by verified evidence", expandable (greyed). */
function HiddenStatements<T>({ items, children }: { items: readonly T[]; children: (items: T[]) => ReactNode }) {
  const [open, setOpen] = useState(false);
  if (items.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      <Button
        variant="ghost"
        size="sm"
        className="h-auto self-start px-1 py-0.5 text-xs text-muted-foreground"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {hiddenClaimsText(items.length)} · {open ? "hide" : "show"}
      </Button>
      {open && <div className="opacity-60">{children([...items])}</div>}
    </div>
  );
}

function ClaimItem({ orgId, claim }: { orgId: string; claim: AiClaim }) {
  return (
    <li className="flex flex-col gap-1" data-claim-status={claim.status}>
      <ModelText value={claim.text} />
      <span className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <span>{claimSupportText(claim)}</span>
        <ConfidenceBadge level={claim.confidence} />
        <CitationChips orgId={orgId} citations={claim.citations} />
      </span>
    </li>
  );
}

function ClaimSection({ title, orgId, claims }: { title: string; orgId: string; claims: readonly AiClaim[] }) {
  const { shown, hidden } = partitionClaims(claims);
  const list = (items: AiClaim[]) => (
    <ul className="flex flex-col gap-3">
      {items.map((claim) => (
        <ClaimItem key={claim.id} orgId={orgId} claim={claim} />
      ))}
    </ul>
  );
  return (
    <Section title={title} count={shown.length}>
      {shown.length === 0 && <p className="text-xs text-muted-foreground">No statement backed by cited evidence.</p>}
      <Collapsible items={shown}>{list}</Collapsible>
      <HiddenStatements items={hidden}>{list}</HiddenStatements>
    </Section>
  );
}

function HypothesisSection({ orgId, hypotheses }: { orgId: string; hypotheses: readonly AiHypothesis[] }) {
  const { shown, hidden } = partitionClaims(hypotheses);
  const list = (items: AiHypothesis[]) => (
    <ul className="flex flex-col gap-3">
      {items.map((h) => (
        <li key={h.id} className="flex flex-col gap-1" data-claim-status={h.status}>
          <ModelText value={h.text} />
          <span className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
            <span>{claimSupportText(h)}</span>
            <ConfidenceBadge level={h.confidence} />
          </span>
          {h.supporting.length > 0 && (
            <span className="flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground">
              <span>Consistent with:</span>
              <CitationChips orgId={orgId} citations={h.supporting} />
            </span>
          )}
          {h.contradicting.length > 0 && (
            <span className="flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground">
              <span>Speaks against:</span>
              <CitationChips orgId={orgId} citations={h.contradicting} />
            </span>
          )}
        </li>
      ))}
    </ul>
  );
  return (
    <Section title="Hypotheses" count={shown.length} hideWhenEmpty={hypotheses.length === 0}>
      <p className="text-[11px] text-muted-foreground">Possibilities to check, not findings.</p>
      <Collapsible items={shown}>{list}</Collapsible>
      <HiddenStatements items={hidden}>{list}</HiddenStatements>
    </Section>
  );
}

function NextStepSection({
  orgId,
  steps,
  title,
  commandLike,
}: {
  orgId: string;
  steps: readonly AiNextStep[];
  title: string;
  commandLike: boolean;
}) {
  return (
    <Section title={title} count={steps.length} hideWhenEmpty>
      {commandLike && <p className="text-[11px] text-muted-foreground">CyberLab never runs commands.</p>}
      <Collapsible items={steps}>
        {(items) => (
          <ol className="flex list-decimal flex-col gap-3 pl-5">
            {items.map((step, index) => (
              <li key={index} className="flex flex-col gap-1">
                <ModelText value={step.text} className={cn(commandLike && "font-mono text-xs")} />
                {step.rationale && <ModelText value={step.rationale} className="text-xs text-muted-foreground" />}
                <CitationChips orgId={orgId} citations={step.refs} />
              </li>
            ))}
          </ol>
        )}
      </Collapsible>
    </Section>
  );
}

function AttackSection({ orgId, techniques }: { orgId: string; techniques: readonly AiAttack[] }) {
  const { shown, hidden } = partitionClaims(techniques);
  const lookup = useAttackLookup(techniques.map((t) => t.technique_id));
  if (techniques.length === 0) return null;
  const list = (items: AiAttack[]) => (
    <ul className="flex flex-col gap-3">
      {items.map((t, index) => (
        <li key={`${t.technique_id}-${index}`} className="flex flex-col gap-1" data-claim-status={t.status}>
          {/* Name and tactic from the offline index, as text: no external link in AI views. */}
          <AttackChips ids={[t.technique_id]} lookup={lookup} link={false} />
          {t.rationale && <ModelText value={t.rationale} />}
          <span className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
            <span>{claimSupportText(t)}</span>
            <CitationChips orgId={orgId} citations={t.citations} />
          </span>
        </li>
      ))}
    </ul>
  );
  return (
    <Section title="Possible ATT&CK techniques" count={shown.length}>
      <Collapsible items={shown}>{list}</Collapsible>
      <HiddenStatements items={hidden}>{list}</HiddenStatements>
      <MitreNotice meta={lookup.meta} />
    </Section>
  );
}

function TimelineSection({ orgId, entries }: { orgId: string; entries: readonly AiTimelineEntry[] }) {
  const { shown, hidden } = partitionClaims(entries);
  if (entries.length === 0) return null;
  // Times come from the cited records (never from the model); entries without one sort last.
  const ordered = [...shown].sort((a, b) => (a.ts ?? "￿").localeCompare(b.ts ?? "￿"));
  const list = (items: AiTimelineEntry[]) => (
    <ol className="relative ml-2 flex flex-col gap-3 border-l pl-4">
      {items.map((entry, index) => (
        <li key={index} className="flex flex-col gap-1">
          <span className="text-xs">
            {entry.ts ? <When iso={entry.ts} /> : <span className="text-muted-foreground">time unknown</span>}
          </span>
          <ModelText value={entry.text} />
          <span className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
            <span>{claimSupportText(entry)}</span>
            <CitationChips orgId={orgId} citations={entry.citations} />
          </span>
        </li>
      ))}
    </ol>
  );
  return (
    <Section title="Timeline" count={shown.length}>
      <p className="text-[11px] text-muted-foreground">Times are taken from the cited records.</p>
      <Collapsible items={ordered}>{list}</Collapsible>
      <HiddenStatements items={hidden}>{list}</HiddenStatements>
    </Section>
  );
}
