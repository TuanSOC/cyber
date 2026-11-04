"use client";

import { When } from "@/components/analysis/result-parts";
import { AttackChips, MitreNotice, useAttackLookup } from "@/components/ti/attack-chips";
import { Permalink, ProviderChip, TextList, TlpBadges } from "@/components/ti/provider-chip";
import {
  RESULT_STATUS_LABELS,
  type TiResult,
  attributedText,
  providerLabel,
  summaryAttackIds,
  summaryFields,
} from "@/lib/ti";
import { useTiResult } from "@/lib/use-ti";

/** Label / value rows of one provider summary (all provider text rendered as text). */
export function SummaryFieldList({ result }: { result: TiResult }) {
  const fields = summaryFields(result.summary);
  if (fields.length === 0) return null;
  return (
    <dl className="grid grid-cols-[minmax(9rem,auto)_1fr] gap-x-4 gap-y-1 text-sm">
      {fields.map((field) => (
        <div key={field.key} className="contents">
          <dt className="text-muted-foreground">{field.label}</dt>
          <dd className="min-w-0">
            {field.iso ? (
              <When iso={field.iso} />
            ) : field.list ? (
              <TextList values={field.list} />
            ) : (
              <span className={field.mono ? "font-mono text-xs break-all" : "break-words"} title={field.text}>
                {field.text}
              </span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * One provider answer in full: attributed header, key fields, tags / families, ATT&CK ids
 * (OTX pulses, MISP galaxies) with the MITRE notice, TLP labels and the https permalink.
 */
export function ResultPanel({ result, compact = false }: { result: TiResult; compact?: boolean }) {
  const ids = [...result.attack_ids, ...summaryAttackIds(result.summary)];
  const attack = useAttackLookup(ids);
  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{providerLabel(result.provider)}</span>
        <ProviderChip e={result} summary={result.summary} />
        <TlpBadges summary={result.summary} />
        <Permalink url={result.permalink} label={`Open in ${providerLabel(result.provider)}`} />
      </div>
      <p className="text-xs text-muted-foreground">
        {attributedText(result)}
        {result.status === "ok" || result.status === "not_found" ? "" : ` (${RESULT_STATUS_LABELS[result.status]})`}
        {result.error_code ? ` · ${result.error_code}` : ""}
      </p>
      {!compact && <SummaryFieldList result={result} />}
      {result.families.length > 0 && (
        <div className="flex flex-wrap items-baseline gap-2 text-sm">
          <span className="text-muted-foreground">Families named by {providerLabel(result.provider)}</span>
          <TextList values={result.families} />
        </div>
      )}
      {!compact && result.tags.length > 0 && (
        <div className="flex flex-wrap items-baseline gap-2 text-sm">
          <span className="text-muted-foreground">Tags</span>
          <TextList values={result.tags} max={20} />
        </div>
      )}
      {ids.length > 0 && (
        <div className="flex flex-col gap-1 text-sm">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="text-muted-foreground">ATT&amp;CK ids cited by {providerLabel(result.provider)}</span>
            <AttackChips ids={ids} lookup={attack} />
          </div>
          <MitreNotice meta={attack.meta} />
        </div>
      )}
      <p className="text-[11px] text-muted-foreground">
        Fetched <When iso={result.fetched_at} />
        {result.expires_at && (
          <>
            {" "}· cached until <When iso={result.expires_at} />
          </>
        )}
        {result.stale && " · stale (past its cache lifetime)"}
      </p>
    </div>
  );
}

/** Loads one stored result by id and shows it (IOC tab expansion). */
export function ResultById({ orgId, resultId }: { orgId: string; resultId: string }) {
  const result = useTiResult(orgId, resultId);
  if (result.isPending) return <p className="text-xs text-muted-foreground">Loading…</p>;
  if (result.isError || !result.data) return <p className="text-xs text-destructive">Could not load this result.</p>;
  return <ResultPanel result={result.data} />;
}
