"use client";

import { Pager } from "@/components/pager";
import { CandidateSample, CategoryCountsTable } from "@/components/retention/retention-preview";
import { RunStatusBadge } from "@/components/retention/retention-runs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatBytes } from "@/lib/format";
import {
  CATEGORY_LABELS,
  MODE_LABELS,
  OUTCOMES,
  OUTCOME_LABELS,
  type OutcomeFilter,
  RETENTION_FIELDS,
  RETENTION_FIELD_TEXT,
  RUN_ITEMS_PAGE,
  type RetentionRunDetail,
  type RetentionRunItem,
  type RunItemsQuery,
  TRIGGER_LABELS,
  formatDayTime,
  formatDays,
  labelText,
  outcomeOptionText,
} from "@/lib/retention";

export const ITEMS_PAGE = RUN_ITEMS_PAGE;

/** The run's items (pure): table names and ids only, as text. */
export function RunItemsTable({ items }: { items: readonly RetentionRunItem[] }) {
  if (items.length === 0) return <p className="text-sm text-muted-foreground">No items.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Outcome</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Table</TableHead>
          <TableHead>Id</TableHead>
          <TableHead className="text-right">Rows</TableHead>
          <TableHead className="text-right">Bytes</TableHead>
          <TableHead>When</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((item) => (
          <TableRow key={item.id} data-outcome={item.outcome}>
            <TableCell>{Object.hasOwn(OUTCOME_LABELS, item.outcome) ? OUTCOME_LABELS[item.outcome] : "Other"}</TableCell>
            <TableCell>{Object.hasOwn(CATEGORY_LABELS, item.category) ? CATEGORY_LABELS[item.category] : "Other"}</TableCell>
            <TableCell className="font-mono text-xs">{labelText(item.ref_table, 64)}</TableCell>
            <TableCell className="max-w-48 truncate font-mono text-xs" title={labelText(item.ref_id, 128)}>
              {labelText(item.ref_id, 64)}
            </TableCell>
            <TableCell className="text-right tabular-nums">{item.rows.toLocaleString("en-US")}</TableCell>
            <TableCell className="text-right tabular-nums">{formatBytes(item.bytes)}</TableCell>
            <TableCell className="whitespace-nowrap">{formatDayTime(item.created_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/**
 * A run: its policy, counts, sample and one page of its items. The API pages and filters the
 * items (`query`: outcome and offset); `onQuery` asks the page for another page or outcome.
 */
export function RetentionRunDetailView({
  run,
  query,
  onQuery,
  loading = false,
}: {
  run: RetentionRunDetail;
  query: RunItemsQuery;
  onQuery: (query: RunItemsQuery) => void;
  loading?: boolean;
}) {
  const counts = run.outcome_counts ?? {};
  const matching = run.items_matching ?? run.items_total;

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            {MODE_LABELS[run.mode]} · {TRIGGER_LABELS[run.trigger]} <RunStatusBadge status={run.status} />
          </CardTitle>
          <CardDescription>
            Queued {formatDayTime(run.created_at)}
            {run.started_at ? ` · started ${formatDayTime(run.started_at)}` : ""}
            {run.finished_at ? ` · finished ${formatDayTime(run.finished_at)}` : ""}
            {run.error ? ` · error ${run.error.slice(0, 64)}` : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {run.policy && (
            <ul className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
              {RETENTION_FIELDS.map((field) => (
                <li key={field}>
                  <span className="text-muted-foreground">{RETENTION_FIELD_TEXT[field].label}:</span>{" "}
                  {formatDays(run.policy?.[field] ?? null)}
                </li>
              ))}
            </ul>
          )}
          {run.mode === "dry_run" && <p className="text-sm text-muted-foreground">A dry run: nothing was deleted.</p>}
          <CategoryCountsTable counts={run.counts} />
          {run.sample.length > 0 && (
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Sample of candidates</p>
              <CandidateSample sample={run.sample} />
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Items</CardTitle>
          <CardDescription aria-live="polite">
            {query.outcome === "all"
              ? `${run.items_total.toLocaleString("en-US")} items.`
              : `${matching.toLocaleString("en-US")} of ${run.items_total.toLocaleString("en-US")} items: ${OUTCOME_LABELS[query.outcome].toLowerCase()}.`}
            {loading ? " Loading…" : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <label className="flex items-center gap-2 text-sm">
            Outcome
            <select
              className="h-8 rounded-md border bg-background px-2 text-sm"
              value={query.outcome}
              onChange={(event) => onQuery({ outcome: event.target.value as OutcomeFilter, offset: 0 })}
            >
              <option value="all">{outcomeOptionText("all", counts, run.items_total)}</option>
              {OUTCOMES.map((value) => (
                <option key={value} value={value}>
                  {outcomeOptionText(value, counts, run.items_total)}
                </option>
              ))}
            </select>
          </label>
          <RunItemsTable items={run.items} />
          <Pager
            offset={query.offset}
            total={matching}
            pageSize={ITEMS_PAGE}
            onChange={(offset) => onQuery({ ...query, offset })}
          />
        </CardContent>
      </Card>
    </div>
  );
}
