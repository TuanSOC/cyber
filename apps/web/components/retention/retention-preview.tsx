"use client";

import { useMutation } from "@tanstack/react-query";
import { Eye } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { errorMessage } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { apiErrorText } from "@/lib/http-errors";
import {
  CATEGORY_LABELS,
  RETENTION_FIELDS,
  RETENTION_FIELD_TEXT,
  type RetentionCandidate,
  type RetentionCategoryCount,
  type RetentionPolicy,
  type RetentionPreview,
  categoryRows,
  countTotals,
  fetchPreview,
  formatDayTime,
  formatDays,
  hasPending,
  labelText,
  previewBody,
} from "@/lib/retention";

/** Per-category counts (pure; also used by the run detail). */
export function CategoryCountsTable({ counts }: { counts: Readonly<Record<string, RetentionCategoryCount>> }) {
  const rows = categoryRows(counts);
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">No candidates.</p>;
  const total = countTotals(counts);
  const cells = (count: RetentionCategoryCount) => (
    <>
      <TableCell className="text-right tabular-nums">{count.candidates.toLocaleString("en-US")}</TableCell>
      <TableCell className="text-right tabular-nums">{count.rows.toLocaleString("en-US")}</TableCell>
      <TableCell className="text-right tabular-nums">{formatBytes(count.bytes)}</TableCell>
      <TableCell className="text-right tabular-nums">{count.skipped_hold.toLocaleString("en-US")}</TableCell>
      <TableCell className="text-right tabular-nums">{count.skipped_locked.toLocaleString("en-US")}</TableCell>
      <TableCell className="text-right tabular-nums">{count.kept_cited.toLocaleString("en-US")}</TableCell>
    </>
  );
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Category</TableHead>
          <TableHead className="text-right">Candidates</TableHead>
          <TableHead className="text-right">Rows</TableHead>
          <TableHead className="text-right">Bytes</TableHead>
          <TableHead className="text-right">Held</TableHead>
          <TableHead className="text-right">Locked</TableHead>
          <TableHead className="text-right">Cited</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map(({ category, count }) => (
          <TableRow key={category}>
            <TableCell>{CATEGORY_LABELS[category]}</TableCell>
            {cells(count)}
          </TableRow>
        ))}
        {rows.length > 1 && (
          <TableRow className="font-medium">
            <TableCell>Total</TableCell>
            {cells(total)}
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}

/** The bounded sample of candidates: table names and ids only, as text (pure). */
export function CandidateSample({ sample }: { sample: readonly RetentionCandidate[] }) {
  if (sample.length === 0) return null;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Category</TableHead>
          <TableHead>Table</TableHead>
          <TableHead>Id</TableHead>
          <TableHead>Job</TableHead>
          <TableHead className="text-right">Rows</TableHead>
          <TableHead className="text-right">Bytes</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {sample.map((item, index) => (
          <TableRow key={`${item.ref_table}:${item.ref_id}:${index}`}>
            <TableCell>{Object.hasOwn(CATEGORY_LABELS, item.category) ? CATEGORY_LABELS[item.category] : "Other"}</TableCell>
            <TableCell className="font-mono text-xs">{labelText(item.ref_table, 64)}</TableCell>
            <TableCell className="max-w-48 truncate font-mono text-xs" title={labelText(item.ref_id, 128)}>
              {labelText(item.ref_id, 64)}
            </TableCell>
            <TableCell className="max-w-40 truncate font-mono text-xs">{labelText(item.job_id, 64)}</TableCell>
            <TableCell className="text-right tabular-nums">{item.rows.toLocaleString("en-US")}</TableCell>
            <TableCell className="text-right tabular-nums">{formatBytes(item.bytes)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/** A preview result (pure). */
export function PreviewResult({ preview, includesPending }: { preview: RetentionPreview; includesPending: boolean }) {
  return (
    <div className="flex flex-col gap-4" data-slot="retention-preview">
      <p className="text-sm text-muted-foreground">
        Computed {formatDayTime(preview.generated_at)}
        {includesPending ? " · includes pending values" : " · effective values"}
        {" · "}
        {preview.holds_active === 1 ? "1 legal hold active" : `${preview.holds_active} legal holds active`}
      </p>
      <ul className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
        {RETENTION_FIELDS.map((field) => (
          <li key={field}>
            <span className="text-muted-foreground">{RETENTION_FIELD_TEXT[field].label}:</span>{" "}
            {formatDays(preview.policy[field])}
          </li>
        ))}
      </ul>
      <CategoryCountsTable counts={preview.counts} />
      {preview.sample.length > 0 && (
        <div className="flex flex-col gap-2">
          <p className="text-sm font-medium">
            Sample of candidates
            {preview.truncated ? <span className="font-normal text-muted-foreground"> (truncated)</span> : null}
          </p>
          <CandidateSample sample={preview.sample} />
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        A preview deletes nothing. Held, locked and cited items are counted but never deleted.
      </p>
    </div>
  );
}

/** "What would a run select now?" (`org.update`; read-only on the server). */
export function RetentionPreviewCard({ orgId, policy }: { orgId: string; policy: RetentionPolicy }) {
  const pendingAvailable = hasPending(policy);
  const [includePending, setIncludePending] = useState(false);
  const preview = useMutation({
    mutationFn: (withPending: boolean) => fetchPreview(orgId, previewBody(policy, withPending)),
  });
  const withPending = pendingAvailable && includePending;
  const empty = RETENTION_FIELDS.every((field) => policy[field] === null) && !withPending;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Preview</CardTitle>
        <CardDescription>What a run would select now: counts and bytes per category and a short sample.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-4">
          <Button size="sm" disabled={preview.isPending} onClick={() => preview.mutate(withPending)}>
            <Eye className="size-4" aria-hidden /> {preview.isPending ? "Computing…" : "Preview"}
          </Button>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={withPending}
              disabled={!pendingAvailable}
              onChange={(event) => setIncludePending(event.target.checked)}
            />
            Include pending values
          </label>
          {empty && <span className="text-xs text-muted-foreground">Every value is keep forever: nothing is selected.</span>}
        </div>
        {preview.isError && (
          <p className="text-sm text-destructive" role="alert">
            {apiErrorText(preview.error) ?? errorMessage(preview.error)}
          </p>
        )}
        {preview.data && <PreviewResult preview={preview.data} includesPending={preview.variables === true} />}
      </CardContent>
    </Card>
  );
}
