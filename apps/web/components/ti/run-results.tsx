"use client";

import Link from "next/link";
import { useState } from "react";

import { ExpandableRow, Trunc, When } from "@/components/analysis/result-parts";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { ProviderChip } from "@/components/ti/provider-chip";
import { ResultPanel } from "@/components/ti/result-panel";
import { RunProgress } from "@/components/ti/run-progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  type TiRunItem,
  historyHref,
  itemReasonText,
  providerLabel,
  tiIocTypeLabel,
} from "@/lib/ti";
import { useRunDetail } from "@/lib/use-ti";

const ITEMS_PAGE = 100;
const COLUMNS = 5;

function StateCell({ item }: { item: TiRunItem }) {
  if (item.result) {
    return (
      <div className="flex flex-col gap-0.5">
        <ProviderChip e={item.result} summary={item.result.summary} />
        <span className="text-[11px] text-muted-foreground">
          {item.from_cache ? "cached, fetched " : "fetched "}
          <When iso={item.result.fetched_at} />
        </span>
      </div>
    );
  }
  if (item.state === "pending") return <span className="text-xs text-muted-foreground">pending</span>;
  if (item.state === "abandoned")
    return <span className="text-xs text-muted-foreground">not looked up: {itemReasonText(item.reason)}</span>;
  return <span className="text-xs text-muted-foreground">—</span>;
}

/** A run's progress and its planned lookups (value × provider) with each answer, cached ones marked. */
export function RunResults({ orgId, runId }: { orgId: string; runId: string }) {
  const [offset, setOffset] = useState(0);
  const detail = useRunDetail(orgId, runId, { limit: ITEMS_PAGE, offset });
  const items = detail.data?.items.items;

  return (
    <div className="flex min-w-0 flex-col gap-3">
      {detail.isError && <QueryError error={detail.error} onRetry={() => void detail.refetch()} />}
      {detail.data && <RunProgress orgId={orgId} run={detail.data} />}
      <div className="min-w-0 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8" />
              <TableHead>Value</TableHead>
              <TableHead className="w-24">Type</TableHead>
              <TableHead className="w-36">Provider</TableHead>
              <TableHead>Answer</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {detail.isPending && (
              <TableRow>
                <TableCell colSpan={COLUMNS} className="py-8 text-center text-muted-foreground">
                  Loading…
                </TableCell>
              </TableRow>
            )}
            {items?.length === 0 && (
              <TableRow>
                <TableCell colSpan={COLUMNS} className="py-8 text-center text-muted-foreground">
                  Nothing was planned for this run.
                </TableCell>
              </TableRow>
            )}
            {items?.map((item) => (
              <ExpandableRow
                key={`${item.provider}-${item.ioc_key}`}
                columns={COLUMNS}
                cells={
                  <>
                    <TableCell>
                      <Trunc value={item.value_norm} mono className="max-w-96" />
                    </TableCell>
                    <TableCell>{tiIocTypeLabel(item.ioc_type)}</TableCell>
                    <TableCell>{providerLabel(item.provider)}</TableCell>
                    <TableCell>
                      <StateCell item={item} />
                    </TableCell>
                  </>
                }
                detail={
                  <div className="flex flex-col gap-2">
                    {item.result ? (
                      <ResultPanel result={item.result} />
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        {item.state === "pending"
                          ? "Not looked up yet."
                          : `No answer: ${itemReasonText(item.reason) ?? item.state}.`}
                      </p>
                    )}
                    <Link
                      href={historyHref(orgId, item.ioc_type, item.value_norm)}
                      className="self-start text-xs text-primary underline-offset-4 hover:underline"
                    >
                      View history
                    </Link>
                  </div>
                }
              />
            ))}
          </TableBody>
        </Table>
      </div>
      <Pager offset={offset} total={detail.data?.items.total ?? 0} pageSize={ITEMS_PAGE} onChange={setOffset} />
    </div>
  );
}
