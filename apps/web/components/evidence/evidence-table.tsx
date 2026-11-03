"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { HashValue } from "@/components/hash-value";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { formatBytes, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";

export function EvidenceTable({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const [offset, setOffset] = useState(0);
  const list = useQuery({
    queryKey: ["org", orgId, "evidence-list", investigationId, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/evidence", {
          params: {
            path: { org_id: orgId, investigation_id: investigationId },
            query: { limit: PAGE_SIZE, offset },
          },
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <div className="flex flex-col gap-3">
      {list.isError && <QueryError error={list.error} onRetry={() => void list.refetch()} />}
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>File</TableHead>
              <TableHead className="w-24 text-right">Size</TableHead>
              <TableHead className="w-48">Detected type</TableHead>
              <TableHead className="w-44">SHA-256</TableHead>
              <TableHead className="w-44">Uploaded</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isPending && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  Loading evidence…
                </TableCell>
              </TableRow>
            )}
            {list.data?.items.map((e) => {
              const uploaded = formatDate(e.uploaded_at);
              return (
                <TableRow key={e.id}>
                  <TableCell className="max-w-72 truncate" title={e.original_filename}>
                    <Link className="hover:underline" href={orgPath(orgId, `evidence/${e.id}`)}>
                      {e.original_filename}
                    </Link>
                    {e.status === "archived" && (
                      <Badge variant="outline" className="ml-2">
                        archived
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{formatBytes(e.size_bytes)}</TableCell>
                  <TableCell className="max-w-48 truncate text-muted-foreground" title={e.detected_description}>
                    {e.detected_mime}
                  </TableCell>
                  <TableCell>{e.hashes.sha256 && <HashValue value={e.hashes.sha256} short />}</TableCell>
                  <TableCell title={uploaded.utc} className="text-muted-foreground">
                    {uploaded.local}
                    <span className="block text-xs">{e.uploaded_by_name}</span>
                  </TableCell>
                </TableRow>
              );
            })}
            {list.data?.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  No evidence yet.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <Pager offset={offset} total={list.data?.total ?? 0} onChange={setOffset} />
    </div>
  );
}
