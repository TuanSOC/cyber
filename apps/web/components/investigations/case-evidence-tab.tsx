"use client";

import Link from "next/link";
import { useState } from "react";

import { EvidenceUploader } from "@/components/evidence/evidence-uploader";
import { HashValue } from "@/components/hash-value";
import {
  EvidenceExclusionBadges,
  EvidenceSharePolicyButton,
} from "@/components/investigations/evidence-share-policy";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { type Investigation, caseErrorMessage } from "@/lib/case";
import { formatBytes, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import type { Permission } from "@/lib/roles";
import { useCaseEvidence } from "@/lib/use-case";

/**
 * Evidence tab: the uploader and the case's evidence with a share-policy badge per excluded
 * item and the per-item share-policy control.
 */
export function CaseEvidenceTab({
  orgId,
  inv,
  can,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
}) {
  const [offset, setOffset] = useState(0);
  const list = useCaseEvidence(orgId, inv.id, offset, PAGE_SIZE);
  const archived = inv.status === "archived";
  const writable = can("investigation.write") && can("evidence.write") && !archived;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {writable && <EvidenceUploader orgId={orgId} investigationId={inv.id} />}
        {archived && <p className="text-sm text-muted-foreground">This investigation is archived and read-only.</p>}
        {list.isError && (
          <p className="text-sm text-destructive" role="alert">
            {caseErrorMessage(list.error)}
          </p>
        )}
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File</TableHead>
                <TableHead className="w-24 text-right">Size</TableHead>
                <TableHead className="w-44">SHA-256</TableHead>
                <TableHead className="w-44">Uploaded</TableHead>
                <TableHead className="w-28">Policy</TableHead>
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
                    <TableCell className="max-w-80 truncate" title={e.original_filename}>
                      <Link className="hover:underline" href={orgPath(orgId, `evidence/${e.id}`)}>
                        {e.original_filename}
                      </Link>
                      {e.status === "archived" && (
                        <Badge variant="outline" className="ml-2">
                          archived
                        </Badge>
                      )}
                      <EvidenceExclusionBadges evidence={e} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{formatBytes(e.size_bytes)}</TableCell>
                    <TableCell>{e.hashes.sha256 && <HashValue value={e.hashes.sha256} short />}</TableCell>
                    <TableCell title={uploaded.utc} className="text-muted-foreground">
                      {uploaded.local}
                      <span className="block text-xs">{e.uploaded_by_name}</span>
                    </TableCell>
                    <TableCell>
                      <EvidenceSharePolicyButton
                        orgId={orgId}
                        evidenceId={e.id}
                        investigationId={inv.id}
                        filename={e.original_filename}
                        tlpRed={inv.tlp === "red"}
                        readOnly={archived}
                      />
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
      </CardContent>
    </Card>
  );
}
