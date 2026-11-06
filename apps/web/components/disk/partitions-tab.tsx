"use client";

import { InertText } from "@/components/disk/inert-text";
import { QueryError } from "@/components/query-error";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FS_STATUS_TEXT, type DiskPartition, PARTITION_OS_LABELS, formatU64, formatU64Bytes, sectorBytes } from "@/lib/disk";
import { formatCount } from "@/lib/pcap-results";
import { useDiskPartitions } from "@/lib/use-disk-job";
import { cn } from "@/lib/utils";

const FS_STYLE: Record<string, string> = {
  ok: "",
  truncated: "border-amber-500/60",
  unsupported: "border-amber-500/60",
  encrypted: "border-amber-500/60",
  undetermined: "",
  error: "border-destructive/50 text-destructive",
};

/** The `fs_status` badge with its plain-words explanation in the tooltip and for screen readers. */
export function FsStatusBadge({ status }: { status: DiskPartition["fs_status"] }) {
  const text = FS_STATUS_TEXT[status] ?? { label: status, detail: "" };
  return (
    <Badge variant="outline" className={cn("font-normal", FS_STYLE[status])} title={text.detail}>
      {text.label}
      <span className="sr-only">: {text.detail}</span>
    </Badge>
  );
}

/** The partition table (pure; tested without queries). Sector values are u64 text. */
export function PartitionTable({ partitions, sectorSize }: { partitions: readonly DiskPartition[]; sectorSize: number | null }) {
  const unreadable = partitions.filter((p) => p.fs_status === "encrypted" || p.fs_status === "unsupported");
  return (
    <div className="flex flex-col gap-3">
      {unreadable.length > 0 ? (
        <ul className="flex flex-col gap-1 text-sm text-muted-foreground">
          {unreadable.map((p) => (
            <li key={p.id}>
              Partition {p.index}: {FS_STATUS_TEXT[p.fs_status].detail}
            </li>
          ))}
        </ul>
      ) : null}
      <div className="min-w-0 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">#</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="text-right">Start sector</TableHead>
              <TableHead className="text-right">Size</TableHead>
              <TableHead>File system</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>OS</TableHead>
              <TableHead>Label</TableHead>
              <TableHead className="text-right">Files</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {partitions.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="py-8 text-center text-muted-foreground">
                  No partitions were recorded.
                </TableCell>
              </TableRow>
            ) : (
              partitions.map((p) => {
                const bytes = sectorBytes(p.length_sectors, sectorSize);
                const files = p.counts?.files;
                return (
                  <TableRow key={p.id}>
                    <TableCell className="tabular-nums">{p.index}</TableCell>
                    <TableCell className="max-w-56">
                      <InertText value={p.description} />
                      <InertText value={p.vs_flags} className="text-xs text-muted-foreground" />
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{formatU64(p.start_sector)}</TableCell>
                    <TableCell className="text-right tabular-nums" title={`${formatU64(p.length_sectors)} sectors`}>
                      {bytes ? formatU64Bytes(bytes) : `${formatU64(p.length_sectors)} sectors`}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{p.fs_type ?? "—"}</TableCell>
                    <TableCell>
                      <FsStatusBadge status={p.fs_status} />
                      {p.error_code ? <span className="ml-1 font-mono text-xs text-muted-foreground">({p.error_code})</span> : null}
                    </TableCell>
                    <TableCell className="max-w-48">
                      {PARTITION_OS_LABELS[p.os]}
                      {p.os_name ? <InertText value={p.os_name} className="text-xs text-muted-foreground" /> : null}
                    </TableCell>
                    <TableCell className="max-w-40">
                      <InertText value={p.fs_label} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{typeof files === "number" ? formatCount(files) : "—"}</TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export function PartitionsTab({ orgId, jobId, sectorSize }: { orgId: string; jobId: string; sectorSize: number | null }) {
  const query = useDiskPartitions(orgId, jobId, true);
  if (query.isError) return <QueryError error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <p className="text-sm text-muted-foreground">Loading partitions…</p>;
  return <PartitionTable partitions={query.data.items} sectorSize={sectorSize} />;
}
