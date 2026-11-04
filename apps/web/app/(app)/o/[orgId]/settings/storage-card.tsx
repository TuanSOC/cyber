"use client";

import { useQuery } from "@tanstack/react-query";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api, errorMessage, unwrap } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";

/** Evidence storage of the org: active + archived evidence against the org's quota. */
export function StorageCard({ orgId }: { orgId: string }) {
  const storage = useQuery({
    queryKey: ["org", orgId, "storage"],
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/storage", { params: { path: { org_id: orgId } } })),
  });

  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle>Storage</CardTitle>
        <CardDescription>
          Evidence storage used by this organization. Archived evidence stays retention-locked, so it
          still counts towards the quota.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {storage.isPending && <Skeleton className="h-12 w-full" />}
        {storage.isError && <p className="text-sm text-destructive">{errorMessage(storage.error)}</p>}
        {storage.data && <Usage {...storage.data} />}
      </CardContent>
    </Card>
  );
}

function Usage({
  used_bytes: used,
  quota_bytes: quota,
  evidence_count: count,
}: {
  used_bytes: number;
  quota_bytes: number;
  evidence_count: number;
}) {
  const percent = quota > 0 ? Math.min(100, (used / quota) * 100) : 100;
  const full = used >= quota;
  const tone = full ? "bg-destructive" : percent >= 90 ? "bg-sev-medium" : "bg-primary";

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-4 text-sm">
        <span>
          <span className="font-medium">{formatBytes(used)}</span>
          <span className="text-muted-foreground"> of {formatBytes(quota)} used</span>
        </span>
        <span className="text-muted-foreground tabular-nums">{Math.floor(percent)}%</span>
      </div>
      <div
        className="h-2 overflow-hidden rounded bg-muted"
        role="progressbar"
        aria-label="Storage used"
        aria-valuenow={Math.floor(percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={`${formatBytes(used)} of ${formatBytes(quota)}`}
      >
        <div className={cn("h-full transition-all", tone)} style={{ width: `${percent}%` }} />
      </div>
      <p className="text-xs text-muted-foreground">
        {count} evidence {count === 1 ? "file" : "files"}
        {full && " · Quota reached: new uploads are rejected until the quota is raised."}
      </p>
    </div>
  );
}
