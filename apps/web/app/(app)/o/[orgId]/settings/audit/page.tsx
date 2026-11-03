"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Fragment, useDeferredValue, useState } from "react";

import { PAGE_SIZE, Pager } from "@/components/pager";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { useOrg } from "@/lib/org-context";

/** `<input type="date">` value -> start of that day in the viewer's timezone, as ISO. */
function dayStart(value: string, plusDays = 0): string | undefined {
  if (!value) return undefined;
  const date = new Date(`${value}T00:00:00`);
  date.setDate(date.getDate() + plusDays);
  return date.toISOString();
}

export default function AuditLogPage() {
  const { orgId, can } = useOrg();
  const [action, setAction] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const deferredAction = useDeferredValue(action.trim());

  const query = {
    action: deferredAction || undefined,
    from: dayStart(from),
    to: dayStart(to, 1),
    limit: PAGE_SIZE,
    offset,
  };
  const logs = useQuery({
    queryKey: ["org", orgId, "audit", query],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/audit-logs", {
          params: { path: { org_id: orgId }, query },
        }),
      ),
    placeholderData: keepPreviousData,
    enabled: can("audit.read"),
  });

  if (!can("audit.read")) {
    return <p className="text-sm text-muted-foreground">Only owners and admins can view the audit log.</p>;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="audit-action">Action</Label>
          <Input
            id="audit-action"
            placeholder="e.g. evidence.downloaded"
            className="w-60"
            maxLength={100}
            value={action}
            onChange={(event) => {
              setAction(event.target.value);
              setOffset(0);
            }}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="audit-from">From</Label>
          <Input id="audit-from" type="date" value={from} onChange={(e) => { setFrom(e.target.value); setOffset(0); }} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="audit-to">To</Label>
          <Input id="audit-to" type="date" value={to} onChange={(e) => { setTo(e.target.value); setOffset(0); }} />
        </div>
      </div>
      {logs.isError && <p className="text-sm text-destructive">Could not load the audit log.</p>}
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-44">When</TableHead>
              <TableHead className="w-52">Action</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead className="w-32">IP</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.data?.items.map((log) => {
              const when = formatDate(log.occurred_at);
              const expanded = open === log.id;
              return (
                <Fragment key={log.id}>
                  <TableRow>
                    <TableCell title={when.utc} className="text-muted-foreground">{when.local}</TableCell>
                    <TableCell className="font-mono text-xs">{log.action}</TableCell>
                    <TableCell className="max-w-64 truncate" title={log.actor_email ?? ""}>
                      {log.actor_email ?? "system"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{log.ip ?? "—"}</TableCell>
                    <TableCell>
                      <button
                        type="button"
                        className="text-xs text-muted-foreground underline-offset-4 hover:underline"
                        aria-expanded={expanded}
                        onClick={() => setOpen(expanded ? null : log.id)}
                      >
                        {expanded ? "Hide" : "Details"}
                      </button>
                    </TableCell>
                  </TableRow>
                  {expanded && (
                    <TableRow>
                      <TableCell colSpan={5}>
                        <pre className="overflow-x-auto rounded bg-muted p-3 text-xs">
                          {JSON.stringify(
                            { target_type: log.target_type, target_id: log.target_id, ...log.details },
                            null,
                            2,
                          )}
                        </pre>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              );
            })}
            {logs.data?.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  No audit events match.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <Pager offset={offset} total={logs.data?.total ?? 0} onChange={setOffset} />
    </div>
  );
}
