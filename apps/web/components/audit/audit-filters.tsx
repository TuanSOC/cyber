"use client";

import { useQuery } from "@tanstack/react-query";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, unwrap } from "@/lib/api";
import { AUDIT_ACTIONS } from "@/lib/audit-actions";

export const ANY = "any";
export type AuditFilterValues = { action: string; actorId: string; from: string; to: string };

export function AuditFilters({
  orgId,
  value,
  onChange,
}: {
  orgId: string;
  value: AuditFilterValues;
  onChange: (next: AuditFilterValues) => void;
}) {
  const members = useQuery({
    queryKey: ["org", orgId, "members"],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/members", {
          params: { path: { org_id: orgId }, query: { limit: 100 } },
        }),
      ),
  });
  const set = (key: keyof AuditFilterValues, v: string) => onChange({ ...value, [key]: v });

  return (
    <div className="flex flex-wrap items-end gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="audit-action">Action</Label>
        <Select value={value.action} onValueChange={(v) => set("action", v)}>
          <SelectTrigger id="audit-action" className="w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Any action</SelectItem>
            {AUDIT_ACTIONS.map((action) => (
              <SelectItem key={action} value={action} className="font-mono text-xs">
                {action}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="audit-actor">Actor</Label>
        <Select value={value.actorId} onValueChange={(v) => set("actorId", v)}>
          <SelectTrigger id="audit-actor" className="w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Anyone</SelectItem>
            {members.data?.items.map((m) => (
              <SelectItem key={m.user_id} value={m.user_id}>
                {m.email}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="audit-from">From</Label>
        <Input id="audit-from" type="date" value={value.from} onChange={(e) => set("from", e.target.value)} />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="audit-to">To</Label>
        <Input id="audit-to" type="date" value={value.to} onChange={(e) => set("to", e.target.value)} />
      </div>
    </div>
  );
}
