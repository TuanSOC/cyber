"use client";

import type { Schemas } from "@cyberlab/contracts";
import { Search } from "lucide-react";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { STATUS_LABELS } from "@/lib/format";

export const ALL = "all";
export const SORTS = {
  "-created_at": "Newest",
  created_at: "Oldest",
  "-severity": "Most severe",
  severity: "Least severe",
} as const satisfies Record<Schemas["SortKey"], string>;

export type Filters = {
  q: string;
  status: Schemas["InvestigationStatus"] | typeof ALL;
  severity: Schemas["Severity"] | typeof ALL;
  sort: Schemas["SortKey"];
};

const SEVERITIES: Schemas["Severity"][] = ["low", "medium", "high", "critical"];

export function InvestigationFilters({
  value,
  onChange,
}: {
  value: Filters;
  onChange: (next: Filters) => void;
}) {
  const set = <K extends keyof Filters>(key: K, v: Filters[K]) => onChange({ ...value, [key]: v });
  return (
    <div className="mb-4 flex flex-wrap items-center gap-2">
      <div className="relative w-full max-w-xs">
        <Search className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" aria-hidden />
        <Input
          aria-label="Search by title or case number"
          placeholder="Search title or CASE-00012"
          className="pl-8"
          maxLength={200}
          value={value.q}
          onChange={(event) => set("q", event.target.value)}
        />
      </div>
      <Select value={value.status} onValueChange={(v) => set("status", v as Filters["status"])}>
        <SelectTrigger className="w-36" aria-label="Status filter">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All statuses</SelectItem>
          {Object.entries(STATUS_LABELS).map(([status, label]) => (
            <SelectItem key={status} value={status}>
              {label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={value.severity} onValueChange={(v) => set("severity", v as Filters["severity"])}>
        <SelectTrigger className="w-36" aria-label="Severity filter">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All severities</SelectItem>
          {SEVERITIES.map((s) => (
            <SelectItem key={s} value={s} className="capitalize">
              {s}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={value.sort} onValueChange={(v) => set("sort", v as Filters["sort"])}>
        <SelectTrigger className="w-40" aria-label="Sort order">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {Object.entries(SORTS).map(([sort, label]) => (
            <SelectItem key={sort} value={sort}>
              {label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
