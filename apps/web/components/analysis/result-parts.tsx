"use client";

import { Check, ChevronDown, ChevronRight, Copy, Network } from "lucide-react";
import { type ReactNode, useState } from "react";

import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { formatDate } from "@/lib/format";
import { type DetailField, type FlowLink, endpointText } from "@/lib/pcap-results";
import { cn } from "@/lib/utils";

export { PAGE_SIZE };
export const ALL = "all";

/**
 * Untrusted text (domains, URIs, user agents, cert subjects, signatures…): rendered as plain
 * text, never linked, cut with an ellipsis and the full value in the title tooltip.
 */
export function Trunc({ value, className, mono }: { value: string | null | undefined; className?: string; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return <span className="text-muted-foreground">—</span>;
  return (
    <span className={cn("block max-w-64 truncate", mono && "font-mono text-xs", className)} title={value}>
      {value}
    </span>
  );
}

export function When({ iso }: { iso: string | null | undefined }) {
  if (!iso) return <span className="text-muted-foreground">—</span>;
  const when = formatDate(iso);
  return (
    <span className="text-muted-foreground" title={when.utc}>
      {when.local}
    </span>
  );
}

type Ends = { src_ip: string | null; src_port: number | null; dst_ip: string | null; dst_port: number | null };

/** "src:port → dst:port" as text (addresses are analyzer output, shown verbatim). */
export function Endpoints({ e, className }: { e: Ends; className?: string }) {
  const src = endpointText(e.src_ip, e.src_port);
  const dst = endpointText(e.dst_ip, e.dst_port);
  return (
    <span className={cn("block max-w-80 truncate font-mono text-xs", className)} title={`${src} → ${dst}`}>
      {src} <span className="text-muted-foreground">→</span> {dst}
    </span>
  );
}

export function CopyButton({ value, label = "Copy value" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable (insecure context / permission): the value stays selectable
    }
  }
  return (
    <>
      <Button variant="ghost" size="icon" className="size-6 shrink-0" aria-label={label} title={label} onClick={copy}>
        {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      </Button>
      <span className="sr-only" aria-live="polite">
        {copied ? "Copied" : ""}
      </span>
    </>
  );
}

/** Button that opens the Flows tab narrowed to a flow (see `flowLinkFor`). */
export function FlowButton({
  link,
  onShowFlow,
  label = "Flow",
  title,
}: {
  link: FlowLink;
  onShowFlow: (link: FlowLink) => void;
  label?: ReactNode;
  title?: string;
}) {
  if (!link.ip && link.port === undefined && !link.ref) return null;
  const hint = title ?? (link.ref ? `Show flow ${link.ref}` : "Show matching flows");
  return (
    <Button
      variant="ghost"
      size="sm"
      className="h-6 gap-1 px-1.5 text-xs"
      title={hint}
      aria-label={label ? undefined : hint}
      onClick={() => onShowFlow(link)}
    >
      <Network className="size-3.5" aria-hidden />
      {label}
    </Button>
  );
}

export function FilterSelect<T extends string>({
  value,
  onChange,
  options,
  allLabel,
  label,
  className,
}: {
  value: T | typeof ALL;
  onChange: (value: T | typeof ALL) => void;
  options: readonly (readonly [T, string])[];
  allLabel: string;
  label: string;
  className?: string;
}) {
  return (
    <Select value={value} onValueChange={(next) => onChange(next as T | typeof ALL)}>
      <SelectTrigger className={cn("w-44", className)} aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{allLabel}</SelectItem>
        {options.map(([option, text]) => (
          <SelectItem key={option} value={option}>
            {text}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/**
 * Page offset that resets to 0 whenever the (debounced) filters change, without an effect:
 * the offset is remembered together with the filter key it belongs to.
 */
export function usePageOffset(filterKey: string): [number, (offset: number) => void] {
  const [state, setState] = useState({ key: filterKey, offset: 0 });
  const offset = state.key === filterKey ? state.offset : 0;
  return [offset, (next) => setState({ key: filterKey, offset: next })];
}

type PageQuery<T> = {
  isPending: boolean;
  isError: boolean;
  error: unknown;
  refetch: () => unknown;
  data?: { items: T[]; total: number };
};

/**
 * Filters, error (with Retry), table with loading / empty rows, and the pager for one
 * paginated result list.
 */
export function ResultTable<T>({
  filters,
  query,
  offset,
  onOffset,
  head,
  columns,
  empty,
  children,
  note,
}: {
  filters?: ReactNode;
  query: PageQuery<T>;
  offset: number;
  onOffset: (offset: number) => void;
  head: ReactNode;
  columns: number;
  empty: string;
  children: (items: T[]) => ReactNode;
  note?: ReactNode;
}) {
  const items = query.data?.items;
  return (
    <div className="flex min-w-0 flex-col gap-3">
      {filters && <div className="flex flex-wrap items-start gap-2">{filters}</div>}
      {note}
      {query.isError && <QueryError error={query.error} onRetry={() => void query.refetch()} />}
      {/* min-w-0: wide tables scroll inside their card instead of widening the page */}
      <div className="min-w-0 rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>{head}</TableRow>
          </TableHeader>
          <TableBody>
            {query.isPending && !query.isError && (
              <TableRow>
                <TableCell colSpan={columns} className="py-8 text-center text-muted-foreground">
                  Loading…
                </TableCell>
              </TableRow>
            )}
            {items && children(items)}
            {items?.length === 0 && (
              <TableRow>
                <TableCell colSpan={columns} className="py-10 text-center whitespace-normal text-muted-foreground">
                  {empty}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <Pager offset={offset} total={query.data?.total ?? 0} onChange={onOffset} />
    </div>
  );
}

/** A table row with a disclosure toggle; the detail row spans the whole table when open. */
export function ExpandableRow({
  cells,
  detail,
  columns,
  className,
}: {
  cells: ReactNode;
  detail: ReactNode;
  columns: number;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <TableRow className={className} data-state={open ? "selected" : undefined}>
        <TableCell className="w-8">
          <Button
            variant="ghost"
            size="icon"
            className="size-6"
            aria-expanded={open}
            aria-label={open ? "Hide details" : "Show details"}
            onClick={() => setOpen(!open)}
          >
            {open ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
          </Button>
        </TableCell>
        {cells}
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={columns} className="px-4 py-3 whitespace-normal">
            {detail}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

/** Label / value list; values wrap (full text, never linked). */
export function FieldList({ fields }: { fields: readonly DetailField[] }) {
  if (fields.length === 0) return <p className="text-sm text-muted-foreground">No details recorded.</p>;
  return (
    <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-sm">
      {fields.map((field) => (
        <div key={field.key} className="contents">
          <dt className="text-muted-foreground">{field.label}</dt>
          <dd className={cn("min-w-0 break-all", field.format === "mono" && "font-mono text-xs")}>
            {field.format === "date" ? <When iso={field.value} /> : field.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function NoResults({ status }: { status: string }) {
  return (
    <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">
      {status === "failed"
        ? "This analysis failed; no results were recorded."
        : status === "succeeded"
          ? "Results will appear here once the analysis has been ingested."
          : "Results will appear here once the analysis finishes and has been ingested."}
    </p>
  );
}
