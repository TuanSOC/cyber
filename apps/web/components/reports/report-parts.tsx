"use client";

import { type ReactNode, createContext, useContext, useState } from "react";

import { RText } from "@/components/reports/report-text";
import { type Severity, SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { formatCount } from "@/lib/pcap-results";
import { truncationNote } from "@/lib/report-format";

/*
 * Building blocks of the report viewer. Every data value goes through `RText` (a text node);
 * ids, classes and anchors are built from constants and integers only.
 */

export const citeAnchor = (n: number) => `rs-cite-${Math.trunc(n)}`;

type CiteContextValue = { open: (n: number) => void; known: ReadonlySet<number> };

const CiteContext = createContext<CiteContextValue>({ open: () => {}, known: new Set() });
export const CiteProvider = CiteContext.Provider;

/** Open an appendix entry (a `<details>`), scroll to it and move focus to its summary. */
export function openCitation(n: number): void {
  const element = document.getElementById(citeAnchor(n));
  if (!element) return;
  if (element instanceof HTMLDetailsElement) element.open = true;
  element.scrollIntoView({ block: "center" });
  element.querySelector<HTMLElement>("summary")?.focus();
}

/** `[C12]` superscripts: buttons that open the citation appendix entry. */
export function Cites({ nos }: { nos: readonly (number | null | undefined)[] }) {
  const { open, known } = useContext(CiteContext);
  const numbers = nos.filter((n): n is number => typeof n === "number" && Number.isInteger(n) && n > 0);
  if (numbers.length === 0) return null;
  return (
    <sup className="ml-0.5 inline-flex flex-wrap gap-0.5">
      {numbers.map((n, index) => (
        <button
          key={`${n}-${index}`}
          type="button"
          data-cite={n}
          className="font-mono text-[10px] text-primary underline-offset-2 hover:underline disabled:text-muted-foreground disabled:no-underline"
          aria-label={`Citation ${n}${known.has(n) ? "" : " (not in the appendix)"}`}
          disabled={!known.has(n)}
          onClick={() => open(n)}
        >
          [C{n}]
        </button>
      ))}
    </sup>
  );
}

export function ReportSection({
  id,
  title,
  note,
  children,
}: {
  id: string;
  title: string;
  note?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="mt-10 print:mt-6">
      <h2 id={id} className="mb-3 scroll-mt-16 border-b pb-1 text-lg font-semibold">
        {title}
      </h2>
      {note ? <div className="mb-2 text-xs text-muted-foreground">{note}</div> : null}
      {children}
    </section>
  );
}

export function SubSection({ title, note, children }: { title: string; note?: ReactNode; children: ReactNode }) {
  return (
    <div className="mt-5">
      <h3 className="mb-2 text-base font-semibold">{title}</h3>
      {note ? <div className="mb-2 text-xs text-muted-foreground">{note}</div> : null}
      {children}
    </div>
  );
}

export function Facts({ rows }: { rows: readonly (readonly [string, ReactNode])[] }) {
  return (
    <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-6 gap-y-1 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Long tables show this many rows first, with a "Show all" button. */
export const ROW_LIMIT = 100;

export function DataTable({
  caption,
  head,
  rows,
  empty,
  limit = ROW_LIMIT,
}: {
  caption: string;
  head: readonly string[];
  rows: readonly ReactNode[][];
  empty: string;
  limit?: number;
}) {
  const [all, setAll] = useState(false);
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const shown = all ? rows : rows.slice(0, limit);
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="border-b px-2 py-1 text-left font-medium text-muted-foreground">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {shown.map((cells, index) => (
            <tr key={index} className="break-inside-avoid border-b align-top">
              {cells.map((cell, i) =>
                i === 0 ? (
                  <th key={i} scope="row" className="px-2 py-1 text-left font-normal">
                    {cell}
                  </th>
                ) : (
                  <td key={i} className="px-2 py-1">
                    {cell}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > shown.length ? (
        <Button variant="outline" size="sm" className="mt-2 print:hidden" onClick={() => setAll(true)}>
          Show all {formatCount(rows.length)} rows
        </Button>
      ) : null}
    </div>
  );
}

export function Truncation({ included, total }: { included: number; total: number }) {
  const note = truncationNote(included, total);
  return note ? <p className="mb-2 text-xs text-muted-foreground">{note} The rest was capped when the version was built.</p> : null;
}

const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);

export function SevText({ value }: { value: string | null | undefined }) {
  if (value && SEVERITIES.has(value)) return <SeverityBadge severity={value as Severity} />;
  return <RText value={value} />;
}

export function Badge({ children, tone = "muted" }: { children: ReactNode; tone?: "muted" | "warn" }) {
  return (
    <span
      className={
        tone === "warn"
          ? "inline-flex items-center rounded border border-amber-500/50 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-800 dark:text-amber-300"
          : "inline-flex items-center rounded border bg-muted px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground"
      }
    >
      {children}
    </span>
  );
}
