import { CheckCircle2, CircleSlash, Copy, XCircle } from "lucide-react";

import { TlpBadge } from "@/components/tlp/tlp-badge";
import { visText } from "@/lib/case";
import {
  type IocItemsAddResult,
  type IocItemManual,
  addSummary,
  defang,
  iocDisplay,
  itemOutcomeText,
} from "@/lib/ioc-collections";
import type { Tlp } from "@/lib/tlp";

/*
 * Presentational parts of the IOC tab. Values are attacker-controlled: text only, defanged by
 * default, never a link.
 */

/** An IOC value as text: defanged unless revealed; invisible characters made visible. */
export function IocValue({ value, type, reveal }: { value: string; type: string; reveal: boolean }) {
  const shown = visText(iocDisplay(value, type, reveal));
  return (
    <span className="font-mono text-xs break-all" title={shown}>
      {shown}
    </span>
  );
}

/** Copies the clear value (never opened). */
export function CopyValue({ value }: { value: string }) {
  return (
    <button
      type="button"
      className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
      aria-label="Copy value"
      title="Copy value"
      onClick={() => void navigator.clipboard?.writeText(value)}
    >
      <Copy className="size-3" aria-hidden />
    </button>
  );
}

const OUTCOME_ICON = { added: CheckCircle2, duplicate: CircleSlash, invalid: XCircle } as const;

/** Per-item results of an add: `added / duplicate / invalid(reason)` next to the submitted value. */
export function AddResultList({
  result,
  submitted,
}: {
  result: IocItemsAddResult;
  submitted: readonly (IocItemManual | { ioc_id: string })[];
}) {
  return (
    <div className="flex flex-col gap-1 rounded-md border p-2 text-xs" role="status">
      <p className="font-medium">{addSummary(result)}</p>
      <ul className="flex max-h-48 flex-col gap-0.5 overflow-y-auto">
        {result.results.map((r) => {
          const item = submitted[r.index];
          const label = item && "value" in item ? `${item.type} ${defang(item.value, item.type)}` : `item ${r.index + 1}`;
          const Icon = OUTCOME_ICON[r.outcome];
          return (
            <li key={r.index} className="flex items-start gap-1.5">
              <Icon className="mt-0.5 size-3 shrink-0" aria-hidden />
              <span className="min-w-0 font-mono break-all">{visText(label)}</span>
              <span className="shrink-0 text-muted-foreground">— {itemOutcomeText(r)}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** The case TLP and the "not redacted" warning shown next to every export (RT8). */
export function ExportNotice({ tlp }: { tlp: Tlp }) {
  return (
    <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <TlpBadge tlp={tlp} />
      <span>Exports carry the case TLP and are not redacted: internal addresses stay in clear.</span>
    </span>
  );
}
