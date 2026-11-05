import Link from "next/link";

import {
  type AiContextStats,
  type AiInclusions,
  INCLUSION_LABELS,
  categoryLabel,
  contextTruncationNotes,
  kindCountRows,
  pseudonymizationText,
} from "@/lib/ai";
import { orgPath } from "@/lib/nav";

/**
 * What a context holds: included / total per kind, truncation and pseudonymization counts,
 * the data categories that leave the platform and the inclusion toggles in effect.
 */
export function ContextSummary({
  orgId,
  stats,
  inclusions,
  categories,
  canManage = false,
}: {
  orgId: string;
  stats: AiContextStats | null | undefined;
  inclusions?: AiInclusions;
  categories?: readonly string[];
  canManage?: boolean;
}) {
  const rows = kindCountRows(stats);
  const notes = contextTruncationNotes(stats);
  const pseudonyms = pseudonymizationText(stats);
  return (
    <div className="flex flex-col gap-3 text-sm">
      {rows.length > 0 && (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-muted-foreground">
              <th className="py-1 font-medium">Kind</th>
              <th className="py-1 text-right font-medium">Included / total</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.kind} className="border-t">
                <td className="py-1">{row.label}</td>
                <td className="py-1 text-right tabular-nums">
                  {row.included} / {row.total}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {stats && stats.est_tokens > 0 && (
        <p className="text-xs text-muted-foreground">About {stats.est_tokens.toLocaleString("en-US")} input tokens.</p>
      )}
      {notes.map((note) => (
        <p key={note} className="text-xs text-muted-foreground">
          {note}
        </p>
      ))}
      <p className="text-xs text-muted-foreground">{pseudonyms ?? "No internal names were pseudonymized."}</p>
      {stats && stats.neutralized > 0 && (
        <p className="text-xs text-muted-foreground">
          {stats.neutralized} pseudonym-shaped tokens already in the evidence were neutralized first.
        </p>
      )}
      {categories && categories.length > 0 && (
        <p className="text-xs">
          <span className="text-muted-foreground">Data that leaves the platform: </span>
          {categories.map(categoryLabel).join(", ")}
        </p>
      )}
      {inclusions && (
        <div className="flex flex-col gap-1 text-xs">
          <span className="text-muted-foreground">Settings in effect (read-only here)</span>
          <ul className="flex flex-col gap-0.5">
            {INCLUSION_LABELS.map(([key, label]) => (
              <li key={key}>
                {label}: <span className="font-medium">{inclusions[key] ? "on" : "off"}</span>
              </li>
            ))}
          </ul>
          {canManage && (
            <Link
              href={orgPath(orgId, "settings/integrations")}
              className="self-start text-primary underline-offset-4 hover:underline"
            >
              Change in Integrations
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
