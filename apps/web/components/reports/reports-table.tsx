import Link from "next/link";

import { When } from "@/components/analysis/result-parts";
import { TlpBadge } from "@/components/tlp/tlp-badge";
import { reportsHref, vis } from "@/lib/report-format";
import type { Report } from "@/lib/reports";

/** Reports as a table: case, title, TLP, latest version, updated, status. */
export function ReportsTable({
  orgId,
  reports,
  showCase = true,
}: {
  orgId: string;
  reports: readonly Report[];
  showCase?: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full border-collapse text-sm">
        <caption className="sr-only">Reports</caption>
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th scope="col" className="px-3 py-2 font-medium">
              Title
            </th>
            {showCase ? (
              <th scope="col" className="px-3 py-2 font-medium">
                Case
              </th>
            ) : null}
            <th scope="col" className="px-3 py-2 font-medium">
              TLP
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Latest version
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Updated
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          {reports.map((report) => (
            <tr key={report.id} className="border-b last:border-b-0 align-top">
              <th scope="row" className="px-3 py-2 text-left font-normal">
                <Link href={reportsHref(orgId, report.id)} className="font-medium underline-offset-4 hover:underline">
                  {vis(report.title)}
                </Link>
                <span className="block text-xs text-muted-foreground">by {vis(report.created_by_name)}</span>
              </th>
              {showCase ? <td className="px-3 py-2 font-mono text-xs">{report.case_ref}</td> : null}
              <td className="px-3 py-2">
                <TlpBadge tlp={report.tlp} />
              </td>
              <td className="px-3 py-2">
                {report.latest ? (
                  <Link
                    href={reportsHref(orgId, report.id, report.latest.version)}
                    className="underline-offset-4 hover:underline"
                  >
                    v{report.latest.version}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">none yet</span>
                )}
              </td>
              <td className="px-3 py-2 text-xs">
                <When iso={report.updated_at} />
              </td>
              <td className="px-3 py-2 text-xs">{report.status === "discarded" ? "Discarded" : "Draft"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
