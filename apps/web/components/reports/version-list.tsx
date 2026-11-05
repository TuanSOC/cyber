import Link from "next/link";

import { TlpBadge } from "@/components/tlp/tlp-badge";
import { formatUtc, reportsHref, shortSha, vis } from "@/lib/report-format";
import { PROFILE_TEXT, type ReportVersion } from "@/lib/reports";
import { cn } from "@/lib/utils";

/** The signed versions of a report, newest first, each linking to its viewer. */
export function VersionList({
  orgId,
  reportId,
  versions,
  current,
}: {
  orgId: string;
  reportId: string;
  versions: readonly ReportVersion[];
  current?: number;
}) {
  const sorted = [...versions].sort((a, b) => b.version - a.version);
  return (
    <section aria-labelledby="report-versions-h" className="rounded-md border p-3">
      <h2 id="report-versions-h" className="mb-2 text-sm font-semibold">
        Signed versions
      </h2>
      {sorted.length === 0 ? <p className="text-xs text-muted-foreground">None yet. Finalize the draft to create v1.</p> : null}
      <ol className="flex flex-col gap-2">
        {sorted.map((version) => (
          <li key={version.id} className={cn("rounded-md p-2 text-xs", current === version.version && "bg-muted")}>
            <Link
              href={reportsHref(orgId, reportId, version.version)}
              aria-current={current === version.version ? "page" : undefined}
              className="font-medium underline-offset-4 hover:underline"
            >
              Version {version.version}
            </Link>
            <span className="ml-2 inline-block align-middle">
              <TlpBadge tlp={version.tlp} />
            </span>
            <span className="block text-muted-foreground">
              {formatUtc(version.finalized_at)} · {vis(version.finalized_by_name)} · {PROFILE_TEXT[version.profile]?.label ?? version.profile}
            </span>
            <span className="block font-mono text-muted-foreground">{shortSha(version.snapshot_sha256)}</span>
            {version.change_note ? (
              <span className="block break-words whitespace-pre-wrap">{vis(version.change_note)}</span>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  );
}
