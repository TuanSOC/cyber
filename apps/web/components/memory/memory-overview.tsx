import { HashValue } from "@/components/hash-value";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MEMORY_PROFILE_LABELS } from "@/lib/analysis";
import { formatBytes, formatDate } from "@/lib/format";
import { MEMORY_OS_LABELS, type MemorySummary, bannerText, summaryCounts } from "@/lib/memory";
import { formatCount } from "@/lib/pcap-results";

/** "Replay engine" label (test profile only: hand-written plugin rows, not a real analysis). */
export function EngineLabel({ engine }: { engine: string | null | undefined }) {
  if (engine !== "replay") return null;
  return (
    <Badge variant="destructive" title="Test profile only: plugin rows were replayed from a fixture, not produced by Volatility.">
      Replay engine (test)
    </Badge>
  );
}

/**
 * Image facts (trusted hashes from the evidence record), the versions that ran and headline
 * counts (the plugin status strip sits above the tabs). Every value is text.
 */
export function MemoryOverview({ summary }: { summary: MemorySummary }) {
  const time = summary.system_time ? formatDate(summary.system_time) : null;
  const banner = bannerText(summary.symbols.linux_banner?.banner);
  const facts: [string, string][] = [
    ["Operating system", MEMORY_OS_LABELS[summary.os] ?? summary.os],
    ["Profile", MEMORY_PROFILE_LABELS[summary.profile] ?? summary.profile],
    ["Architecture", summary.arch ?? "—"],
    ["Layers", summary.layer ?? "—"],
    ["Windows build", summary.nt_build ?? "—"],
    ["Image size", formatBytes(summary.size_bytes)],
    ["Symbols", summary.symbols.status === "resolved" ? "Resolved" : "Missing"],
  ];
  const versions = Object.entries(summary.tool_versions ?? {});
  const counts = summaryCounts(summary.counts);
  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            Image <EngineLabel engine={summary.engine} />
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 text-sm lg:grid-cols-2">
          <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1">
            {facts.map(([label, value]) => (
              <div key={label} className="contents">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="min-w-0 break-all">{value}</dd>
              </div>
            ))}
            <dt className="text-muted-foreground">System time</dt>
            <dd title={time?.utc}>{time?.local ?? "—"}</dd>
          </dl>
          <div className="flex min-w-0 flex-col gap-3">
            <div>
              <p className="text-xs text-muted-foreground uppercase">sha256 (evidence record)</p>
              <HashValue value={summary.sha256} />
            </div>
            {banner ? (
              <div>
                <p className="text-xs text-muted-foreground">Kernel banner (from the image)</p>
                <p className="font-mono text-xs break-all whitespace-pre-wrap">“{banner}”</p>
              </div>
            ) : null}
            {summary.symbols.isf_sha256 ? (
              <div>
                <p className="text-xs text-muted-foreground">Symbol table used (sha256)</p>
                <HashValue value={summary.symbols.isf_sha256} />
              </div>
            ) : null}
            {versions.length > 0 ? (
              <div>
                <p className="text-xs text-muted-foreground">Versions</p>
                <ul className="text-xs">
                  {versions.map(([name, version]) => (
                    <li key={name} className="break-all">
                      <span className="font-mono">{name}</span> {String(version)}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Recovered</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {counts.length > 0 ? (
            <p className="text-sm tabular-nums">
              {counts.map((row, index) => (
                <span key={row.key}>
                  {index > 0 && <span className="text-muted-foreground"> · </span>}
                  {formatCount(row.value)} {row.label}
                </span>
              ))}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">No counts recorded.</p>
          )}
          {summary.engine_errors.length > 0 ? (
            <p className="text-xs text-muted-foreground">
              Engine notes: <span className="font-mono">{summary.engine_errors.join(", ")}</span>
            </p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
