"use client";

import { TriangleAlert } from "lucide-react";

import { CopyButton, FlowButton, Trunc, When } from "@/components/analysis/result-parts";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { type AnalysisJob, formatDuration, hasSummary, isActiveStatus } from "@/lib/analysis";
import { formatBytes, shortHash } from "@/lib/format";
import {
  type FlowLink,
  type HostStat,
  engineErrorText,
  formatCount,
  parseOverview,
  protocolTree,
  truncationText,
} from "@/lib/pcap-results";

const TOOL_LABELS: Record<string, string> = {
  zeek: "Zeek",
  tshark: "TShark",
  suricata: "Suricata",
  rules_sha256: "ET Open rules (sha256)",
};

/**
 * Overview of the analysis summary. Every value is untrusted analyzer output (protocol paths,
 * link type, tool versions included): plain text only, truncated with the full value in a tooltip.
 */
export function AnalysisOverview({
  job,
  onShowFlows,
}: {
  job: AnalysisJob;
  onShowFlows?: (link: FlowLink) => void;
}) {
  if (job.status !== "succeeded" || !hasSummary(job.summary)) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {job.status === "failed"
              ? "This analysis failed; no results were recorded."
              : isActiveStatus(job.status)
                ? "Results will appear here once the analysis finishes and has been ingested."
                : "Results will appear here once the analysis has been ingested."}
          </p>
        </CardContent>
      </Card>
    );
  }

  const o = parseOverview(job.summary);
  const cap = o.capture;
  const tree = protocolTree(o.hierarchy);
  const facts: [string, React.ReactNode][] = [
    ["Packets", formatCount(cap?.packets)],
    [
      "Bytes",
      cap?.bytes === null || cap?.bytes === undefined ? (
        "—"
      ) : (
        <span title={`${formatCount(cap.bytes)} bytes`}>{formatBytes(cap.bytes)}</span>
      ),
    ],
    ["Start", <When key="start" iso={cap?.firstTs} />],
    ["End", <When key="end" iso={cap?.lastTs} />],
    ["Duration", cap?.durationS === null || cap?.durationS === undefined ? "—" : formatDuration(cap.durationS * 1000)],
    ["Link type", <Trunc key="link" value={cap?.linkType} />],
    ["Format", <Trunc key="format" value={o.captureFormat} />],
  ];

  return (
    <div className="flex flex-col gap-6">
      {o.engineErrors.length > 0 && (
        <Alert className="border-sev-medium/50">
          <TriangleAlert className="text-sev-medium" aria-hidden />
          <AlertTitle>Some analysis engines reported problems</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-4">
              {o.engineErrors.map((code) => (
                <li key={code}>
                  {engineErrorText(code)} <span className="font-mono text-xs">({code})</span>
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {o.truncated.length > 0 && (
        <Alert className="border-sev-medium/50">
          <TriangleAlert className="text-sev-medium" aria-hidden />
          <AlertTitle>Results are partial</AlertTitle>
          <AlertDescription>
            <p>Limits were hit while analyzing this capture; the views below are incomplete.</p>
            <ul className="list-disc pl-4">
              {o.truncated.map((key) => (
                <li key={key}>{truncationText(key)}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Capture</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm">
              {facts.map(([label, value]) => (
                <div key={label} className="contents">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="min-w-0 tabular-nums">{value}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Results</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {o.counts.length === 0 ? (
              <p className="text-sm text-muted-foreground">No counts recorded.</p>
            ) : (
              <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-4">
                {o.counts.map((row) => (
                  <div key={row.key}>
                    <dt className="text-xs text-muted-foreground">{row.label}</dt>
                    <dd className="tabular-nums">{formatCount(row.stored)}</dd>
                  </div>
                ))}
              </dl>
            )}
            <div>
              <p className="mb-1 text-xs text-muted-foreground">Tools</p>
              {o.toolVersions.length === 0 ? (
                <p className="text-sm text-muted-foreground">—</p>
              ) : (
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                  {o.toolVersions.map(([name, version]) => (
                    <div key={name} className="contents">
                      <dt className="max-w-48 truncate text-muted-foreground" title={name}>
                        {Object.hasOwn(TOOL_LABELS, name) ? TOOL_LABELS[name] : name}
                      </dt>
                      <dd className="flex min-w-0 items-center gap-1">
                        <span className="truncate font-mono text-xs" title={version}>
                          {name === "rules_sha256" ? shortHash(version, 16) : version}
                        </span>
                        {name === "rules_sha256" && <CopyButton value={version} label="Copy rules digest" />}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Protocol hierarchy</CardTitle>
        </CardHeader>
        <CardContent>
          {tree.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No protocol hierarchy recorded{o.engineErrors.some((c) => c.startsWith("tshark_")) ? " (TShark did not complete)" : ""}.
            </p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm" aria-label="Protocol hierarchy by bytes">
              {tree.map((node) => (
                <li
                  key={node.path}
                  className="grid grid-cols-[minmax(0,14rem)_1fr_auto] items-center gap-3"
                  title={`${node.path} — ${formatCount(node.bytes)} bytes, ${formatCount(node.frames)} frames`}
                >
                  <span className="truncate font-mono text-xs" style={{ paddingLeft: `${Math.min(node.depth, 12) * 0.75}rem` }}>
                    {node.label}
                  </span>
                  <span className="h-2 rounded-full bg-muted" aria-hidden>
                    <span
                      className="block h-2 rounded-full bg-primary/70"
                      style={{ width: `${Math.max(node.share * 100, node.bytes > 0 ? 0.5 : 0)}%` }}
                    />
                  </span>
                  <span className="w-36 text-right text-xs text-muted-foreground tabular-nums">
                    {formatBytes(node.bytes)} · {formatCount(node.frames)} fr
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-3">
        <HostTable title="Top sources" hosts={o.topSources} onShowFlows={onShowFlows} />
        <HostTable title="Top destinations" hosts={o.topDestinations} onShowFlows={onShowFlows} />
        <Card>
          <CardHeader>
            <CardTitle>Top ports</CardTitle>
          </CardHeader>
          <CardContent>
            {o.topPorts.length === 0 ? (
              <p className="text-sm text-muted-foreground">None recorded.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Port</TableHead>
                    <TableHead className="text-right">Flows</TableHead>
                    <TableHead className="text-right">Bytes</TableHead>
                    {onShowFlows && <TableHead className="w-10" />}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {o.topPorts.map((p) => (
                    <TableRow key={`${p.proto}/${p.port}`}>
                      <TableCell className="max-w-28 truncate font-mono text-xs" title={`${p.port}/${p.proto}`}>
                        {p.port}/{p.proto}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{formatCount(p.flows)}</TableCell>
                      <TableCell className="text-right tabular-nums" title={`${formatCount(p.bytes)} bytes`}>
                        {formatBytes(p.bytes)}
                      </TableCell>
                      {onShowFlows && (
                        <TableCell>
                          <FlowButton link={{ port: p.port }} onShowFlow={onShowFlows} label="" title={`Flows on port ${p.port}`} />
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function HostTable({
  title,
  hosts,
  onShowFlows,
}: {
  title: string;
  hosts: HostStat[];
  onShowFlows?: (link: FlowLink) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {hosts.length === 0 ? (
          <p className="text-sm text-muted-foreground">None recorded.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead className="text-right">Bytes</TableHead>
                <TableHead className="text-right">Packets</TableHead>
                <TableHead className="text-right">Flows</TableHead>
                {onShowFlows && <TableHead className="w-10" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {hosts.map((h) => (
                <TableRow key={h.ip}>
                  <TableCell>
                    <Trunc value={h.ip} mono className="max-w-48" />
                  </TableCell>
                  <TableCell className="text-right tabular-nums" title={`${formatCount(h.bytes)} bytes`}>
                    {formatBytes(h.bytes)}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{formatCount(h.packets)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatCount(h.flows)}</TableCell>
                  {onShowFlows && (
                    <TableCell>
                      <FlowButton link={{ ip: h.ip }} onShowFlow={onShowFlows} label="" title={`Flows of ${h.ip}`} />
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
