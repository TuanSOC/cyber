"use client";

import { Sparkles } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import {
  Badge,
  Cites,
  DataTable,
  Facts,
  ReportSection,
  SevText,
  SubSection,
  Truncation,
  citeAnchor,
} from "@/components/reports/report-parts";
import { RText } from "@/components/reports/report-text";
import { flagText, taskLabel } from "@/lib/ai";
import { formatBytes } from "@/lib/format";
import { formatCount } from "@/lib/pcap-results";
import { citationHref, formatUtc, jobRoutes } from "@/lib/report-format";
import { ANALYST_SECTIONS, type ReportSnapshot } from "@/lib/reports";

/*
 * The sections of a `cyberlab.report.v1` snapshot, in snapshot order. Text only: values are
 * `RText` nodes; the only links are the appendix's "open current record" links, built from ids
 * by `citationHref` (none in external snapshots).
 */

type S = ReportSnapshot;

export const SECTION_IDS = {
  case: "rs-case",
  assessment: "rs-assessment",
  evidence: "rs-evidence",
  jobs: "rs-jobs",
  findings: "rs-findings",
  alerts: "rs-alerts",
  iocs: "rs-iocs",
  attack: "rs-attack",
  timeline: "rs-timeline",
  notes: "rs-notes",
  ai: "rs-ai",
  appendix: "rs-appendix",
} as const;

export const TOC: readonly { id: string; label: string }[] = [
  { id: SECTION_IDS.case, label: "Case" },
  { id: SECTION_IDS.assessment, label: "Assessment" },
  { id: SECTION_IDS.evidence, label: "Evidence and chain of custody" },
  { id: SECTION_IDS.jobs, label: "Analyses and tool versions" },
  { id: SECTION_IDS.findings, label: "Findings" },
  { id: SECTION_IDS.alerts, label: "Alerts" },
  { id: SECTION_IDS.iocs, label: "Indicators of compromise" },
  { id: SECTION_IDS.attack, label: "ATT&CK techniques" },
  { id: SECTION_IDS.timeline, label: "Timeline" },
  { id: SECTION_IDS.notes, label: "Analyst notes" },
  { id: SECTION_IDS.ai, label: "AI-assisted analysis" },
  { id: SECTION_IDS.appendix, label: "Appendix: citations" },
];

const when = (iso: string | null | undefined) => <span className="whitespace-nowrap">{formatUtc(iso)}</span>;
const statusText = (value: string | null | undefined) => (value ? value.replaceAll("_", " ") : null);

export function CaseSection({ snapshot }: { snapshot: S }) {
  const c = snapshot.case;
  return (
    <ReportSection id={SECTION_IDS.case} title="Case">
      <Facts
        rows={[
          ["Reference", <RText key="r" value={c.case_ref} />],
          ["Title", <RText key="t" value={c.title} />],
          ["Status", <RText key="s" value={statusText(c.status)} />],
          ["Severity", <SevText key="v" value={c.severity} />],
          ["Opened", when(c.created_at)],
        ]}
      />
      <SubSection title="Description">
        <RText block value={c.description || "No description."} />
      </SubSection>
      <SubSection title="Status history">
        <Truncation included={c.status_history.length} total={c.status_history_total} />
        <DataTable
          caption="Status history"
          head={["When", "From", "To", "Reason", "By"]}
          empty="No status changes."
          rows={c.status_history.map((event) => [
            when(event.occurred_at),
            <RText key="f" value={statusText(event.from_status)} />,
            <RText key="t" value={statusText(event.to_status)} />,
            <RText key="r" value={event.reason} />,
            <RText key="a" value={event.actor} />,
          ])}
        />
      </SubSection>
    </ReportSection>
  );
}

export function AssessmentSection({ snapshot }: { snapshot: S }) {
  return (
    <ReportSection id={SECTION_IDS.assessment} title="Assessment" note="Written by the analysts (plain text).">
      {ANALYST_SECTIONS.map((section) => (
        <SubSection key={section.key} title={section.label}>
          {snapshot.sections[section.key] ? (
            <RText block value={snapshot.sections[section.key]} className="text-sm" />
          ) : (
            <p className="text-sm text-muted-foreground">Not provided.</p>
          )}
        </SubSection>
      ))}
    </ReportSection>
  );
}

const VERIFICATION_TEXT: Record<string, string> = {
  ok: "Hashes verified",
  mismatch: "HASH MISMATCH",
  unverified: "Not verified",
};

export function EvidenceSection({ snapshot }: { snapshot: S }) {
  const custody = snapshot.custody.items;
  const network = custody.some((item) => item.ip || item.user_agent);
  return (
    <ReportSection id={SECTION_IDS.evidence} title="Evidence and chain of custody">
      <SubSection title="Evidence inventory">
        <Truncation included={snapshot.evidence.items.length} total={snapshot.evidence.total} />
        <DataTable
          caption="Evidence inventory"
          head={["File", "Size and type", "Hashes", "Uploaded", "Verification"]}
          empty="No evidence included."
          rows={snapshot.evidence.items.map((item) => [
            <span key="f">
              <RText value={item.filename} />
              <Cites nos={[item.cite_no]} />
              {item.description ? <RText block value={item.description} className="text-muted-foreground" /> : null}
            </span>,
            <span key="s">
              {formatBytes(item.size_bytes)}
              <br />
              <RText value={item.mime} mono />
            </span>,
            <span key="h" className="flex flex-col gap-0.5">
              <span>
                SHA-256 <RText value={item.sha256} mono />
              </span>
              {item.sha1 ? (
                <span>
                  SHA-1 <RText value={item.sha1} mono />
                </span>
              ) : null}
              {item.md5 ? (
                <span>
                  MD5 <RText value={item.md5} mono />
                </span>
              ) : null}
            </span>,
            <span key="u">
              {when(item.uploaded_at)}
              <br />
              <RText value={item.uploaded_by} />
            </span>,
            <span key="v" className={item.verification === "mismatch" ? "font-semibold text-destructive" : undefined}>
              {VERIFICATION_TEXT[item.verification] ?? item.verification}
              {item.last_verified_at ? <span className="block text-muted-foreground">{formatUtc(item.last_verified_at)}</span> : null}
            </span>,
          ])}
        />
      </SubSection>
      <SubSection title="Chain of custody">
        <Truncation included={custody.length} total={snapshot.custody.total} />
        <DataTable
          caption="Chain of custody"
          head={network ? ["When", "Action", "By", "Evidence", "IP address", "User agent"] : ["When", "Action", "By", "Evidence"]}
          empty="No custody events included."
          rows={custody.map((item) => {
            const cells: ReactNode[] = [
              when(item.occurred_at),
              <RText key="a" value={statusText(item.action)} />,
              <RText key="b" value={item.actor} />,
              <RText key="e" value={item.evidence_id} mono />,
            ];
            if (network) cells.push(<RText key="i" value={item.ip} mono />, <RText key="u" value={item.user_agent} />);
            return cells;
          })}
        />
      </SubSection>
    </ReportSection>
  );
}

export function JobsSection({ snapshot }: { snapshot: S }) {
  const files = new Map(snapshot.evidence.items.map((item) => [item.evidence_id, item.filename]));
  return (
    <ReportSection id={SECTION_IDS.jobs} title="Analyses and tool versions">
      <Truncation included={snapshot.jobs.items.length} total={snapshot.jobs.total} />
      <DataTable
        caption="Analyses and tool versions"
        head={["Analysis", "Evidence", "Status", "Started / finished", "Tool versions"]}
        empty="No analyses included."
        rows={snapshot.jobs.items.map((job) => [
          <span key="a">
            <RText value={job.analyzer === "static" ? "Static analysis" : job.analyzer === "pcap" ? "PCAP analysis" : job.analyzer} />
            {job.profile ? <RText value={` (${job.profile})`} /> : null}
            <Cites nos={[job.cite_no]} />
            <RText block value={job.job_id} mono className="text-muted-foreground" />
          </span>,
          <RText key="e" value={files.get(job.evidence_id) ?? job.evidence_id} />,
          <RText key="s" value={statusText(job.status)} />,
          <span key="t">
            {when(job.created_at)}
            <br />
            {when(job.finished_at)}
          </span>,
          <span key="v" className="flex flex-col">
            {Object.entries(job.tool_versions)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([tool, version]) => (
                <RText key={tool} value={`${tool} ${version}`} mono />
              ))}
          </span>,
        ])}
      />
    </ReportSection>
  );
}

export function FindingsSection({ snapshot }: { snapshot: S }) {
  return (
    <ReportSection id={SECTION_IDS.findings} title="Findings">
      <Truncation included={snapshot.findings.items.length} total={snapshot.findings.total} />
      <DataTable
        caption="Findings"
        head={["Finding", "Severity", "Category and score", "ATT&CK", "Description"]}
        empty="No findings included."
        rows={snapshot.findings.items.map((item) => [
          <span key="t">
            <RText value={item.title} />
            <Cites nos={[item.cite_no]} />
          </span>,
          <SevText key="s" value={item.severity} />,
          <span key="c">
            <RText value={item.category} />
            {item.score ? <RText block value={`score ${item.score}`} className="text-muted-foreground" /> : null}
          </span>,
          <RText key="a" value={item.attack_ids.join(", ")} mono />,
          <RText key="d" value={item.description} />,
        ])}
      />
    </ReportSection>
  );
}

export function AlertsSection({ snapshot }: { snapshot: S }) {
  return (
    <ReportSection id={SECTION_IDS.alerts} title="Alerts">
      <Truncation included={snapshot.alerts.items.length} total={snapshot.alerts.total} />
      <DataTable
        caption="Alerts"
        head={["Signature", "Severity", "Endpoints", "Count", "First seen"]}
        empty="No alerts included."
        rows={snapshot.alerts.items.map((item) => [
          <span key="s">
            <RText value={item.signature} />
            <Cites nos={[item.cite_no]} />
            {item.signature_id !== null && item.signature_id !== undefined ? (
              <RText block value={`SID ${item.signature_id}`} mono className="text-muted-foreground" />
            ) : null}
          </span>,
          <SevText key="v" value={item.severity} />,
          <span key="e">
            <RText value={`${item.src ?? "?"} → ${item.dst ?? "?"}`} mono />
            {item.proto ? <RText block value={item.proto} className="text-muted-foreground" /> : null}
          </span>,
          formatCount(item.count),
          when(item.ts),
        ])}
      />
    </ReportSection>
  );
}

export function IocsSection({ snapshot }: { snapshot: S }) {
  const values = new Map(snapshot.iocs.items.map((item) => [item.ioc_key, item.value]));
  return (
    <ReportSection
      id={SECTION_IDS.iocs}
      title="Indicators of compromise"
      note="Values are defanged as stored in the signed snapshot; they are never linked."
    >
      <Truncation included={snapshot.iocs.items.length} total={snapshot.iocs.total} />
      <DataTable
        caption="Indicators of compromise"
        head={["Value", "Type", "Seen", "Analyses", "Collections"]}
        empty="No IOCs included."
        rows={snapshot.iocs.items.map((item) => [
          <span key="v">
            <RText value={item.value} mono />
            <Cites nos={[item.cite_no]} />
          </span>,
          <RText key="t" value={item.ioc_type} />,
          <span key="s">
            {when(item.first_seen)}
            <br />
            {when(item.last_seen)}
          </span>,
          formatCount(item.count_jobs),
          <RText key="c" value={item.collections.join(", ")} />,
        ])}
      />
      <SubSection
        title="Threat intelligence"
        note="Statements of the named providers at the time shown, attributed to them; not CyberLab verdicts."
      >
        <Truncation included={snapshot.ti.items.length} total={snapshot.ti.total} />
        <DataTable
          caption="Threat intelligence"
          head={["Indicator", "Provider", "Result", "Summary", "Fetched"]}
          empty="No threat intelligence included."
          rows={snapshot.ti.items.map((item) => [
            <span key="i">
              <RText value={values.get(item.ioc_key) ?? item.ioc_key} mono />
              <Cites nos={[item.cite_no]} />
            </span>,
            <RText key="p" value={item.provider} />,
            <span key="r">
              <RText value={item.found ? "Listed" : "Not listed"} />
              {item.score ? <RText block value={`score ${item.score}${item.score_scale ? ` (${item.score_scale})` : ""}`} /> : null}
              {item.status !== "ok" ? <RText block value={statusText(item.status)} className="text-muted-foreground" /> : null}
            </span>,
            <RText key="s" value={item.summary} />,
            when(item.fetched_at),
          ])}
        />
      </SubSection>
    </ReportSection>
  );
}

export function AttackSection({ snapshot }: { snapshot: S }) {
  const groups = new Map<string, S["attack"]["items"]>();
  for (const item of snapshot.attack.items) {
    for (const tactic of item.tactics.length ? item.tactics : ["(no tactic)"]) {
      groups.set(tactic, [...(groups.get(tactic) ?? []), item]);
    }
  }
  return (
    <ReportSection
      id={SECTION_IDS.attack}
      title="ATT&CK techniques"
      note="Mappings confirmed or marked suspected by the analysts (MITRE ATT&CK v20, offline index)."
    >
      <Truncation included={snapshot.attack.items.length} total={snapshot.attack.total} />
      {groups.size === 0 ? <p className="text-sm text-muted-foreground">No techniques included.</p> : null}
      <div className="grid gap-4 sm:grid-cols-2">
        {[...groups.entries()].map(([tactic, items]) => (
          <div key={tactic} className="rounded-md border p-3">
            <h3 className="mb-2 text-sm font-semibold">
              <RText value={tactic.replaceAll("-", " ")} />
            </h3>
            <ul className="flex flex-col gap-2 text-sm">
              {items.map((item) => (
                <li key={`${tactic}-${item.technique_id}`}>
                  <span className="font-mono text-xs">{item.technique_id}</span> <RText value={item.name} />{" "}
                  <Badge tone={item.status === "suspected" ? "warn" : "muted"}>{item.status}</Badge>
                  {item.revoked ? <Badge tone="warn">revoked in ATT&CK</Badge> : null}
                  <Cites nos={item.cite_nos} />
                  {item.rationale ? <RText block value={item.rationale} className="text-xs text-muted-foreground" /> : null}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </ReportSection>
  );
}

export function TimelineSection({ snapshot }: { snapshot: S }) {
  return (
    <ReportSection id={SECTION_IDS.timeline} title="Timeline">
      <Truncation included={snapshot.timeline.items.length} total={snapshot.timeline.total} />
      <DataTable
        caption="Timeline"
        head={["When", "Event", "Kind", "Severity"]}
        empty="No timeline entries included."
        rows={snapshot.timeline.items.map((item) => [
          <span key="w">
            {when(item.ts)}
            <span className="block text-muted-foreground">
              <RText value={statusText(item.ts_source)} />
            </span>
          </span>,
          <span key="t">
            <RText value={item.title} />
            <Cites nos={[item.cite_no]} />
          </span>,
          <RText key="k" value={statusText(item.kind)} />,
          <SevText key="s" value={item.severity} />,
        ])}
      />
    </ReportSection>
  );
}

export function NotesSection({ snapshot }: { snapshot: S }) {
  const external = snapshot.report.profile === "external";
  return (
    <ReportSection id={SECTION_IDS.notes} title="Analyst notes">
      {external ? (
        <p className="text-sm text-muted-foreground">Analyst notes are left out of external reports.</p>
      ) : (
        <>
          <Truncation included={snapshot.notes.items.length} total={snapshot.notes.total} />
          {snapshot.notes.items.length === 0 ? <p className="text-sm text-muted-foreground">No notes included.</p> : null}
          <ol className="flex flex-col gap-3">
            {snapshot.notes.items.map((note) => (
              <li key={note.note_id} className="rounded-md border p-3 text-sm">
                <p className="mb-1 text-xs text-muted-foreground">
                  <RText value={note.author} /> · {formatUtc(note.updated_at)} · version {note.version}
                  <Cites nos={note.cite_nos} />
                </p>
                <RText block value={note.body} />
              </li>
            ))}
          </ol>
        </>
      )}
    </ReportSection>
  );
}

const CLAIM_SECTIONS = [
  ["observed", "Observed"],
  ["interpretation", "Interpretation"],
  ["hypotheses", "Hypotheses"],
  ["next_steps", "Next steps"],
  ["limitations", "Limitations"],
] as const;

export const AI_REPORT_DISCLAIMER =
  "AI-generated, verify before acting. Only statements backed by verified citations and labelled hypotheses are included.";

export function AiSections({ snapshot }: { snapshot: S }) {
  const external = snapshot.report.profile === "external";
  return (
    <ReportSection id={SECTION_IDS.ai} title="AI-assisted analysis">
      <Truncation included={snapshot.ai.items.length} total={snapshot.ai.total} />
      {snapshot.ai.items.length === 0 ? <p className="text-sm text-muted-foreground">No AI runs included.</p> : null}
      {snapshot.ai.items.map((run, index) => (
        <article key={run.run_id} className="mt-4" aria-labelledby={`rs-ai-run-${index + 1}`}>
          <h3 id={`rs-ai-run-${index + 1}`} className="text-base font-semibold">
            <RText value={taskLabel(run.task)} />
          </h3>
          <div role="note" className="mt-2 rounded-md border-2 border-dashed p-3 text-xs">
            <p className="flex items-start gap-2 font-medium">
              <Sparkles className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              <span>{AI_REPORT_DISCLAIMER}</span>
            </p>
            <RText block value={run.disclaimer} className="mt-1 text-muted-foreground" />
          </div>
          <Facts
            rows={[
              ["Model", <RText key="m" value={`${run.provider} / ${run.model}`} />],
              ["Overall confidence", <RText key="c" value={run.overall_confidence ?? "not stated"} />],
              ["Finished", when(run.finished_at)],
              ["Prompt version", <RText key="p" value={run.prompt_version} mono />],
              ["Context SHA-256", <RText key="h" value={run.context_sha256} mono />],
            ]}
          />
          {run.omitted_unsupported > 0 || run.omitted_flagged > 0 ? (
            <p className="mt-2 text-xs text-muted-foreground">
              {run.omitted_unsupported > 0
                ? `${formatCount(run.omitted_unsupported)} statement${run.omitted_unsupported === 1 ? "" : "s"} omitted: not supported by verified evidence. `
                : null}
              {run.omitted_flagged > 0
                ? `${formatCount(run.omitted_flagged)} flagged statement${run.omitted_flagged === 1 ? "" : "s"} omitted${external ? " from this external report" : ""} (conclusive wording or web addresses).`
                : null}
            </p>
          ) : null}
          {CLAIM_SECTIONS.map(([key, label]) => {
            const claims = run.claims.filter((claim) => claim.section === key);
            if (claims.length === 0) return null;
            return (
              <div key={key} className="mt-3">
                <h4 className="text-sm font-semibold">{label}</h4>
                <ul className="mt-1 flex list-disc flex-col gap-2 pl-5 text-sm">
                  {claims.map((claim) => (
                    <li key={claim.claim_id}>
                      {claim.status === "hypothesis" ? <Badge tone="warn">Hypothesis</Badge> : null}{" "}
                      {claim.confidence ? <Badge>confidence: {claim.confidence}</Badge> : null}{" "}
                      <RText value={claim.text} />
                      <Cites nos={claim.cite_nos} />
                      {claim.flags.length ? (
                        <ul className="mt-1 flex flex-col gap-0.5 text-xs text-amber-800 dark:text-amber-300">
                          {claim.flags.map((flag) => (
                            <li key={flag}>
                              <RText value={flagText(flag)} />
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </article>
      ))}
    </ReportSection>
  );
}

export const OPEN_RECORD_LABEL = "Open current record (may differ from the snapshot copy)";

export function AppendixSection({ orgId, snapshot }: { orgId: string; snapshot: S }) {
  const routes = jobRoutes(snapshot.jobs.items);
  const citations = snapshot.citations;
  return (
    <ReportSection
      id={SECTION_IDS.appendix}
      title="Appendix: citations"
      note="Each citation is a copy of the cited record's fields when this version was built, with the SHA-256 of that copy."
    >
      <Truncation included={citations.items.length} total={citations.total} />
      {citations.dropped_out_of_scope > 0 ? (
        <p className="mb-2 text-xs text-muted-foreground">
          {formatCount(citations.dropped_out_of_scope)} cited record{citations.dropped_out_of_scope === 1 ? " was" : "s were"} outside
          this case and left out.
        </p>
      ) : null}
      {citations.items.length === 0 ? <p className="text-sm text-muted-foreground">No citations.</p> : null}
      <ol className="flex flex-col gap-1">
        {citations.items.map((citation) => {
          const href = citationHref(orgId, citation, routes, snapshot.case.investigation_id);
          return (
            <li key={citation.cite_no}>
              <details id={citeAnchor(citation.cite_no)} className="rounded-md border px-3 py-1 text-xs open:pb-3">
                <summary className="cursor-pointer py-1 text-sm">
                  <span className="font-mono">[C{citation.cite_no}]</span> <RText value={citation.kind.replaceAll("_", " ")} /> ·{" "}
                  <RText value={citation.ref_table} mono />
                </summary>
                <Facts
                  rows={[
                    ["Kind", <RText key="k" value={citation.kind} />],
                    ["Source", <RText key="s" value={citation.source} />],
                    ["Record id", <RText key="r" value={citation.ref_id} mono />],
                    ["Analysis id", <RText key="j" value={citation.job_id} mono />],
                    ["Fields SHA-256", <RText key="h" value={citation.fields_sha256} mono />],
                  ]}
                />
                <DataTable
                  caption={`Copied fields of citation ${citation.cite_no}`}
                  head={["Field", "Value at snapshot time"]}
                  empty="No fields copied."
                  rows={Object.entries(citation.fields).map(([field, value]) => [
                    <RText key="f" value={field} mono />,
                    <RText key="v" value={value} />,
                  ])}
                />
                {href ? (
                  <Link href={href} className="mt-2 inline-block text-sm underline underline-offset-4 print:hidden">
                    {OPEN_RECORD_LABEL}
                  </Link>
                ) : null}
              </details>
            </li>
          );
        })}
      </ol>
    </ReportSection>
  );
}
