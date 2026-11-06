"use client";

import { Hammer, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type ReactNode, useState } from "react";
import { toast } from "sonner";

import { InertText } from "@/components/disk/inert-text";
import { QueryError } from "@/components/query-error";
import { CodeViewer } from "@/components/reverse/code-viewer";
import { ExplainFunctionButton } from "@/components/reverse/explain-function-button";
import { AttackChips, useAttackLookup } from "@/components/ti/attack-chips";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AnalysisJob } from "@/lib/analysis";
import { ApiError } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import {
  DECOMPILE_CONFIRM,
  DECOMPILE_LABELS,
  type FunctionCode,
  type FunctionDetail,
  type FunctionRef,
  type FunctionTab,
  NAME_SOURCE_LABELS,
  type ReProfileName,
  decompileReason,
  formatAddress,
  functionFlags,
  reRunErrorText,
} from "@/lib/reverse";
import { useActiveReJob, useReCode, useReFunction, useRunRe } from "@/lib/use-re-job";

/** A linked list of functions (callers / callees): each opens that function here. */
function FunctionLinks({
  items,
  total,
  onOpen,
  empty,
}: {
  items: readonly FunctionRef[];
  total: number;
  onOpen: (entry: string) => void;
  empty: string;
}) {
  if (items.length === 0) return <p className="text-xs text-muted-foreground">{empty}</p>;
  return (
    <ul className="flex flex-col gap-0.5 text-xs">
      {items.map((ref) => (
        <li key={ref.entry} className="flex min-w-0 items-center gap-2">
          <button
            type="button"
            className="min-w-0 truncate text-left font-mono underline-offset-4 hover:underline"
            onClick={() => onOpen(ref.entry)}
            title={formatAddress(ref.entry)}
          >
            <InertText value={ref.name} max={255} />
          </button>
          <span className="shrink-0 font-mono text-muted-foreground">{formatAddress(ref.entry)}</span>
        </li>
      ))}
      {total > items.length ? <li className="text-muted-foreground">and {total - items.length} more</li> : null}
    </ul>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex min-w-0 flex-col gap-1">
      <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{title}</h3>
      {children}
    </section>
  );
}

/** The facts of one function (signature, name source, flags, links, imports, strings, capa). */
export function FunctionFacts({
  orgId,
  jobId,
  detail,
  profile,
  onOpen,
}: {
  orgId: string;
  jobId: string;
  detail: FunctionDetail;
  profile: ReProfileName;
  onOpen: (entry: string) => void;
}) {
  const fn = detail.function;
  const flags = functionFlags(fn);
  const lookup = useAttackLookup(detail.capabilities.flatMap((cap) => cap.attack));
  const findingsHref = (id: string) => `${orgPath(orgId, `reverse-engineering/${jobId}`)}?tab=findings&ref=${encodeURIComponent(id)}`;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Section title="Signature">
        <InertText value={fn.signature} mono wrap max={512} />
      </Section>
      <Section title="Facts">
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
          <dt className="text-muted-foreground">Entry</dt>
          <dd className="font-mono">{formatAddress(fn.entry)}</dd>
          <dt className="text-muted-foreground">RVA</dt>
          <dd className="font-mono">{formatAddress(fn.rva)}</dd>
          <dt className="text-muted-foreground">Size</dt>
          <dd className="tabular-nums">{fn.size.toLocaleString("en-US")} bytes</dd>
          <dt className="text-muted-foreground">Instructions</dt>
          <dd className="tabular-nums">{fn.instructions.toLocaleString("en-US")}</dd>
          <dt className="text-muted-foreground">Name</dt>
          <dd>{NAME_SOURCE_LABELS[fn.name_source] ?? fn.name_source}</dd>
          {fn.calling_convention ? (
            <>
              <dt className="text-muted-foreground">Convention</dt>
              <dd className="font-mono">
                <InertText value={fn.calling_convention} max={32} />
              </dd>
            </>
          ) : null}
          {flags.length ? (
            <>
              <dt className="text-muted-foreground">Flags</dt>
              <dd className="flex flex-wrap gap-1">
                {flags.map((flag) => (
                  <Badge key={flag} variant="outline">
                    {flag}
                  </Badge>
                ))}
              </dd>
            </>
          ) : null}
        </dl>
      </Section>
      <Section title="Decompilation">
        <p className="text-xs">
          <Badge variant="secondary" className="mr-2">
            {DECOMPILE_LABELS[fn.decompile_status] ?? fn.decompile_status}
          </Badge>
          {decompileReason(fn, profile)}
        </p>
      </Section>
      <Section title={`Capabilities (${detail.capabilities.length})`}>
        {detail.capabilities.length === 0 ? (
          <p className="text-xs text-muted-foreground">No capa capability is located in this function.</p>
        ) : (
          <ul className="flex flex-col gap-1 text-xs">
            {detail.capabilities.map((cap) => (
              <li key={cap.capability_id} className="flex flex-wrap items-center gap-2">
                <InertText value={cap.name} max={200} />
                {cap.attack.length ? <AttackChips ids={cap.attack} lookup={lookup} /> : null}
                <span className="font-mono text-muted-foreground">@ {formatAddress(cap.file_va)}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">Capabilities are static rule matches, not observed behaviour.</p>
      </Section>
      <Section title={`Callers (${fn.callers})`}>
        <FunctionLinks items={detail.callers} total={fn.callers} onOpen={onOpen} empty="No caller was recovered." />
      </Section>
      <Section title={`Callees (${fn.callees})`}>
        <FunctionLinks items={detail.callees} total={fn.callees} onOpen={onOpen} empty="It calls no recovered function." />
      </Section>
      <Section title={`Imports called (${detail.imports.length})`}>
        {detail.imports.length === 0 ? (
          <p className="text-xs text-muted-foreground">None.</p>
        ) : (
          <ul className="flex flex-col gap-0.5 font-mono text-xs">
            {detail.imports.map((imp) => (
              <li key={imp.id} className="min-w-0">
                <InertText value={`${imp.library}!${imp.name ?? (imp.ordinal !== null ? `#${imp.ordinal}` : "?")}`} max={300} />
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title={`Strings referenced (${detail.strings.length})`}>
        {detail.strings.length === 0 ? (
          <p className="text-xs text-muted-foreground">None.</p>
        ) : (
          <ul className="flex flex-col gap-0.5 text-xs">
            {detail.strings.map((s) => (
              <li key={s.id} className="flex min-w-0 gap-2">
                <span className="shrink-0 font-mono text-muted-foreground">{formatAddress(s.address)}</span>
                <InertText value={s.value} mono max={300} />
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title={`Findings (${detail.finding_ids.length})`}>
        {detail.finding_ids.length === 0 ? (
          <p className="text-xs text-muted-foreground">No finding cites this function.</p>
        ) : (
          <ul className="flex flex-col gap-0.5 text-xs">
            {detail.finding_ids.map((id, index) => (
              <li key={id}>
                <Link href={findingsHref(id)} className="underline-offset-4 hover:underline">
                  Finding {index + 1}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

/**
 * "Decompile this function" (RT10): a new `full` RE job of the same sample with this entry
 * decompiled first, after a confirmation (it re-analyses the whole sample). Disabled while an
 * RE job of the sample is queued or running.
 */
export function DecompileFunctionButton({ orgId, job, entry }: { orgId: string; job: AnalysisJob; entry: string }) {
  const { can } = useOrg();
  const router = useRouter();
  const [confirm, setConfirm] = useState(false);
  const active = useActiveReJob(orgId, job.evidence_id);
  const run = useRunRe(orgId);
  const sourceJobId = job.source_job_id;
  if (!can("evidence.write") || !sourceJobId) return null;
  const busy = Boolean(active.data);
  if (!confirm) {
    return (
      <Button
        type="button"
        size="sm"
        variant="outline"
        disabled={busy || run.isPending}
        title={busy ? "A reverse-engineering job of this sample is already queued or running" : "Re-analyse the sample with this function decompiled first"}
        onClick={() => setConfirm(true)}
      >
        <Hammer className="size-3.5" aria-hidden />
        Decompile this function
      </Button>
    );
  }
  return (
    <div className="flex max-w-xl flex-col gap-2 rounded-md border p-3 text-xs" role="dialog" aria-label="Decompile this function">
      <p>{DECOMPILE_CONFIRM}</p>
      {run.error ? (
        <p role="alert" className="text-destructive">
          {reRunErrorText(run.error)}
        </p>
      ) : null}
      <div className="flex gap-2">
        <Button
          type="button"
          size="sm"
          disabled={run.isPending || busy}
          onClick={() =>
            run.mutate(
              { evidenceId: job.evidence_id, sourceJobId, profile: "full", decompileAddresses: [formatAddress(entry)] },
              {
                onSuccess: (created) => {
                  toast.success("A new reverse-engineering job was queued");
                  router.push(orgPath(orgId, `reverse-engineering/${created.id}`));
                },
              },
            )
          }
        >
          {run.isPending ? "Requesting…" : "Re-analyse with this function first"}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setConfirm(false)}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

function CodePane({ code }: { code: FunctionCode | undefined }) {
  if (!code) return <p className="text-sm text-muted-foreground">Loading code…</p>;
  if (code.code === null) {
    return <p className="text-sm text-muted-foreground">No code for this function ({DECOMPILE_LABELS[code.status] ?? code.status}).</p>;
  }
  return (
    <CodeViewer
      code={code.code}
      codeKind={code.code_kind}
      truncated={code.status === "truncated" || code.truncated_bytes > 0}
      label={code.name}
    />
  );
}

/** One function: facts and code tabs, Explain function and Decompile this function. */
export function FunctionView({
  orgId,
  job,
  entry,
  tab,
  profile,
  onTab,
  onOpen,
  onClose,
}: {
  orgId: string;
  job: AnalysisJob;
  entry: string;
  tab: FunctionTab;
  profile: ReProfileName;
  onTab: (tab: FunctionTab) => void;
  onOpen: (entry: string) => void;
  onClose: () => void;
}) {
  const detail = useReFunction(orgId, job.id, entry);
  const fn = detail.data?.function;
  const hasCode = fn ? fn.decompile_status === "ok" || fn.decompile_status === "truncated" : false;
  const code = useReCode(orgId, job.id, entry, hasCode && tab === "code");
  if (detail.error instanceof ApiError && detail.error.status === 404) {
    return (
      <Card className="mb-4">
        <CardContent className="flex items-center justify-between gap-2 text-sm">
          <span>No function starts at {formatAddress(entry)} in this analysis.</span>
          <Button type="button" variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card className="mb-4" data-testid="function-view">
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-start gap-2">
          <div className="min-w-0 flex-1">
            <p className="text-xs text-muted-foreground">Function at {formatAddress(entry)}</p>
            <h2 className="min-w-0 font-mono text-base font-medium">
              <InertText value={fn?.name ?? "…"} max={255} />
            </h2>
          </div>
          {fn ? <ExplainFunctionButton orgId={orgId} jobId={job.id} functionId={fn.id} name={fn.name} /> : null}
          {fn && profile === "full" && !hasCode ? <DecompileFunctionButton orgId={orgId} job={job} entry={entry} /> : null}
          <Button type="button" variant="ghost" size="icon" aria-label="Close the function" onClick={onClose}>
            <X className="size-4" aria-hidden />
          </Button>
        </div>
        {detail.isError && !(detail.error instanceof ApiError && detail.error.status === 404) ? (
          <QueryError error={detail.error} onRetry={() => void detail.refetch()} />
        ) : null}
        <Tabs value={tab} onValueChange={(value) => onTab(value === "code" ? "code" : "facts")}>
          <TabsList aria-label="Function views">
            <TabsTrigger value="facts">Facts</TabsTrigger>
            <TabsTrigger value="code" disabled={!hasCode}>
              Code
            </TabsTrigger>
          </TabsList>
          <TabsContent value="facts">
            {detail.data ? (
              <FunctionFacts orgId={orgId} jobId={job.id} detail={detail.data} profile={profile} onOpen={onOpen} />
            ) : (
              <p className="text-sm text-muted-foreground">Loading…</p>
            )}
          </TabsContent>
          <TabsContent value="code">
            {code.error instanceof ApiError && code.error.code === "code_not_available" ? (
              // The function exists but has no decompiled lines (an empty state, not an error).
              <p className="text-sm text-muted-foreground">No decompiled code for this function.</p>
            ) : code.isError ? (
              <QueryError error={code.error} onRetry={() => void code.refetch()} />
            ) : (
              <CodePane code={code.data} />
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
