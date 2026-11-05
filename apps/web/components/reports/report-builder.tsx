"use client";

import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Eye, FileSignature, RotateCcw, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { toast } from "sonner";

import { ConfirmButton } from "@/components/confirm-button";
import { NotFoundCard } from "@/components/not-found-card";
import { QueryError } from "@/components/query-error";
import { DistributionField, ProfileField, SectionsEditor, TitleField } from "@/components/reports/builder-fields";
import { type FinalizeOptions, FinalizeDialog } from "@/components/reports/finalize-dialog";
import { PreviewPanel } from "@/components/reports/preview-panel";
import {
  AttackGroup,
  EvidenceGroup,
  FindingsAlertsGroup,
  IocsGroup,
  TimelineGroup,
} from "@/components/reports/selection-groups";
import { AiRunsPicker, CitedRowsPicker, JobsPicker, NotesPicker } from "@/components/reports/selection-pickers";
import { VersionList } from "@/components/reports/version-list";
import { TlpSelect } from "@/components/tlp/tlp-select";
import { Button } from "@/components/ui/button";
import { ApiError, errorMessage } from "@/lib/api";
import { reportsHref, vis } from "@/lib/report-format";
import {
  type DraftInclude,
  DraftSaver,
  type ReportDetail,
  type ReportDraft,
  type ReportProfile,
  SAVE_STATUS_TEXT,
  type SaverState,
  addCitedRow,
  distributionRequired,
  draftProblems,
  finalizeReport,
  isStaleDraft,
  removeCitedRow,
  reportErrorText,
  updateReport,
} from "@/lib/reports";
import { TLP_LABELS, type Tlp, isDowngrade } from "@/lib/tlp";
import { useOrg } from "@/lib/org-context";
import {
  reportKeys,
  useCaseAiRuns,
  useCaseCollections,
  useCaseJobs,
  useCaseNotes,
  useDiscardReport,
  useInvestigation,
  usePreviewReport,
  useReport,
  useReportVersions,
} from "@/lib/use-reports";
import { cn } from "@/lib/utils";

/** The draft builder page body: loads the draft, then hands it to the form (remounted on reload). */
export function ReportBuilder({ orgId, reportId }: { orgId: string; reportId: string }) {
  const detail = useReport(orgId, reportId);
  const [loadKey, setLoadKey] = useState(0);

  if (detail.error instanceof ApiError && (detail.error.status === 404 || detail.error.status === 422)) {
    return <NotFoundCard title="Report not found" backHref={reportsHref(orgId)} backLabel="Reports" />;
  }
  if (detail.isError) {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">{reportErrorText(detail.error) ?? ""}</p>
        <QueryError error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }
  if (!detail.data) return <p className="text-sm text-muted-foreground">Loading report…</p>;
  return (
    <BuilderForm
      key={loadKey}
      orgId={orgId}
      initial={detail.data}
      onReload={async () => {
        await detail.refetch();
        setLoadKey((key) => key + 1);
      }}
    />
  );
}

/** The autosave state line and, on a conflict, the banner with "Reload" (focus moves to it). */
export function SaveState({ state, onReload, onRetry }: { state: SaverState; onReload: () => void; onRetry: () => void }) {
  const banner = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (state.status === "conflict") banner.current?.focus();
  }, [state.status]);
  return (
    <>
      <p
        aria-live="polite"
        className={cn("text-xs", state.status === "conflict" || state.status === "error" ? "text-destructive" : "text-muted-foreground")}
        data-save-status={state.status}
      >
        {SAVE_STATUS_TEXT[state.status]} · revision {state.revision}
      </p>
      {state.status === "conflict" ? (
        <div
          ref={banner}
          role="alert"
          tabIndex={-1}
          className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-destructive bg-destructive/5 p-3 text-sm outline-none"
        >
          <span>
            This draft was changed somewhere else (another tab or person). Your latest edits were not saved and nothing was
            overwritten. Reload to continue from the saved draft (copy any text you want to keep first).
          </span>
          <Button size="sm" variant="outline" onClick={onReload}>
            <RotateCcw className="size-4" aria-hidden />
            Reload
          </Button>
        </div>
      ) : null}
      {state.status === "error" ? (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-destructive/50 p-3 text-sm">
          <span>{reportErrorText(state.error) ?? errorMessage(state.error)}</span>
          <Button size="sm" variant="outline" onClick={onRetry}>
            Retry saving
          </Button>
        </div>
      ) : null}
    </>
  );
}

function BuilderForm({ orgId, initial, onReload }: { orgId: string; initial: ReportDetail; onReload: () => Promise<void> }) {
  const report = initial.report;
  const reportId = report.id;
  const { can } = useOrg();
  const router = useRouter();
  const queryClient = useQueryClient();
  const editable = can("investigation.write") && report.status === "draft";
  const canDowngrade = can("org.update");

  const [title, setTitle] = useState(report.title);
  const [tlp, setTlp] = useState<Tlp>(report.tlp);
  const [tlpAck, setTlpAck] = useState(false);
  const [profile, setProfile] = useState<ReportProfile>(report.profile);
  const [distribution, setDistribution] = useState(report.distribution ?? "");
  const [draft, setDraft] = useState<ReportDraft>(initial.draft);
  const [finalizeOpen, setFinalizeOpen] = useState(false);

  const [saver] = useState(() => new DraftSaver(report.revision, (body) => updateReport(orgId, reportId, body)));
  const saveState = useSyncExternalStore(saver.subscribe, saver.getState, saver.getState);
  useEffect(
    () => () => {
      void saver.flush();
      saver.dispose();
    },
    [saver],
  );
  useEffect(() => {
    if (saveState.status !== "dirty" && saveState.status !== "saving") return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [saveState.status]);

  const investigation = useInvestigation(orgId, report.investigation_id);
  const caseTlp = investigation.data?.tlp ?? null;
  const jobs = useCaseJobs(orgId, report.investigation_id);
  const notes = useCaseNotes(orgId, report.investigation_id);
  const collections = useCaseCollections(orgId, report.investigation_id);
  const aiRuns = useCaseAiRuns(orgId, report.investigation_id, (jobs.data ?? []).map((job) => job.id));
  const versions = useReportVersions(orgId, reportId);
  const preview = usePreviewReport(orgId, reportId);
  const discard = useDiscardReport(orgId, reportId);

  const disabled = !editable || saveState.status === "conflict";
  const fields = { title, tlp, profile, distribution, draft };
  const problems = draftProblems(fields);
  const tlpPendingAck = caseTlp !== null && isDowngrade(tlp, caseTlp) && !tlpAck;
  const latestVersion = versions.data?.reduce((max, v) => Math.max(max, v.version), report.latest_version) ?? report.latest_version;

  const setInclude = (include: DraftInclude) => {
    const next = { ...draft, include };
    setDraft(next);
    saver.change({ draft: next });
  };

  async function savedRevision(): Promise<number> {
    await saver.flush();
    const state = saver.getState();
    if (state.status !== "saved") throw new Error("The draft is not saved yet. Fix the save problem first.");
    return state.revision;
  }

  async function runPreview() {
    try {
      await savedRevision();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : errorMessage(error));
      return;
    }
    preview.mutate(undefined, { onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)) });
  }

  async function finalize(options: FinalizeOptions) {
    const revision = await savedRevision();
    try {
      const version = await finalizeReport(orgId, reportId, { ...options, revision });
      await queryClient.invalidateQueries({ queryKey: reportKeys.all(orgId) });
      setFinalizeOpen(false);
      toast.success(`Version ${version.version} finalized and signed.`);
      router.push(`${reportsHref(orgId, reportId, version.version)}?finalized=1`);
      return version;
    } catch (error) {
      if (isStaleDraft(error)) {
        saver.markConflict(error);
        setFinalizeOpen(false);
      }
      throw error;
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link href={reportsHref(orgId)} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="size-4" aria-hidden /> Reports
          </Link>
          <h1 className="mt-1 truncate text-2xl font-semibold tracking-tight">{vis(title) || "Untitled report"}</h1>
          <p className="text-sm text-muted-foreground">
            Draft of {report.case_ref}
            {report.status === "discarded" ? " · discarded" : ""}
            {!can("investigation.write") ? " · read-only for your role" : ""}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" disabled={disabled || preview.isPending} onClick={() => void runPreview()}>
            <Eye className="size-4" aria-hidden />
            {preview.isPending ? "Building preview…" : "Preview"}
          </Button>
          <Button disabled={disabled} onClick={() => setFinalizeOpen(true)}>
            <FileSignature className="size-4" aria-hidden />
            Finalize…
          </Button>
          {editable && latestVersion === 0 ? (
            <ConfirmButton
              variant="ghost"
              title="Discard this draft?"
              description="The draft has no signed version. It is kept as discarded and can no longer be edited."
              confirmLabel="Discard"
              pending={discard.isPending}
              onConfirm={() =>
                discard.mutate(undefined, {
                  onSuccess: () => router.push(reportsHref(orgId)),
                  onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)),
                })
              }
            >
              <Trash2 className="size-4" aria-hidden />
              Discard
            </ConfirmButton>
          ) : null}
        </div>
      </div>

      {editable ? (
        <SaveState
          state={saveState}
          onRetry={() => saver.retry()}
          onReload={() => {
            saver.reset(saveState.revision);
            void onReload();
          }}
        />
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <form className="flex min-w-0 flex-col gap-6" onSubmit={(event) => event.preventDefault()} aria-label="Report draft">
          <div className="grid gap-4 rounded-md border p-4 md:grid-cols-2">
            <div className="md:col-span-2">
              <TitleField
                value={title}
                disabled={disabled}
                onChange={(value) => {
                  setTitle(value);
                  if (value.trim()) saver.change({ title: value });
                }}
              />
            </div>
            <div className="flex flex-col gap-1">
              <TlpSelect
                value={tlp}
                current={caseTlp ?? report.tlp}
                canDowngrade={canDowngrade}
                disabled={disabled}
                label="Report TLP"
                onChange={(next, ack) => {
                  setTlp(next);
                  setTlpAck(ack);
                  if (caseTlp !== null && isDowngrade(next, caseTlp) && !ack) return;
                  saver.change({ tlp: next, acknowledge_tlp_downgrade: ack });
                }}
              />
              {caseTlp ? (
                <p className="text-xs text-muted-foreground">
                  The case is marked {TLP_LABELS[caseTlp]}. A report may not be less restrictive unless an admin confirms it.
                </p>
              ) : null}
              {tlpPendingAck ? (
                <p className="text-xs font-medium text-destructive">Not saved: confirm the lower marking above to save it.</p>
              ) : null}
            </div>
            <ProfileField
              value={profile}
              disabled={disabled}
              onChange={(value) => {
                setProfile(value);
                saver.change({ profile: value });
              }}
            />
            <div className="md:col-span-2">
              <DistributionField
                value={distribution}
                required={distributionRequired(tlp, profile)}
                disabled={disabled}
                onChange={(value) => {
                  setDistribution(value);
                  saver.change({ distribution: value });
                }}
              />
            </div>
          </div>

          <SectionsEditor
            sections={draft.sections}
            disabled={disabled}
            onChange={(sections) => {
              const next = { ...draft, sections };
              setDraft(next);
              saver.change({ draft: next });
            }}
          />

          <h2 className="text-lg font-semibold">What the report includes</h2>
          <div className="grid gap-4 lg:grid-cols-2">
            <EvidenceGroup include={draft.include} onChange={setInclude} disabled={disabled} />
            <JobsPicker
              include={draft.include}
              onChange={setInclude}
              disabled={disabled}
              jobs={jobs.data ?? []}
              loading={jobs.isLoading}
              error={jobs.error}
            />
            <FindingsAlertsGroup include={draft.include} onChange={setInclude} disabled={disabled} />
            <IocsGroup
              include={draft.include}
              onChange={setInclude}
              disabled={disabled}
              collections={collections.data ?? []}
              collectionsNote={
                collections.isLoading
                  ? "Loading collections…"
                  : collections.error
                    ? (reportErrorText(collections.error) ?? errorMessage(collections.error))
                    : null
              }
            />
            <AttackGroup include={draft.include} onChange={setInclude} disabled={disabled} />
            <TimelineGroup include={draft.include} onChange={setInclude} disabled={disabled} />
            <NotesPicker
              include={draft.include}
              onChange={setInclude}
              disabled={disabled}
              notes={(notes.data ?? []).map((note) => ({
                id: note.id,
                body: note.body,
                author_name: note.author_name,
                updated_at: note.updated_at,
              }))}
              loading={notes.isLoading}
              error={notes.error}
            />
            <AiRunsPicker
              include={draft.include}
              onChange={setInclude}
              disabled={disabled}
              runs={aiRuns.runs}
              loading={aiRuns.isLoading}
              error={aiRuns.error}
            />
          </div>
          <CitedRowsPicker
            orgId={orgId}
            investigationId={report.investigation_id}
            include={draft.include}
            jobs={jobs.data ?? []}
            disabled={disabled}
            onAdd={(row) => {
              const result = addCitedRow(draft, row);
              if (!result.added) {
                toast.info(result.reason === "full" ? "The report already cites the maximum number of rows." : "Already cited.");
                return;
              }
              setDraft(result.draft);
              saver.change({ draft: result.draft });
            }}
            onRemove={(row) => {
              const next = removeCitedRow(draft, row);
              setDraft(next);
              saver.change({ draft: next });
            }}
          />
        </form>

        <aside className="flex flex-col gap-4" aria-label="Versions">
          <VersionList orgId={orgId} reportId={reportId} versions={versions.data ?? initial.versions} />
          {problems.length ? (
            <div className="rounded-md border p-3 text-xs">
              <p className="mb-1 font-medium">Before you finalize</p>
              <ul className="list-disc pl-4 text-muted-foreground">
                {problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </aside>
      </div>

      {preview.data ? <PreviewPanel orgId={orgId} preview={preview.data} /> : null}

      <FinalizeDialog
        open={finalizeOpen}
        onOpenChange={setFinalizeOpen}
        canDowngrade={canDowngrade}
        blockers={[...problems, ...(tlpPendingAck ? ["Confirm the lower TLP marking (or raise it) so the draft can be saved."] : [])]}
        summary={{
          tlp,
          caseTlp,
          profile,
          distribution,
          nextVersion: latestVersion + 1,
          counts: preview.data?.section_counts ?? null,
        }}
        onFinalize={finalize}
      />
    </div>
  );
}
