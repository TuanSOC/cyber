"use client";

import { useMutation } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";
import { toast } from "sonner";

import { NotFoundCard } from "@/components/not-found-card";
import { QueryError } from "@/components/query-error";
import { INTEGRITY_FAILED, type Integrity, IntegrityStrip } from "@/components/reports/integrity-strip";
import { ReportRenders } from "@/components/reports/report-renders";
import { ReportView } from "@/components/reports/report-view";
import { VersionList } from "@/components/reports/version-list";
import { ApiError, errorMessage } from "@/lib/api";
import { useOrg } from "@/lib/org-context";
import { downloadFilename, reportsHref } from "@/lib/report-format";
import { downloadSignature, hasCode, reportErrorText, saveBlob } from "@/lib/reports";
import { useReportVersion, useReportVersions, useVersionContent } from "@/lib/use-reports";

/**
 * One signed version: its snapshot (`…/content`) in the viewer, the integrity status of the
 * stored object and signature, the renditions and downloads, and the other versions.
 */
export function VersionViewer({
  orgId,
  reportId,
  version,
  focusTitle = false,
}: {
  orgId: string;
  reportId: string;
  version: number;
  focusTitle?: boolean;
}) {
  const { can } = useOrg();
  const detail = useReportVersion(orgId, reportId, version);
  const content = useVersionContent(orgId, reportId, version);
  const versions = useReportVersions(orgId, reportId);
  const signature = useMutation({
    mutationFn: async () => {
      const file = await downloadSignature(orgId, reportId, version);
      saveBlob(file.blob, downloadFilename(file.disposition, `report-v${version}.sig.json`));
    },
    onError: (error) => toast.error(reportErrorText(error) ?? errorMessage(error)),
  });

  const loaded = Boolean(content.data);
  useEffect(() => {
    // After finalize: move focus to the new version's title (screen readers announce it).
    if (focusTitle && loaded) document.getElementById("report-title")?.focus();
  }, [focusTitle, loaded]);

  const notFound = [detail.error, content.error].some((e) => e instanceof ApiError && (e.status === 404 || e.status === 422));
  if (notFound) return <NotFoundCard title="Report version not found" backHref={reportsHref(orgId)} backLabel="Reports" />;

  const integrity: Integrity | null = detail.data
    ? {
        snapshotOk: detail.data.snapshot_ok,
        signatureValid: detail.data.signature_valid,
        kid: detail.data.version.kid,
        sha256: detail.data.version.snapshot_sha256,
      }
    : null;
  const integrityFailed = hasCode(content.error, "integrity_failed");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3 print:hidden">
        <Link
          href={reportsHref(orgId, reportId)}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-4" aria-hidden /> Draft and versions
        </Link>
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="min-w-0">
          {integrityFailed ? (
            <div className="flex flex-col gap-3">
              <p role="alert" className="rounded-md border border-destructive bg-destructive/5 p-3 text-sm font-semibold text-destructive">
                {INTEGRITY_FAILED}: the stored snapshot of version {version} does not match its recorded hash, so it is not shown.
                This is recorded in the audit log.
              </p>
              {integrity ? <IntegrityStrip integrity={integrity} /> : null}
            </div>
          ) : content.isError ? (
            <QueryError error={content.error} onRetry={() => void content.refetch()} />
          ) : !content.data ? (
            <p className="text-sm text-muted-foreground">Loading version {version}…</p>
          ) : (
            <ReportView
              orgId={orgId}
              snapshot={content.data}
              integrity={integrity}
              onDownloadSignature={() => signature.mutate()}
              signaturePending={signature.isPending}
            />
          )}
          {detail.isError ? (
            <div className="mt-4">
              <p className="mb-2 text-sm text-destructive">The integrity status could not be loaded.</p>
              <QueryError error={detail.error} onRetry={() => void detail.refetch()} />
            </div>
          ) : null}
        </div>
        <aside className="flex flex-col gap-4 print:hidden" aria-label="Version tools">
          <ReportRenders
            orgId={orgId}
            reportId={reportId}
            version={version}
            canRender={can("investigation.write")}
            canDownload={can("evidence.read")}
          />
          <VersionList orgId={orgId} reportId={reportId} versions={versions.data ?? []} current={version} />
        </aside>
      </div>
    </div>
  );
}
