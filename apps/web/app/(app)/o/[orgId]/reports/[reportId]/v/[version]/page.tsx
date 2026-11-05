"use client";

import { useParams, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { NotFoundCard } from "@/components/not-found-card";
import { VersionViewer } from "@/components/reports/version-viewer";
import { useOrg } from "@/lib/org-context";
import { reportsHref } from "@/lib/report-format";

/** The viewer of one signed report version. */
export default function ReportVersionPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
      <Viewer />
    </Suspense>
  );
}

function Viewer() {
  const { reportId, version } = useParams<{ reportId: string; version: string }>();
  const searchParams = useSearchParams();
  const { orgId } = useOrg();
  const number = /^\d{1,6}$/.test(version) ? Number(version) : 0;
  if (number < 1) return <NotFoundCard title="Report version not found" backHref={reportsHref(orgId)} backLabel="Reports" />;
  return (
    <VersionViewer
      orgId={orgId}
      reportId={reportId}
      version={number}
      focusTitle={searchParams.get("finalized") === "1"}
    />
  );
}
