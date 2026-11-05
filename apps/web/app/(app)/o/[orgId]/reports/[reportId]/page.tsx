"use client";

import { useParams } from "next/navigation";

import { ReportBuilder } from "@/components/reports/report-builder";
import { useOrg } from "@/lib/org-context";

/** The draft builder of one report. */
export default function ReportBuilderPage() {
  const { reportId } = useParams<{ reportId: string }>();
  const { orgId } = useOrg();
  return <ReportBuilder orgId={orgId} reportId={reportId} />;
}
