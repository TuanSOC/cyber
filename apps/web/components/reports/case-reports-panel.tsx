import Link from "next/link";

/**
 * The reports entry on a case page (M6 phase 1 stub; phase 7 replaces the body with the
 * case's report list and keeps these props).
 */
export function CaseReportsPanel({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const href = `/o/${encodeURIComponent(orgId)}/reports?investigation=${encodeURIComponent(investigationId)}`;
  return (
    <section aria-label="Reports" className="flex items-center justify-between rounded-md border p-4">
      <span className="text-sm font-medium">Reports</span>
      <Link href={href} className="text-sm underline underline-offset-4">
        View the reports of this case
      </Link>
    </section>
  );
}
