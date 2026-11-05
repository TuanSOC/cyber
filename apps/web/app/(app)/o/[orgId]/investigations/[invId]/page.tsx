"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Suspense } from "react";
import { toast } from "sonner";

import { EditInvestigationDialog } from "@/components/investigations/edit-investigation-dialog";
import { CaseWorkspace } from "@/components/investigations/case-workspace";
import { StatusControl } from "@/components/investigations/status-control";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { SeverityBadge } from "@/components/severity-badge";
import { TlpBadge } from "@/components/tlp/tlp-badge";
import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/lib/api";
import { type InvestigationUpdate, caseErrorMessage } from "@/lib/case";
import { STATUS_LABELS, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { useInvestigation, useUpdateInvestigation } from "@/lib/use-case";

/** The case workspace page: a thin shell (header, status, edit) around the tabbed workspace. */
export default function InvestigationPage() {
  const { invId } = useParams<{ invId: string }>();
  const { orgId, can } = useOrg();
  const investigation = useInvestigation(orgId, invId);
  const update = useUpdateInvestigation(orgId, invId);
  const save = (body: InvestigationUpdate) =>
    update.mutateAsync(body).then(
      () => toast.success("Investigation updated"),
      (error: unknown) => {
        toast.error(caseErrorMessage(error));
      },
    );

  const back = orgPath(orgId, "investigations");
  if (investigation.error instanceof ApiError && investigation.error.status === 404) {
    return <NotFoundCard title="Investigation not found" backHref={back} backLabel="Investigations" />;
  }
  if (investigation.isError) {
    return <QueryError error={investigation.error} onRetry={() => void investigation.refetch()} />;
  }
  const inv = investigation.data;
  if (!inv) return <p className="text-sm text-muted-foreground">Loading investigation…</p>;

  const writable = can("investigation.write") && inv.status !== "archived";
  const created = formatDate(inv.created_at);

  return (
    <>
      <Link href={back} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Investigations
      </Link>
      <PageHeader
        title={inv.title}
        description={`${inv.case_ref} · opened by ${inv.created_by_name} · ${created.local}`}
        actions={
          <>
            <TlpBadge tlp={inv.tlp} />
            <SeverityBadge severity={inv.severity} />
            {writable && (
              <EditInvestigationDialog
                investigation={inv}
                pending={update.isPending}
                onSave={(changes) =>
                  // Rejects on error so the dialog stays open with the user's input.
                  update.mutateAsync(changes).then(
                    () => toast.success("Investigation updated"),
                    (error: unknown) => {
                      toast.error(caseErrorMessage(error));
                      throw error;
                    },
                  )
                }
              />
            )}
            {writable && inv.allowed_transitions.length > 0 ? (
              <StatusControl
                status={inv.status}
                allowed={inv.allowed_transitions}
                pending={update.isPending}
                onChange={(status, reason) => void save(reason ? { status, status_reason: reason } : { status })}
              />
            ) : (
              <Badge variant="secondary">{STATUS_LABELS[inv.status]}</Badge>
            )}
          </>
        }
      />
      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading the case…</p>}>
        <CaseWorkspace orgId={orgId} inv={inv} can={can} pending={update.isPending} onUpdate={(body) => void save(body)} />
      </Suspense>
    </>
  );
}
