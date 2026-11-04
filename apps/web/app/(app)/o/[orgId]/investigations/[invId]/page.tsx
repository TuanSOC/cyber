"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { toast } from "sonner";

import { InvestigationAnalyses } from "@/components/analysis/investigation-analyses";
import { EvidenceTable } from "@/components/evidence/evidence-table";
import { EvidenceUploader } from "@/components/evidence/evidence-uploader";
import {
  EditInvestigationDialog,
  type InvestigationEdit,
} from "@/components/investigations/edit-investigation-dialog";
import { StatusControl } from "@/components/investigations/status-control";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { QueryError } from "@/components/query-error";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, api, errorMessage, unwrap } from "@/lib/api";
import { STATUS_LABELS, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";

type Change = InvestigationEdit & { status?: Schemas["InvestigationStatus"] };

export default function InvestigationPage() {
  const { invId } = useParams<{ invId: string }>();
  const { orgId, can } = useOrg();
  const queryClient = useQueryClient();
  const key = ["org", orgId, "investigation", invId];

  const investigation = useQuery({
    queryKey: key,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}", {
          params: { path: { org_id: orgId, investigation_id: invId } },
        }),
      ),
  });

  const update = useMutation({
    mutationFn: async (body: Change) =>
      unwrap(
        await api.PATCH("/api/v1/orgs/{org_id}/investigations/{investigation_id}", {
          params: { path: { org_id: orgId, investigation_id: invId } },
          body,
        }),
      ),
    onSuccess: async (updated) => {
      queryClient.setQueryData(key, updated);
      await queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigations"] });
      toast.success("Investigation updated");
    },
    onError: async (error) => {
      toast.error(errorMessage(error));
      await queryClient.invalidateQueries({ queryKey: key }); // stale data (e.g. 409): reload
    },
  });

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
            <SeverityBadge severity={inv.severity} />
            {writable && (
              <EditInvestigationDialog
                investigation={inv}
                pending={update.isPending}
                onSave={(changes) => update.mutateAsync(changes)}
              />
            )}
            {writable && inv.allowed_transitions.length > 0 ? (
              <StatusControl
                status={inv.status}
                allowed={inv.allowed_transitions}
                pending={update.isPending}
                onChange={(status) => update.mutate({ status })}
              />
            ) : (
              <Badge variant="secondary">{STATUS_LABELS[inv.status]}</Badge>
            )}
          </>
        }
      />
      {inv.description && (
        <p className="mb-6 max-w-3xl text-sm whitespace-pre-wrap text-muted-foreground">{inv.description}</p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Evidence</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {writable && can("evidence.write") && <EvidenceUploader orgId={orgId} investigationId={invId} />}
          {inv.status === "archived" && (
            <p className="text-sm text-muted-foreground">This investigation is archived and read-only.</p>
          )}
          <EvidenceTable orgId={orgId} investigationId={invId} />
        </CardContent>
      </Card>
      <InvestigationAnalyses orgId={orgId} investigationId={invId} />
    </>
  );
}
