"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Archive, Download, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { ConfirmButton } from "@/components/confirm-button";
import { Button } from "@/components/ui/button";
import { api, errorMessage, unwrap } from "@/lib/api";

type Evidence = Schemas["EvidenceOut"];
type Verify = Schemas["VerifyOut"];

export function EvidenceActions({
  orgId,
  evidence,
  canWrite,
  investigationArchived,
  onVerified,
}: {
  orgId: string;
  evidence: Evidence;
  canWrite: boolean;
  investigationArchived: boolean;
  onVerified: (result: Verify) => void;
}) {
  const queryClient = useQueryClient();
  const path = { org_id: orgId, evidence_id: evidence.id };
  const key = ["org", orgId, "evidence", evidence.id];
  const refreshCustody = () => queryClient.invalidateQueries({ queryKey: [...key, "custody"] });

  const verify = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/verify", { params: { path } })),
    onSuccess: async (result) => {
      onVerified(result);
      await refreshCustody();
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const archive = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/archive", { params: { path } })),
    onSuccess: async (updated) => {
      queryClient.setQueryData(key, updated);
      await refreshCustody();
      toast.success("Evidence archived");
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  async function download() {
    // Make sure the access cookie is fresh (refreshes on 401) before the browser takes over.
    try {
      unwrap(await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}", { params: { path } }));
    } catch (error) {
      toast.error(errorMessage(error));
      return;
    }
    // `download` keeps the app on screen even if the server answers with an error.
    const link = document.createElement("a");
    link.href = `/api/v1/orgs/${encodeURIComponent(orgId)}/evidence/${encodeURIComponent(evidence.id)}/download`;
    link.download = "";
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => void refreshCustody(), 1500);
  }

  return (
    <>
      <Button variant="outline" size="sm" onClick={download}>
        <Download className="size-4" aria-hidden /> Download
      </Button>
      {canWrite && (
        <Button size="sm" disabled={verify.isPending} onClick={() => verify.mutate()}>
          <ShieldCheck className="size-4" aria-hidden />
          {verify.isPending ? "Verifying…" : "Verify"}
        </Button>
      )}
      {canWrite && !investigationArchived && evidence.status !== "archived" && (
        <ConfirmButton
          variant="ghost"
          size="sm"
          title="Archive this evidence?"
          description="Archived evidence stays stored, hashed and downloadable, but is marked inactive. This cannot be undone in M1."
          confirmLabel="Archive"
          pending={archive.isPending}
          onConfirm={() => archive.mutate()}
        >
          <Archive className="size-4" aria-hidden /> Archive
        </ConfirmButton>
      )}
    </>
  );
}
