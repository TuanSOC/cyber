"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api";
import { sensitivityKey } from "@/lib/evidence-sensitivity";

/** The generic sensitivity of one evidence item (state + source; M9, RT2). */
export function useEvidenceSensitivity(orgId: string, evidenceId: string, enabled = true) {
  return useQuery({
    queryKey: sensitivityKey(orgId, evidenceId),
    enabled,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/sensitivity", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
        }),
      ),
  });
}

/** Admin release (`org.update`), once, acknowledged, with a reason (audited by source). */
export function useReleaseEvidence(orgId: string, evidenceId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { acknowledge: boolean; reason: string }) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/sensitivity/release", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
          body,
        }),
      ),
    onSuccess: async (released) => {
      queryClient.setQueryData(sensitivityKey(orgId, evidenceId), released);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", evidenceId] }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "audit"] }),
      ]);
    },
  });
}
