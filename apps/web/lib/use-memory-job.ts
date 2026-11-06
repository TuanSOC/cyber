"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { type AnalysisStatus, type MemoryProfile, type OsHint, pollWhileActive } from "@/lib/analysis";
import { ApiError, api, unwrap } from "@/lib/api";
import { type MemoryProcess, TREE_MAX_NODES, TREE_PAGE } from "@/lib/memory";

/**
 * Hooks of the Memory Analysis pages (M8 phase 9). Query keys live under the job
 * (`["org", org, "analysis", job, "memory", …]`) and the evidence
 * (`["org", org, "evidence", evidence, …]`), so the shared invalidations refresh them.
 */

const memoryKey = (orgId: string, jobId: string) => ["org", orgId, "analysis", jobId, "memory"] as const;
const sensitivityKey = (orgId: string, evidenceId: string) =>
  ["org", orgId, "evidence", evidenceId, "memory-sensitivity"] as const;

/** Memory jobs of the org for the module list (`GET /analyses?analyzer=memory`). */
export function useMemoryJobs({
  orgId,
  status,
  profile,
  offset,
  pageSize,
}: {
  orgId: string;
  status?: AnalysisStatus;
  profile?: MemoryProfile;
  offset: number;
  pageSize: number;
}) {
  const params = { analyzer: "memory" as const, profile, status, limit: pageSize, offset };
  return useQuery({
    queryKey: ["org", orgId, "analyses", params],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses", {
          params: { path: { org_id: orgId }, query: params },
        }),
      ),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => pollWhileActive(query.state.data?.items ?? []),
  });
}

/** The job's image facts, symbols outcome and plugin status (also for a `symbols_missing` job). */
export function useMemorySummary(orgId: string, jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: [...memoryKey(orgId, jobId), "summary"],
    enabled,
    retry: (count, error) => !(error instanceof ApiError && error.status < 500) && count < 2,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory", {
          params: { path: { org_id: orgId, job_id: jobId } },
        }),
      ),
  });
}

/** The evidence record (same key and request as the evidence page, so the cache is shared). */
export function useEvidenceRecord(orgId: string, evidenceId: string | undefined) {
  return useQuery({
    queryKey: ["org", orgId, "evidence", evidenceId],
    enabled: Boolean(evidenceId),
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}", {
          params: { path: { org_id: orgId, evidence_id: evidenceId ?? "" } },
        }),
      ),
  });
}

export function useMemorySensitivity(orgId: string, evidenceId: string | undefined) {
  return useQuery({
    queryKey: sensitivityKey(orgId, evidenceId ?? ""),
    enabled: Boolean(evidenceId),
    retry: (count, error) => !(error instanceof ApiError && error.status < 500) && count < 2,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/memory-sensitivity", {
          params: { path: { org_id: orgId, evidence_id: evidenceId ?? "" } },
        }),
      ),
  });
}

/** Admin release (`org.update`, acknowledgement and reason; once). */
export function useReleaseMemory(orgId: string, evidenceId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { acknowledge: boolean; reason: string }) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/memory-sensitivity/release", {
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

/** Request a memory run (also the "Re-run" of a `symbols_missing` job). */
export function useRunMemory(orgId: string, evidenceId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ profile, osHint }: { profile: MemoryProfile; osHint: OsHint }) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
          body: { analyzer: "memory", profile, os_hint: osHint },
        }),
      ),
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", evidenceId] }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] }),
      ]);
    },
  });
}

/**
 * Every process of the job for the tree view, in pages of `TREE_PAGE` (≤ 200 rows per request),
 * up to `TREE_MAX_NODES`. `capped` means the job has more: the page shows the list view instead.
 */
export function useAllProcesses(orgId: string, jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: [...memoryKey(orgId, jobId), "processes", "all"],
    enabled,
    staleTime: Number.POSITIVE_INFINITY, // a succeeded job's rows never change
    queryFn: async ({ signal }) => {
      const items: MemoryProcess[] = [];
      let total = 0;
      for (let offset = 0; offset < TREE_MAX_NODES; offset += TREE_PAGE) {
        const page = unwrap(
          await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/processes", {
            params: { path: { org_id: orgId, job_id: jobId }, query: { limit: TREE_PAGE, offset } },
            signal,
          }),
        );
        items.push(...page.items);
        total = page.total;
        if (page.items.length < TREE_PAGE || items.length >= total) break;
      }
      return { items, total, capped: total > TREE_MAX_NODES || items.length < total };
    },
  });
}

/** One process with its parent, children, connections, memory regions and artifacts. */
export function useProcessDetail(orgId: string, jobId: string, pid: number | null) {
  return useQuery({
    queryKey: [...memoryKey(orgId, jobId), "process", pid],
    enabled: pid !== null,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/processes/{pid}", {
          params: { path: { org_id: orgId, job_id: jobId, pid: pid ?? 0 } },
        }),
      ),
  });
}

/** Findings and memory regions of the first page, for the process flags of the tree / list. */
export function useFlagSources(orgId: string, jobId: string, enabled: boolean) {
  const findings = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "findings", { limit: 100, offset: 0, flags: true }],
    enabled,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/findings", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { limit: 100, offset: 0 } },
        }),
      ),
  });
  const injections = useQuery({
    queryKey: [...memoryKey(orgId, jobId), "injections", { limit: 100, offset: 0, flags: true }],
    enabled,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/memory/injections", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { limit: 100, offset: 0 } },
        }),
      ),
  });
  return { findings, injections };
}
