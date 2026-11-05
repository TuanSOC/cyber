"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { type AiRunCreate, type AiRunStatus, type AiTask, aiPollMs, isActiveAiRun } from "@/lib/ai";
import { api, unwrap } from "@/lib/api";

/*
 * React Query hooks for the AI analyst routes. Runs are polled only while active (2 s, then
 * until `resume_at` while waiting) and never once final.
 */

export const aiKeys = {
  all: (orgId: string) => ["org", orgId, "ai"] as const,
  settings: (orgId: string) => ["org", orgId, "ai", "settings"] as const,
  providers: (orgId: string) => ["org", orgId, "ai", "providers"] as const,
  runs: (orgId: string) => ["org", orgId, "ai", "runs"] as const,
  run: (orgId: string, runId: string) => ["org", orgId, "ai", "run", runId] as const,
  context: (orgId: string, runId: string) => ["org", orgId, "ai", "run", runId, "context"] as const,
};

/** The org's AI settings (read-only here; the Integrations page edits them). */
export function useAiSettings(orgId: string) {
  return useQuery({
    queryKey: aiKeys.settings(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/ai/settings", { params: { path: { org_id: orgId } } })),
    staleTime: 30_000,
  });
}

/** The provider catalog with this org's configuration (never a key). */
export function useAiProviders(orgId: string, enabled = true) {
  return useQuery({
    queryKey: aiKeys.providers(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/ai/providers", { params: { path: { org_id: orgId } } })),
    staleTime: 30_000,
    enabled,
  });
}

export type AiRunFilters = {
  job_id?: string;
  investigation_id?: string;
  task?: AiTask;
  status?: AiRunStatus;
  target_id?: string;
  limit?: number;
  offset?: number;
};

/** Top-level runs (newest first), polled while any listed run is active. */
export function useAiRuns(orgId: string, filters: AiRunFilters, enabled = true) {
  return useQuery({
    queryKey: [...aiKeys.runs(orgId), filters],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ai/runs", {
          params: { path: { org_id: orgId }, query: filters },
        }),
      ),
    placeholderData: keepPreviousData,
    enabled,
    refetchInterval: (query) => {
      const active = query.state.data?.items.find((run) => isActiveAiRun(run.status));
      return aiPollMs(active, query.state.dataUpdateCount, Date.now());
    },
  });
}

/**
 * One run with its output read model. `keep` asks for the pseudonyms as sent; otherwise the
 * API's default for the caller's role applies (original internal names for `evidence.write`,
 * pseudonyms kept for viewers: `reverse` is never sent, a viewer would get 403).
 * Polled while active; refreshes the run lists once it ends.
 */
export function useAiRun(orgId: string, runId: string | null, keep = false) {
  const queryClient = useQueryClient();
  const key = [...aiKeys.run(orgId, runId ?? ""), keep ? "keep" : "default"];
  return useQuery({
    queryKey: key,
    queryFn: async () => {
      const previous = queryClient.getQueryData<{ status: AiRunStatus }>(key);
      const next = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ai/runs/{run_id}", {
          params: {
            path: { org_id: orgId, run_id: runId ?? "" },
            query: keep ? { pseudonyms: "keep" } : {},
          },
        }),
      );
      if (previous && isActiveAiRun(previous.status) && !isActiveAiRun(next.status)) {
        void queryClient.invalidateQueries({ queryKey: aiKeys.runs(orgId) });
      }
      return next;
    },
    enabled: runId !== null,
    placeholderData: keepPreviousData,
    refetchInterval: (query) => aiPollMs(query.state.data, query.state.dataUpdateCount, Date.now()),
  });
}

/** The exact frozen context(s) a run sent; `reveal` adds the pseudonym map (original names). */
export function useAiRunContext(orgId: string, runId: string, reveal: boolean, enabled: boolean) {
  return useQuery({
    queryKey: [...aiKeys.context(orgId, runId), reveal],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ai/runs/{run_id}/context", {
          params: { path: { org_id: orgId, run_id: runId }, query: { reveal } },
        }),
      ),
    enabled,
    staleTime: Infinity, // frozen at request time
  });
}

export function useContextPreview(orgId: string) {
  return useMutation({
    mutationFn: async (body: AiRunCreate) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/ai/context-preview", {
          params: { path: { org_id: orgId } },
          body,
        }),
      ),
  });
}

export function useCreateAiRun(orgId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: AiRunCreate) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/ai/runs", {
          params: { path: { org_id: orgId } },
          body,
        }),
      ),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: aiKeys.runs(orgId) });
    },
  });
}
