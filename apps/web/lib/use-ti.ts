"use client";

import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api";
import { type IntegrationPage, type TiRun, attackIds, isActiveRun, runPollMs } from "@/lib/ti";

/*
 * React Query hooks for the threat intel routes. Nothing here ever holds an API key: keys are
 * sent once by the Integrations form (never through a mutation's cached variables) and no
 * response carries one.
 */

export const tiKeys = {
  all: (orgId: string) => ["org", orgId, "ti"] as const,
  integrations: (orgId: string) => ["org", orgId, "ti", "integrations"] as const,
  settings: (orgId: string) => ["org", orgId, "ti", "settings"] as const,
  runs: (orgId: string) => ["org", orgId, "ti", "runs"] as const,
  run: (orgId: string, runId: string) => ["org", orgId, "ti", "run", runId] as const,
  result: (orgId: string, resultId: string) => ["org", orgId, "ti", "result", resultId] as const,
  history: (orgId: string) => ["org", orgId, "ti", "history"] as const,
};

export function useIntegrations(
  orgId: string,
  poll: number | false | ((data: IntegrationPage | undefined) => number | false) = false,
) {
  return useQuery({
    queryKey: tiKeys.integrations(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/integrations", { params: { path: { org_id: orgId } } })),
    refetchInterval: typeof poll === "function" ? (query) => poll(query.state.data) : poll,
  });
}

export function useTiSettings(orgId: string) {
  return useQuery({
    queryKey: tiKeys.settings(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/ti/settings", { params: { path: { org_id: orgId } } })),
  });
}

/** One stored provider answer (append-only: never changes, so it is cached for good). */
export function useTiResult(orgId: string, resultId: string | null) {
  return useQuery({
    queryKey: tiKeys.result(orgId, resultId ?? ""),
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ti/results/{result_id}", {
          params: { path: { org_id: orgId, result_id: resultId ?? "" } },
        }),
      ),
    enabled: resultId !== null,
    staleTime: Infinity,
  });
}

/**
 * The newest run of a job (for the IOC tab's progress strip), polled with back-off while it
 * is queued / running / waiting. When it reaches a final state the IOC list is refreshed.
 */
export function useLatestJobRun(orgId: string, jobId: string) {
  const queryClient = useQueryClient();
  const key = [...tiKeys.runs(orgId), { job_id: jobId, limit: 1 }];
  return useQuery({
    queryKey: key,
    queryFn: async () => {
      const previous = queryClient.getQueryData<{ items: TiRun[] }>(key)?.items[0];
      const page = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ti/runs", {
          params: { path: { org_id: orgId }, query: { job_id: jobId, limit: 1 } },
        }),
      );
      const next = page.items[0];
      if (previous && next && previous.id === next.id && isActiveRun(previous.status) && !isActiveRun(next.status)) {
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "analysis", jobId, "iocs"] });
      }
      return page;
    },
    refetchInterval: (query) => runPollMs(query.state.data?.items[0]?.status, query.state.dataUpdateCount),
  });
}

/** A run with one page of its items (`state` / `provider` filters), polled while active. */
export function useRunDetail(
  orgId: string,
  runId: string | null,
  params: { limit?: number; offset?: number; state?: "pending" | "done" | "cached" | "abandoned" } = {},
) {
  return useQuery({
    queryKey: [...tiKeys.run(orgId, runId ?? ""), params],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ti/runs/{run_id}", {
          params: { path: { org_id: orgId, run_id: runId ?? "" }, query: params },
        }),
      ),
    enabled: runId !== null,
    placeholderData: keepPreviousData,
    refetchInterval: (query) => runPollMs(query.state.data?.status, query.state.dataUpdateCount),
  });
}

/**
 * Labels for ATT&CK ids from the offline index (one batched request per id set; the index is
 * static, so answers never go stale). With no ids it still returns `meta` (version, notice).
 */
export function useAttackLabels(ids: readonly string[]) {
  const wanted = attackIds(ids).sort();
  const joined = wanted.join(",");
  return useQuery({
    queryKey: ["attack", "techniques", joined],
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/attack/techniques", { params: { query: joined ? { ids: joined } : {} } })),
    staleTime: Infinity,
    gcTime: 60 * 60 * 1000,
  });
}
