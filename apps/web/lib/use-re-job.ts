"use client";

import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { type AnalysisJob, type AnalysisStatus, pollWhileActive } from "@/lib/analysis";
import { ApiError, api, unwrap } from "@/lib/api";
import {
  type CapabilityFunctions,
  type FunctionCode,
  type FunctionDetail,
  type FunctionFilters,
  type Page,
  type ReFunction,
  type ReImport,
  type ReProfileName,
  type ReString,
  type ReSummary,
  functionQuery,
} from "@/lib/reverse";

/**
 * Hooks of the Reverse Engineering pages (M10 phase 10). Query keys live under the job
 * (`["org", org, "analysis", job, "reverse", …]`) so the shared invalidations refresh them.
 *
 * The RE read routes are frozen in phase 1 (`reverse_engineering/router.py`) but not yet in
 * the generated contracts (regenerated in Docker after the merge), so these calls go through
 * `reGet` with the hand-written types of `lib/reverse.ts`; the path templates are the API's.
 */

type Query = Record<string, string | number | boolean | undefined>;

// The typed client, loosened for paths the generated contracts do not list yet.
const untyped = api as unknown as {
  GET: (
    path: string,
    init: { params: { path: Record<string, string>; query?: Query }; signal?: AbortSignal },
  ) => Promise<{ data?: unknown; error?: unknown; response: Response }>;
  POST: (
    path: string,
    init: { params: { path: Record<string, string> }; body: unknown },
  ) => Promise<{ data?: unknown; error?: unknown; response: Response }>;
};

async function reGet<T>(path: string, params: Record<string, string>, query?: Query, signal?: AbortSignal): Promise<T> {
  return unwrap(await untyped.GET(path, { params: { path: params, query }, signal })) as T;
}

const JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}";
const RE = `${JOB}/reverse`;
/** The API's page size and offset cap (`core/pagination.py`). */
export const RE_PAGE = 100;
export const RE_MAX_OFFSET = 10_000;

const reKey = (orgId: string, jobId: string) => ["org", orgId, "analysis", jobId, "reverse"] as const;
const noRetryOn4xx = (count: number, error: unknown) => !(error instanceof ApiError && error.status < 500) && count < 2;

/** RE jobs of the org for the module list (`GET /analyses?analyzer=reverse`), newest first. */
export function useReJobs({
  orgId,
  status,
  profile,
  offset,
  pageSize,
}: {
  orgId: string;
  status?: AnalysisStatus;
  profile?: ReProfileName;
  offset: number;
  pageSize: number;
}) {
  const query: Query = { analyzer: "reverse", profile, status, limit: pageSize, offset };
  return useQuery({
    queryKey: ["org", orgId, "analyses", query],
    queryFn: async () => reGet<Page<AnalysisJob>>("/api/v1/orgs/{org_id}/analyses", { org_id: orgId }, query),
    placeholderData: keepPreviousData,
    refetchInterval: (q) => pollWhileActive(q.state.data?.items ?? []),
  });
}

/** Program facts, stage strip and counts (`404` until the job has results). */
export function useReSummary(orgId: string, jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: [...reKey(orgId, jobId), "summary"],
    enabled,
    retry: noRetryOn4xx,
    queryFn: async () => reGet<ReSummary>(RE, { org_id: orgId, job_id: jobId }),
  });
}

/** Server-paginated functions (pages of `RE_PAGE`, up to the offset cap), for the windowed table. */
export function useReFunctions(orgId: string, jobId: string, filters: FunctionFilters, ref: string | null, enabled: boolean) {
  const query = { ...functionQuery(filters), ...(ref ? { ref } : {}) };
  return useInfiniteQuery({
    queryKey: [...reKey(orgId, jobId), "functions", query],
    enabled,
    retry: noRetryOn4xx,
    initialPageParam: 0,
    queryFn: async ({ pageParam, signal }) =>
      reGet<Page<ReFunction>>(`${RE}/functions`, { org_id: orgId, job_id: jobId }, { ...query, limit: RE_PAGE, offset: pageParam }, signal),
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((n, page) => n + page.items.length, 0);
      if (last.items.length === 0 || loaded >= last.total) return undefined;
      return loaded > RE_MAX_OFFSET ? undefined : loaded;
    },
    placeholderData: keepPreviousData,
    staleTime: Number.POSITIVE_INFINITY, // a succeeded job's rows never change
  });
}

export function useReFunction(orgId: string, jobId: string, entry: string | null) {
  return useQuery({
    queryKey: [...reKey(orgId, jobId), "function", entry],
    enabled: entry !== null,
    retry: noRetryOn4xx,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () => reGet<FunctionDetail>(`${RE}/functions/{entry}`, { org_id: orgId, job_id: jobId, entry: entry ?? "" }),
  });
}

export function useReCode(orgId: string, jobId: string, entry: string | null, enabled: boolean) {
  return useQuery({
    queryKey: [...reKey(orgId, jobId), "code", entry],
    enabled: enabled && entry !== null,
    retry: noRetryOn4xx,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () => reGet<FunctionCode>(`${RE}/functions/{entry}/code`, { org_id: orgId, job_id: jobId, entry: entry ?? "" }),
  });
}

export function useReImports(orgId: string, jobId: string, q: string, ref: string | null, offset: number) {
  const query: Query = { q: q || undefined, ref: ref ?? undefined, limit: RE_PAGE, offset };
  return useQuery({
    queryKey: [...reKey(orgId, jobId), "imports", query],
    retry: noRetryOn4xx,
    placeholderData: keepPreviousData,
    queryFn: async () => reGet<Page<ReImport>>(`${RE}/imports`, { org_id: orgId, job_id: jobId }, query),
  });
}

export function useReStrings(orgId: string, jobId: string, q: string, referenced: boolean | null, ref: string | null, offset: number) {
  const query: Query = { q: q || undefined, referenced: referenced ?? undefined, ref: ref ?? undefined, limit: RE_PAGE, offset };
  return useQuery({
    queryKey: [...reKey(orgId, jobId), "strings", query],
    retry: noRetryOn4xx,
    placeholderData: keepPreviousData,
    queryFn: async () => reGet<Page<ReString>>(`${RE}/strings`, { org_id: orgId, job_id: jobId }, query),
  });
}

/** The functions of the newest RE job of the sample containing a capability (Malware Lab). */
export function useCapabilityFunctions(orgId: string, staticJobId: string, capabilityId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["org", orgId, "analysis", staticJobId, "capabilities", capabilityId, "functions"],
    enabled,
    retry: noRetryOn4xx,
    queryFn: async () =>
      reGet<CapabilityFunctions>(`${JOB}/capabilities/{capability_id}/functions`, {
        org_id: orgId,
        job_id: staticJobId,
        capability_id: capabilityId,
      }),
  });
}

export type ReRunRequest = {
  evidenceId: string;
  sourceJobId: string;
  profile: ReProfileName;
  /** `0x…` entries decompiled first (`full` only; "Decompile this function", RT10). */
  decompileAddresses?: string[];
};

/** Request an RE job (never automatic): `POST /evidence/{id}/analyses` with `analyzer: reverse`. */
export function useRunRe(orgId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (req: ReRunRequest) =>
      unwrap(
        await untyped.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path: { org_id: orgId, evidence_id: req.evidenceId } },
          body: {
            analyzer: "reverse",
            profile: req.profile,
            source_job_id: req.sourceJobId,
            ...(req.profile === "full" && req.decompileAddresses?.length ? { decompile_addresses: req.decompileAddresses } : {}),
          },
        }),
      ) as AnalysisJob,
    onSettled: async (_data, _error, req) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", req.evidenceId] }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] }),
      ]);
    },
  });
}

/** An RE job of this sample that is still queued or running (disables "Decompile this function"). */
export function useActiveReJob(orgId: string, evidenceId: string | undefined) {
  return useQuery({
    queryKey: ["org", orgId, "evidence", evidenceId, "analyses", "reverse-active"],
    enabled: Boolean(evidenceId),
    queryFn: async () => {
      const page = await reGet<Page<AnalysisJob>>(
        "/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses",
        { org_id: orgId, evidence_id: evidenceId ?? "" },
        { limit: 50, offset: 0 },
      );
      return page.items.find((job) => job.analyzer === "reverse" && (job.status === "queued" || job.status === "running")) ?? null;
    },
    refetchInterval: (q) => (q.state.data ? 5_000 : false),
  });
}
