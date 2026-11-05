"use client";

import { keepPreviousData, useInfiniteQuery, useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";

import { isUuid } from "@/lib/ai";
import { ApiError, api, unwrap } from "@/lib/api";
import {
  type RenderFormat,
  type ReportCreate,
  type ReportDetail,
  type ReportFinalize,
  createReport,
  discardReport,
  finalizeReport,
  getReport,
  getVersion,
  getVersionContent,
  isSelectableAiRun,
  listCaseReports,
  listRenders,
  listReports,
  listVersions,
  previewReport,
  renderPollMs,
  requestRender,
} from "@/lib/reports";

/*
 * React Query hooks of the reports module. Version content is immutable (signed): it is never
 * refetched in the background. Renders are polled only while one is queued or running.
 */

export const reportKeys = {
  all: (orgId: string) => ["org", orgId, "reports"] as const,
  list: (orgId: string, investigationId: string | null) => ["org", orgId, "reports", "list", investigationId] as const,
  case: (orgId: string, investigationId: string) => ["org", orgId, "reports", "case", investigationId] as const,
  detail: (orgId: string, reportId: string) => ["org", orgId, "reports", "detail", reportId] as const,
  versions: (orgId: string, reportId: string) => ["org", orgId, "reports", "versions", reportId] as const,
  version: (orgId: string, reportId: string, version: number) =>
    ["org", orgId, "reports", "version", reportId, version] as const,
  content: (orgId: string, reportId: string, version: number) =>
    ["org", orgId, "reports", "content", reportId, version] as const,
  renders: (orgId: string, reportId: string, version: number) =>
    ["org", orgId, "reports", "renders", reportId, version] as const,
};

/** No retries on 4xx (404, 409 integrity_failed, 501 not_implemented is 5xx but final). */
function retryUnlessClientError(count: number, error: unknown): boolean {
  if (error instanceof ApiError && (error.status < 500 || error.status === 501)) return false;
  return count < 2;
}

export function useReportList(orgId: string, investigationId: string | null) {
  return useInfiniteQuery({
    queryKey: reportKeys.list(orgId, investigationId),
    queryFn: ({ pageParam }) =>
      listReports(orgId, { investigation_id: investigationId, cursor: pageParam ?? null }),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor,
    retry: retryUnlessClientError,
  });
}

export function useCaseReports(orgId: string, investigationId: string, enabled = true) {
  return useQuery({
    queryKey: reportKeys.case(orgId, investigationId),
    queryFn: () => listCaseReports(orgId, investigationId),
    enabled: enabled && isUuid(investigationId),
    retry: retryUnlessClientError,
  });
}

export function useReport(orgId: string, reportId: string) {
  return useQuery({
    queryKey: reportKeys.detail(orgId, reportId),
    queryFn: () => getReport(orgId, reportId),
    enabled: isUuid(reportId),
    // The builder owns the draft while it is open: no refetch that could reset the form.
    refetchOnWindowFocus: false,
    staleTime: Infinity,
    retry: retryUnlessClientError,
  });
}

export function useReportVersions(orgId: string, reportId: string) {
  return useQuery({
    queryKey: reportKeys.versions(orgId, reportId),
    queryFn: () => listVersions(orgId, reportId),
    enabled: isUuid(reportId),
    retry: retryUnlessClientError,
  });
}

export function useReportVersion(orgId: string, reportId: string, version: number) {
  return useQuery({
    queryKey: reportKeys.version(orgId, reportId, version),
    queryFn: () => getVersion(orgId, reportId, version),
    enabled: isUuid(reportId) && version >= 1,
    retry: retryUnlessClientError,
  });
}

export function useVersionContent(orgId: string, reportId: string, version: number) {
  return useQuery({
    queryKey: reportKeys.content(orgId, reportId, version),
    queryFn: () => getVersionContent(orgId, reportId, version),
    enabled: isUuid(reportId) && version >= 1,
    staleTime: Infinity, // a signed version never changes
    refetchOnWindowFocus: false,
    retry: retryUnlessClientError,
  });
}

export function useRenders(orgId: string, reportId: string, version: number) {
  return useQuery({
    queryKey: reportKeys.renders(orgId, reportId, version),
    queryFn: () => listRenders(orgId, reportId, version),
    enabled: isUuid(reportId) && version >= 1,
    placeholderData: keepPreviousData,
    retry: retryUnlessClientError,
    refetchInterval: (query) => (query.state.error ? false : renderPollMs(query.state.data)),
  });
}

export function useRequestRender(orgId: string, reportId: string, version: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (format: RenderFormat) => requestRender(orgId, reportId, version, format),
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: reportKeys.renders(orgId, reportId, version) });
    },
  });
}

export function useCreateReport(orgId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ investigationId, body }: { investigationId: string; body: ReportCreate }) =>
      createReport(orgId, investigationId, body),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: reportKeys.all(orgId) });
    },
  });
}

export function useDiscardReport(orgId: string, reportId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => discardReport(orgId, reportId),
    onSuccess: async (detail) => {
      queryClient.setQueryData<ReportDetail>(reportKeys.detail(orgId, reportId), detail);
      await queryClient.invalidateQueries({ queryKey: reportKeys.all(orgId) });
    },
  });
}

/** On demand only (a button), never on keystrokes: the route is rate limited. */
export function usePreviewReport(orgId: string, reportId: string) {
  return useMutation({ mutationFn: () => previewReport(orgId, reportId) });
}

export function useFinalizeReport(orgId: string, reportId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: ReportFinalize) => finalizeReport(orgId, reportId, body),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: reportKeys.all(orgId) });
    },
  });
}

// ---------------------------------------------------------------------------------------------
// Picker data (the case's analyses, notes, IOC collections and AI runs)

export function useInvestigation(orgId: string, investigationId: string | null | undefined) {
  return useQuery({
    queryKey: ["org", orgId, "investigation", investigationId],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}", {
          params: { path: { org_id: orgId, investigation_id: investigationId ?? "" } },
        }),
      ),
    enabled: isUuid(investigationId),
    retry: retryUnlessClientError,
  });
}

/** Cases a report can be created for (newest first, archived cases left out). */
export function useReportableCases(orgId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["org", orgId, "reports", "cases"],
    queryFn: async () => {
      const page = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations", {
          params: { path: { org_id: orgId }, query: { limit: 100 } },
        }),
      );
      return page.items.filter((inv) => inv.status !== "archived");
    },
    enabled,
    staleTime: 30_000,
  });
}

export function useCaseJobs(orgId: string, investigationId: string) {
  return useQuery({
    queryKey: ["org", orgId, "reports", "case-jobs", investigationId],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses", {
          params: { path: { org_id: orgId }, query: { investigation_id: investigationId, limit: 100 } },
        }),
      ).items,
    enabled: isUuid(investigationId),
    staleTime: 30_000,
    retry: retryUnlessClientError,
  });
}

export function useCaseNotes(orgId: string, investigationId: string) {
  return useQuery({
    queryKey: ["org", orgId, "reports", "case-notes", investigationId],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/notes", {
          params: { path: { org_id: orgId, investigation_id: investigationId }, query: { limit: 100 } },
        }),
      ).items.filter((note) => !note.deleted && note.include_in_reports),
    enabled: isUuid(investigationId),
    staleTime: 30_000,
    retry: retryUnlessClientError,
  });
}

export function useCaseCollections(orgId: string, investigationId: string) {
  return useQuery({
    queryKey: ["org", orgId, "reports", "case-collections", investigationId],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/ioc-collections", {
          params: { path: { org_id: orgId, investigation_id: investigationId } },
        }),
      ).items.filter((collection) => !collection.archived),
    enabled: isUuid(investigationId),
    staleTime: 30_000,
    retry: retryUnlessClientError,
  });
}

/**
 * Completed AI runs of the case: the case-scope runs plus the job runs of its analyses.
 * Refused and canary-leak runs are never offered (`isSelectableAiRun`).
 */
export function useCaseAiRuns(orgId: string, investigationId: string, jobIds: readonly string[]) {
  const ids = jobIds.filter(isUuid).slice(0, 50);
  const queries = useQueries({
    queries: [
      { kind: "investigation_id" as const, id: investigationId },
      ...ids.map((id) => ({ kind: "job_id" as const, id })),
    ].map(({ kind, id }) => ({
      queryKey: ["org", orgId, "ai", "runs", { [kind]: id, status: "completed", limit: 100 }],
      queryFn: async () =>
        unwrap(
          await api.GET("/api/v1/orgs/{org_id}/ai/runs", {
            params: { path: { org_id: orgId }, query: { [kind]: id, status: "completed", limit: 100 } },
          }),
        ).items,
      enabled: isUuid(id),
      staleTime: 30_000,
    })),
  });
  const seen = new Set<string>();
  const runs = queries
    .flatMap((query) => query.data ?? [])
    .filter((run) => {
      if (seen.has(run.id) || !isSelectableAiRun(run)) return false;
      seen.add(run.id);
      return true;
    })
    .sort((a, b) => (b.finished_at ?? b.created_at).localeCompare(a.finished_at ?? a.created_at));
  return {
    runs,
    isLoading: queries.some((query) => query.isLoading),
    error: queries.find((query) => query.error)?.error ?? null,
  };
}

/** The first page of a job's findings or alerts, for the row picker. */
export function useJobRows(orgId: string, jobId: string | null, kind: "finding" | "alert") {
  return useQuery({
    queryKey: ["org", orgId, "reports", "job-rows", jobId, kind],
    queryFn: async () => {
      const params = { path: { org_id: orgId, job_id: jobId ?? "" }, query: { limit: 50 } };
      if (kind === "finding") {
        const page = unwrap(await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/findings", { params }));
        return page.items.map((row) => ({ id: row.id, label: row.title, severity: String(row.severity) }));
      }
      const page = unwrap(await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/alerts", { params }));
      return page.items.map((row) => ({ id: row.id, label: row.signature, severity: `sev ${row.severity}` }));
    },
    enabled: isUuid(jobId),
    staleTime: 30_000,
    retry: retryUnlessClientError,
  });
}
