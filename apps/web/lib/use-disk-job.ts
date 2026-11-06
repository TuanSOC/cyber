"use client";

import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { type AnalysisStatus, type DiskProfile, type OsHint, pollWhileActive } from "@/lib/analysis";
import { ApiError, api, unwrap } from "@/lib/api";
import { saveDownload } from "@/lib/case";
import { DISK_PAGE, type DiskRunProfile, type FileQuery, nextOffset, sortByName } from "@/lib/disk";
import {
  type DiskExport,
  INTEROP_EXPORTS,
  type InteropExportName,
  exportSelection,
  rememberExports,
  rememberedExports,
} from "@/lib/disk-exports";
import { type TimelineCursor, type TimelineQuery, nextTimelineCursor } from "@/lib/disk-timeline";
import { sensitivityKey } from "@/lib/evidence-sensitivity";

/**
 * Hooks of the Forensics pages (M9 phase 11). Query keys live under the job
 * (`["org", org, "analysis", job, "disk", …]`) and the evidence (`["org", org, "evidence", …]`),
 * so the shared invalidations refresh them. A succeeded job's rows never change: their pages
 * are cached for good (`staleTime: Infinity`).
 */

const diskKey = (orgId: string, jobId: string) => ["org", orgId, "analysis", jobId, "disk"] as const;
const noClientRetry = (count: number, error: unknown) => !(error instanceof ApiError && error.status < 500) && count < 2;

/** Disk jobs of the org for the module list (`GET /analyses?analyzer=disk`). */
export function useDiskJobs({
  orgId,
  status,
  profile,
  investigationId,
  offset,
  pageSize,
}: {
  orgId: string;
  status?: AnalysisStatus;
  profile?: DiskProfile;
  investigationId?: string;
  offset: number;
  pageSize: number;
}) {
  const params = { analyzer: "disk" as const, profile, status, investigation_id: investigationId, limit: pageSize, offset };
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

/** The org's cases for the list filter (first 100, newest first). */
export function useCaseOptions(orgId: string) {
  return useQuery({
    queryKey: ["org", orgId, "forensics", "cases"],
    staleTime: 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations", {
          params: { path: { org_id: orgId }, query: { limit: 100 } },
        }),
      ).items,
  });
}

export function useDiskSummary(orgId: string, jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: [...diskKey(orgId, jobId), "summary"],
    enabled,
    retry: noClientRetry,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk", {
          params: { path: { org_id: orgId, job_id: jobId } },
        }),
      ),
  });
}

/** Every partition of the job (at most 128, the API's index range: two pages at most). */
export function useDiskPartitions(orgId: string, jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: [...diskKey(orgId, jobId), "partitions"],
    enabled,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async ({ signal }) => {
      const first = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/partitions", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { limit: DISK_PAGE, offset: 0 } },
          signal,
        }),
      );
      if (first.total <= first.items.length) return first;
      const second = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/partitions", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { limit: DISK_PAGE, offset: DISK_PAGE } },
          signal,
        }),
      );
      return { items: [...first.items, ...second.items], total: first.total };
    },
  });
}

/** The filtered file list in pages of `DISK_PAGE`, loaded as the table scrolls. */
export function useDiskFiles(orgId: string, jobId: string, query: FileQuery & { ref?: string }, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: [...diskKey(orgId, jobId), "files", query],
    enabled,
    staleTime: Number.POSITIVE_INFINITY,
    initialPageParam: 0,
    queryFn: async ({ pageParam, signal }) =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/files", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { ...query, limit: DISK_PAGE, offset: pageParam } },
          signal,
        }),
      ),
    getNextPageParam: (last, pages) => nextOffset(pages.reduce((n, page) => n + page.items.length, 0), last.total),
  });
}

/**
 * One directory's entries (`/dirs`): the root of a partition when `parent` is null. `parent`
 * is u64 text (an inode number): sent as text in the query string, never through `Number`.
 */
export function useDiskDir(orgId: string, jobId: string, partition: number | null, parent: string | null, enabled = true) {
  return useInfiniteQuery({
    queryKey: [...diskKey(orgId, jobId), "dir", partition, parent],
    enabled,
    staleTime: Number.POSITIVE_INFINITY,
    initialPageParam: 0,
    queryFn: async ({ pageParam, signal }) =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/dirs", {
          params: {
            path: { org_id: orgId, job_id: jobId },
            query: {
              limit: DISK_PAGE,
              offset: pageParam,
              ...(partition !== null ? { partition } : {}),
              // CONTRACT: `parent` is an int query parameter (≤ 2^64-1); a JS number loses bits
              // above 2^53, so the decimal text goes on the wire as is.
              ...(parent !== null ? { parent: parent as unknown as number } : {}),
            },
          },
          signal,
        }),
      ),
    getNextPageParam: (last, pages) => nextOffset(pages.reduce((n, page) => n + page.items.length, 0), last.total),
  });
}

export function useDiskFile(orgId: string, jobId: string, fileId: string | null) {
  return useQuery({
    queryKey: [...diskKey(orgId, jobId), "file", fileId],
    enabled: fileId !== null,
    staleTime: Number.POSITIVE_INFINITY,
    retry: noClientRetry,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/files/{file_id}", {
          params: { path: { org_id: orgId, job_id: jobId, file_id: fileId ?? "" } },
        }),
      ),
  });
}

/**
 * Events tied to one file: the API filters events by message text only, so the events whose
 * message names the file are fetched (first page) and kept when their `file_id` is the file.
 */
export function useDiskFileEvents(orgId: string, jobId: string, file: { id: string; name: string } | null) {
  const q = file && file.name.trim().length >= 2 ? file.name.trim().slice(0, 128) : null;
  return useQuery({
    queryKey: [...diskKey(orgId, jobId), "file-events", file?.id, q],
    enabled: file !== null && q !== null,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () => {
      const page = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/events", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { q: q ?? undefined, limit: DISK_PAGE, offset: 0 } },
        }),
      );
      return { items: page.items.filter((event) => event.file_id === file?.id), scanned: page.items.length, total: page.total };
    },
  });
}

/** Findings of the job's first page that cite the file (`evidence_refs` holds `file:<id>`). */
export function useDiskFileFindings(orgId: string, jobId: string, fileId: string | null) {
  const findings = useQuery({
    queryKey: ["org", orgId, "analysis", jobId, "findings", { limit: 100, offset: 0, disk_refs: true }],
    enabled: fileId !== null,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/findings", {
          params: { path: { org_id: orgId, job_id: jobId }, query: { limit: 100, offset: 0 } },
        }),
      ),
  });
  const ref = fileId ? `file:${fileId}` : null;
  return {
    ...findings,
    matches: ref ? (findings.data?.items ?? []).filter((f) => f.evidence_refs.includes(ref)) : [],
    partial: (findings.data?.total ?? 0) > (findings.data?.items.length ?? 0),
  };
}

/** The merged timeline, page by page (offset, then a time seek past the offset cap). */
export function useDiskTimeline(orgId: string, jobId: string, query: TimelineQuery | null, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: [...diskKey(orgId, jobId), "timeline", query],
    enabled: enabled && query !== null,
    staleTime: Number.POSITIVE_INFINITY,
    initialPageParam: { offset: 0 } as TimelineCursor,
    queryFn: async ({ pageParam, signal }) =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/timeline", {
          params: {
            path: { org_id: orgId, job_id: jobId },
            query: { ...query, ...(pageParam.from ? { from: pageParam.from } : {}), limit: DISK_PAGE, offset: pageParam.offset },
          },
          signal,
        }),
      ),
    getNextPageParam: (last, _pages, cursor) => nextTimelineCursor(cursor, last),
  });
}

// ---------------------------------------------------------------------------------------------
// Sensitivity of the segments (RT20)

/** The sensitivity of every segment (generic route; one request each, shared cache). */
export function useSegmentSensitivity(orgId: string, evidenceIds: readonly string[]) {
  return useQueries({
    queries: evidenceIds.map((evidenceId) => ({
      queryKey: sensitivityKey(orgId, evidenceId),
      retry: noClientRetry,
      queryFn: async () =>
        unwrap(
          await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/sensitivity", {
            params: { path: { org_id: orgId, evidence_id: evidenceId } },
          }),
        ),
    })),
  });
}

/** The evidence record (same key and request as the evidence page, so the cache is shared). */
export function useEvidenceRecord(orgId: string, evidenceId: string | undefined | null) {
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

/**
 * Admin batch release of a disk job's segments (`org.update`; RT20): one acknowledged request
 * with `job_id` releases every still-restricted segment. Every segment's sensitivity refreshes.
 */
export function useReleaseDiskJob(orgId: string, evidenceId: string, jobId: string, segmentIds: readonly string[]) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { acknowledge: boolean; reason: string }) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/sensitivity/release", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
          body: { ...body, job_id: jobId },
        }),
      ),
    onSuccess: async () => {
      await Promise.all([
        ...segmentIds.map((id) => queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", id] })),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "audit"] }),
      ]);
    },
  });
}

// ---------------------------------------------------------------------------------------------
// Run

/** Candidate segments: the case's evidence (up to 300 items, 3 pages), in natural name order. */
export function useSegmentCandidates(orgId: string, investigationId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["org", orgId, "evidence-list", investigationId, "disk-segments"],
    enabled,
    queryFn: async ({ signal }) => {
      const items = [];
      let total = 0;
      for (let offset = 0; offset < 300; offset += DISK_PAGE) {
        const page = unwrap(
          await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/evidence", {
            params: { path: { org_id: orgId, investigation_id: investigationId }, query: { limit: DISK_PAGE, offset } },
            signal,
          }),
        );
        items.push(...page.items);
        total = page.total;
        if (page.items.length < DISK_PAGE || items.length >= total) break;
      }
      return { items: sortByName(items), total, capped: items.length < total };
    },
  });
}

export function useRunDisk(orgId: string, evidenceId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ profile, osHint, segments }: { profile: DiskRunProfile; osHint: OsHint; segments: string[] }) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
          body: { analyzer: "disk", profile, os_hint: osHint, segments },
        }),
      ),
    onSettled: async (_job, _error, variables) => {
      await Promise.all([
        ...variables.segments.map((id) => queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", id] })),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] }),
      ]);
    },
  });
}

// ---------------------------------------------------------------------------------------------
// Exports

/** An audited interop download, saved under the server's file name (fallback: the catalog's). */
export function useInteropDownload(orgId: string, jobId: string) {
  return useMutation({
    mutationFn: async ({ name, excel }: { name: InteropExportName; excel?: boolean }) => {
      const fallback = INTEROP_EXPORTS.find((e) => e.name === name)?.fallback ?? "export.txt";
      return saveDownload(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/exports/{name}", {
          params: { path: { org_id: orgId, job_id: jobId, name }, query: excel ? { excel: true } : {} },
          parseAs: "blob",
        }),
        fallback,
      );
    },
  });
}

const exportsKey = (orgId: string, jobId: string) => [...diskKey(orgId, jobId), "file-exports"] as const;

/** The export ids this browser requested for the job (re-read from storage on mount). */
export function useRememberedExports(orgId: string, jobId: string) {
  return useQuery({
    queryKey: exportsKey(orgId, jobId),
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: () => rememberedExports(jobId),
  });
}

/** Request file exports (1..20 files; RT29); remembers the new export ids for this job. */
export function useRequestFileExports(orgId: string, jobId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (fileIds: Iterable<string>) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/analyses/{job_id}/disk/file-exports", {
          params: { path: { org_id: orgId, job_id: jobId } },
          body: { file_ids: exportSelection(fileIds) },
        }),
      ),
    onSuccess: async (list) => {
      for (const item of list.items) queryClient.setQueryData(["org", orgId, "disk-export", item.id], item);
      queryClient.setQueryData(exportsKey(orgId, jobId), rememberExports(jobId, list.items.map((item) => item.id)));
      await queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] });
    },
  });
}

/** One file export, polled while pending. */
export function useDiskExport(orgId: string, exportId: string) {
  return useQuery({
    queryKey: ["org", orgId, "disk-export", exportId],
    retry: noClientRetry,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/disk-exports/{export_id}", {
          params: { path: { org_id: orgId, export_id: exportId } },
        }),
      ),
    refetchInterval: (query) => (query.state.data?.state === "pending" ? 5000 : false),
  });
}

/** "Add to case as evidence": promotes a ready export into derived evidence. */
export function usePromoteExport(orgId: string, investigationId: string | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (exportId: string) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/disk-exports/{export_id}/promote", {
          params: { path: { org_id: orgId, export_id: exportId } },
        }),
      ),
    onSuccess: async (out: DiskExport) => {
      queryClient.setQueryData(["org", orgId, "disk-export", out.id], out);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence-list"] }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] }),
        ...(investigationId ? [queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigation", investigationId] })] : []),
      ]);
    },
  });
}

/** The custody events of derived evidence (first page), for the "Exported from" badge. */
export function useDerivedCustody(orgId: string, evidenceId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["org", orgId, "evidence", evidenceId, "custody", "derived-from"],
    enabled,
    staleTime: 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/custody", {
          params: { path: { org_id: orgId, evidence_id: evidenceId }, query: { limit: 25, offset: 0 } },
        }),
      ),
  });
}
