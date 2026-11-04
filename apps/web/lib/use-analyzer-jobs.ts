"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import {
  type AnalysisStatus,
  type Analyzer,
  type StaticProfile,
  pollWhileActive,
} from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";

/**
 * One analyzer's jobs for a module list (PCAP Analyzer, Malware Lab), filtered and paged by
 * the API (`analyzer`, `profile`, `status`).
 */
export function useAnalyzerJobs({
  orgId,
  analyzer,
  status,
  profile,
  offset,
  pageSize,
}: {
  orgId: string;
  analyzer: Analyzer;
  status?: AnalysisStatus;
  profile?: StaticProfile;
  offset: number;
  pageSize: number;
}) {
  const params = { analyzer, profile, status, limit: pageSize, offset };
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
