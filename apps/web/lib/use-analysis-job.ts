"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";

import { type AnalysisJob, justSucceeded, pollWhileActive } from "@/lib/analysis";
import { api, unwrap } from "@/lib/api";

/** One analysis job, polled while queued / running; refreshes evidence and lists when it succeeds. */
export function useAnalysisJob(orgId: string, jobId: string) {
  const queryClient = useQueryClient();
  const key = ["org", orgId, "analysis", jobId];
  return useQuery({
    queryKey: key,
    queryFn: async () => {
      const previous = queryClient.getQueryData<AnalysisJob>(key);
      const next = unwrap(
        await api.GET("/api/v1/orgs/{org_id}/analyses/{job_id}", {
          params: { path: { org_id: orgId, job_id: jobId } },
        }),
      );
      if (justSucceeded(previous ? [previous] : undefined, [next])) {
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", next.evidence_id] });
        void queryClient.invalidateQueries({ queryKey: ["org", orgId, "analyses"] });
      }
      return next;
    },
    refetchInterval: (query) => pollWhileActive(query.state.data ? [query.state.data] : undefined),
  });
}
