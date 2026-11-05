"use client";

/**
 * Slot (M7 phase 1, RT16): the "also seen in" pivot of a job's observables, mounted once in
 * `components/analysis/iocs-tab.tsx` (pcap and static job pages). Phase 8 fills it from
 * `GET /orgs/{org}/analyses/{job}/correlations`. Renders nothing until then.
 */
export function IocSeenIn({ orgId, jobId }: { orgId: string; jobId: string }) {
  void orgId;
  void jobId;
  return null;
}
