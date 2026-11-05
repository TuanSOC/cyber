"use client";

import type { Schemas } from "@cyberlab/contracts";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

import { EvidenceAnalysesCard } from "@/components/analysis/evidence-analyses-card";
import { CustodyTimeline } from "@/components/evidence/custody-timeline";
import { EvidenceActions } from "@/components/evidence/evidence-actions";
import { EvidenceIntegrityStrip } from "@/components/evidence/evidence-integrity-strip";
import { HashValue } from "@/components/hash-value";
import { EvidenceExclusionBadges, EvidenceSharePolicyCard } from "@/components/investigations/evidence-share-policy";
import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, api, unwrap } from "@/lib/api";
import { formatBytes, formatDate } from "@/lib/format";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";

const CUSTODY_PAGE = 50;
const VERIFY_TITLES: Record<Schemas["VerifyOut"]["result"], string> = {
  ok: "Integrity verified: stored bytes match the recorded hashes.",
  mismatch: "Integrity check FAILED: stored bytes do not match the recorded hashes.",
  missing: "Stored content is missing.",
};

export default function EvidencePage() {
  const { evidenceId } = useParams<{ evidenceId: string }>();
  const { orgId, can } = useOrg();
  const [verify, setVerify] = useState<Schemas["VerifyOut"] | null>(null);
  const [custodyOffset, setCustodyOffset] = useState(0);
  const path = { org_id: orgId, evidence_id: evidenceId };
  const key = ["org", orgId, "evidence", evidenceId];

  const evidence = useQuery({
    queryKey: key,
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}", { params: { path } })),
  });
  const investigationId = evidence.data?.investigation_id;
  const investigation = useQuery({
    queryKey: ["org", orgId, "investigation", investigationId],
    enabled: Boolean(investigationId),
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}", {
          params: { path: { org_id: orgId, investigation_id: investigationId ?? "" } },
        }),
      ),
  });
  const custody = useQuery({
    queryKey: [...key, "custody", custodyOffset],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/custody", {
          params: { path, query: { limit: CUSTODY_PAGE, offset: custodyOffset } },
        }),
      ),
    placeholderData: keepPreviousData,
    refetchOnWindowFocus: true, // a download started in this tab is recorded server-side
  });

  const back = orgPath(orgId, "investigations");
  if (evidence.error instanceof ApiError && evidence.error.status === 404) {
    return <NotFoundCard title="Evidence not found" backHref={back} backLabel="Investigations" />;
  }
  if (evidence.isError) return <QueryError error={evidence.error} onRetry={() => void evidence.refetch()} />;
  const e = evidence.data;
  if (!e) return <p className="text-sm text-muted-foreground">Loading evidence…</p>;
  const uploaded = formatDate(e.uploaded_at);

  return (
    <>
      <Link href={orgPath(orgId, `investigations/${e.investigation_id}`)}
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Investigation
      </Link>
      <PageHeader
        title={e.original_filename}
        description={`${formatBytes(e.size_bytes)} · uploaded by ${e.uploaded_by_name} · ${uploaded.local}`}
        actions={
          <>
            {e.status === "archived" && <Badge variant="outline">archived</Badge>}
            <EvidenceExclusionBadges evidence={e} />
            <EvidenceActions
              orgId={orgId}
              evidence={e}
              canWrite={can("evidence.write")}
              investigationArchived={investigation.data?.status === "archived"}
              onVerified={setVerify}
            />
          </>
        }
      />
      {/* M7 slot: purged bytes and declared vs detected type (phase 9). */}
      <EvidenceIntegrityStrip evidence={e} />
      {verify && (
        <Alert variant={verify.result === "ok" ? "default" : "destructive"} className="mb-6">
          <AlertTitle>{VERIFY_TITLES[verify.result]}</AlertTitle>
          {verify.actual && verify.result !== "ok" && (
            <AlertDescription className="font-mono text-xs break-all">
              actual sha256 {verify.actual.sha256}
            </AlertDescription>
          )}
        </Alert>
      )}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,22rem)]">
        <div className="flex min-w-0 flex-col gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Integrity</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3 text-sm">
              {(["sha256", "sha1", "md5"] as const).map((algo) => (
                <div key={algo}>
                  <p className="text-xs text-muted-foreground uppercase">{algo}</p>
                  {e.hashes[algo] && <HashValue value={e.hashes[algo]} />}
                </div>
              ))}
              <div>
                <p className="text-xs text-muted-foreground">Detected type (first 8 KiB, informational)</p>
                <p>{e.detected_mime}</p>
                <p className="text-muted-foreground">{e.detected_description}</p>
              </div>
              {e.description && (
                <div>
                  <p className="text-xs text-muted-foreground">Description</p>
                  <p className="whitespace-pre-wrap">{e.description}</p>
                </div>
              )}
            </CardContent>
          </Card>
          {investigation.data ? (
            <EvidenceSharePolicyCard
              orgId={orgId}
              evidenceId={e.id}
              investigationId={e.investigation_id}
              tlpRed={investigation.data.tlp === "red"}
              readOnly={investigation.data.status === "archived"}
            />
          ) : null}
          <EvidenceAnalysesCard
            orgId={orgId}
            evidence={e}
            canWrite={can("evidence.write")}
            investigationArchived={investigation.data?.status === "archived"}
          />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>
              Chain of custody
              {custody.data && (
                <span className="ml-2 text-xs font-normal text-muted-foreground">{custody.data.total} events</span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {custody.isError ? (
              <QueryError error={custody.error} onRetry={() => void custody.refetch()} />
            ) : custody.data ? (
              <CustodyTimeline events={custody.data.items} />
            ) : (
              <p className="text-sm text-muted-foreground">Loading custody chain…</p>
            )}
            <Pager offset={custodyOffset} total={custody.data?.total ?? 0} pageSize={CUSTODY_PAGE}
              onChange={setCustodyOffset} />
          </CardContent>
        </Card>
      </div>
    </>
  );
}
