"use client";

import type { Schemas } from "@cyberlab/contracts";
import { HardDrive } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { isUuid } from "@/lib/ai";
import { inertText } from "@/lib/disk";
import { type DerivedOrigin, derivedOrigin } from "@/lib/disk-exports";
import { orgPath } from "@/lib/nav";
import { useDerivedCustody } from "@/lib/use-disk-job";

/** The tooltip text of the badge (pure; the path is attacker-chosen, shown inert). */
export function derivedTitle(origin: DerivedOrigin | null): string {
  const parts = ["Exported from a disk image (derived evidence)."];
  if (origin && origin.partition !== null) parts.push(`Partition ${origin.partition}.`);
  if (origin?.path) parts.push(`Path in the image: ${inertText(origin.path, 1024)}`);
  return parts.join(" ");
}

/** The badge alone (pure; tested without queries). Links only to internal UUID routes. */
export function DerivedBadgeView({
  orgId,
  sourceEvidenceId,
  origin,
}: {
  orgId: string;
  sourceEvidenceId: string;
  origin: DerivedOrigin | null;
}) {
  const href = origin?.jobId
    ? orgPath(orgId, `forensics/${origin.jobId}?tab=exports`)
    : orgPath(orgId, `evidence/${sourceEvidenceId}`);
  const where =
    origin && (origin.partition !== null || origin.path)
      ? ` (${[origin.partition !== null ? `partition ${origin.partition}` : null, origin.path ? inertText(origin.path, 80) : null]
          .filter(Boolean)
          .join(", ")})`
      : "";
  return (
    <Badge variant="outline" className="max-w-96 gap-1" title={derivedTitle(origin)} data-testid="derived-badge">
      <HardDrive className="size-3.5 shrink-0" aria-hidden />
      <Link href={href} className="truncate underline-offset-4 hover:underline">
        {origin?.jobId ? "Exported from disk job" : "Exported from a disk image"}
        {where}
      </Link>
    </Badge>
  );
}

/**
 * "Exported from disk job … (partition, path)" (M9 phase 11; mounted once in the evidence page
 * header): a file exported from a disk image links back to its source job (from the
 * `derived_from` custody event) or, failing that, to the source evidence (`derived_from`).
 * The sensitivity badge beside it is the generic one (phase 1).
 */
export function DerivedEvidenceBadge({ orgId, evidence }: { orgId: string; evidence: Schemas["EvidenceOut"] }) {
  const source = evidence.derived_from ?? null;
  const custody = useDerivedCustody(orgId, evidence.id, Boolean(source));
  if (!source || !isUuid(source)) return null;
  return <DerivedBadgeView orgId={orgId} sourceEvidenceId={source} origin={derivedOrigin(custody.data?.items)} />;
}
