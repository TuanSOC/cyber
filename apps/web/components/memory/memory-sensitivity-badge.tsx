"use client";

import type { Schemas } from "@cyberlab/contracts";

import { ReleaseButton } from "@/components/memory/release-dialog";
import { Badge } from "@/components/ui/badge";
import { RESTRICTED_BANNER } from "@/lib/memory-sensitivity";
import { useOrg } from "@/lib/org-context";

type SensitivityField = "restricted" | "released" | null | undefined;

/** The badge alone (pure; tested without the org context). */
export function SensitivityBadge({ state }: { state: SensitivityField }) {
  if (state === "restricted") {
    return (
      <Badge variant="destructive" title={RESTRICTED_BANNER}>
        Memory image · restricted (TLP:RED)
      </Badge>
    );
  }
  if (state === "released") {
    return (
      <Badge variant="outline" title="An admin released this memory image; the share policy decides AI and threat-intel use.">
        Memory image · released
      </Badge>
    );
  }
  return null;
}

/**
 * The memory sensitivity of an evidence item (M8 phase 9, mounted once in the evidence page
 * header): a badge while restricted or released, and "Release…" for admins while restricted.
 * Renders nothing for evidence that was never marked (`EvidenceOut.memory_sensitivity` null).
 */
export function MemorySensitivityBadge({ orgId, evidence }: { orgId: string; evidence: Schemas["EvidenceOut"] }) {
  const { can } = useOrg();
  const state = evidence.memory_sensitivity;
  if (state !== "restricted" && state !== "released") return null;
  return (
    <span className="inline-flex items-center gap-2">
      <SensitivityBadge state={state} />
      {state === "restricted" && can("org.update") ? (
        <ReleaseButton orgId={orgId} evidenceId={evidence.id} filename={evidence.original_filename} />
      ) : null}
    </span>
  );
}
