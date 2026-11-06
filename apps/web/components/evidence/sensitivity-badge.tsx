"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useState } from "react";

import { ReleaseForm, ReleasedNext } from "@/components/memory/release-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { DISK_RESTRICTED_BANNER, SOURCE_LABELS, genericSensitivity } from "@/lib/evidence-sensitivity";
import { useOrg } from "@/lib/org-context";
import { useReleaseEvidence } from "@/lib/use-evidence-sensitivity";

/** The badge alone (pure; tested without the org context). */
export function EvidenceSensitivityState({
  state,
  source,
}: {
  state: "restricted" | "released";
  source: "disk" | "derived";
}) {
  const label = SOURCE_LABELS[source];
  if (state === "restricted") {
    return (
      <Badge variant="destructive" title={DISK_RESTRICTED_BANNER}>
        {label} · restricted (TLP:RED)
      </Badge>
    );
  }
  return (
    <Badge variant="outline" title="An admin released this evidence; the share policy decides AI and threat-intel use.">
      {label} · released
    </Badge>
  );
}

function ReleaseEvidenceButton({ orgId, evidenceId, filename }: { orgId: string; evidenceId: string; filename: string }) {
  const [open, setOpen] = useState(false);
  const release = useReleaseEvidence(orgId, evidenceId);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next && !release.isSuccess) release.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          Release…
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Release this evidence</DialogTitle>
          <DialogDescription className="break-all">{filename}</DialogDescription>
        </DialogHeader>
        {release.isSuccess ? (
          <>
            <ReleasedNext orgId={orgId} evidenceId={evidenceId} />
            <DialogFooter>
              <Button type="button" onClick={() => setOpen(false)}>
                Close
              </Button>
            </DialogFooter>
          </>
        ) : open ? (
          <ReleaseForm
            pending={release.isPending}
            error={release.error}
            onSubmit={(body) => release.mutate(body)}
            onCancel={() => setOpen(false)}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

/**
 * The sensitivity of disk images and files derived from them (M9, RT2; mounted once in the
 * evidence page header beside M8's memory badge): a badge while restricted or released, and
 * "Release…" for admins while restricted. Renders nothing for memory evidence (M8's badge) or
 * evidence never marked (`EvidenceOut.sensitivity` null).
 */
export function EvidenceSensitivityBadge({ orgId, evidence }: { orgId: string; evidence: Schemas["EvidenceOut"] }) {
  const { can } = useOrg();
  const shown = genericSensitivity(evidence.sensitivity);
  if (!shown) return null;
  return (
    <span className="inline-flex items-center gap-2">
      <EvidenceSensitivityState state={shown.state} source={shown.source} />
      {shown.state === "restricted" && can("org.update") ? (
        <ReleaseEvidenceButton orgId={orgId} evidenceId={evidence.id} filename={evidence.original_filename} />
      ) : null}
    </span>
  );
}
