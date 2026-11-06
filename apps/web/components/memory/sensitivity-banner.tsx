"use client";

import { ReleaseButton, ReleasedNext } from "@/components/memory/release-dialog";
import { TlpBadge } from "@/components/tlp/tlp-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { RESTRICTED_BANNER } from "@/lib/memory-sensitivity";

/**
 * The restricted banner of a memory job page. Admins (`org.update`) see "Release…"; everyone
 * else is told who can. After a release, the next step (the share policy) is linked.
 */
export function SensitivityBanner({
  orgId,
  evidenceId,
  filename,
  restriction,
  canRelease,
}: {
  orgId: string;
  evidenceId: string;
  filename: string;
  restriction: "restricted" | "released" | "none" | null;
  canRelease: boolean;
}) {
  if (restriction === "released") {
    return (
      <Alert className="mb-6">
        <AlertTitle>Memory image released by an admin</AlertTitle>
        <AlertDescription>
          <ReleasedNext orgId={orgId} evidenceId={evidenceId} />
        </AlertDescription>
      </Alert>
    );
  }
  if (restriction === "none") return null;
  // Restricted, or not known yet: memory is TLP:RED material by default.
  return (
    <Alert className="mb-6 border-destructive/50" data-testid="sensitivity-banner">
      <AlertTitle className="flex flex-wrap items-center gap-2">
        <TlpBadge tlp="red" />
        Restricted memory image
      </AlertTitle>
      <AlertDescription className="flex flex-wrap items-center gap-3">
        <span>{RESTRICTED_BANNER}</span>
        {restriction === "restricted" && canRelease ? (
          <ReleaseButton orgId={orgId} evidenceId={evidenceId} filename={filename} />
        ) : restriction === "restricted" ? (
          <span className="text-xs text-muted-foreground">Only an admin can release it.</span>
        ) : null}
      </AlertDescription>
    </Alert>
  );
}
