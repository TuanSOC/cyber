"use client";

import { CircleCheck, FileKey, TriangleAlert } from "lucide-react";

import { CopyButton } from "@/components/analysis/result-parts";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type Integrity = {
  snapshotOk: boolean;
  signatureValid: boolean;
  kid: string;
  sha256: string;
};

export const INTEGRITY_FAILED = "Integrity check failed";

function Check({ ok, okText, failText }: { ok: boolean; okText: string; failText: string }) {
  return (
    <p className={cn("flex items-start gap-2 text-sm", ok ? "text-emerald-700 dark:text-emerald-400" : "font-semibold text-destructive")}>
      {ok ? (
        <CircleCheck className="mt-0.5 size-4 shrink-0" aria-hidden />
      ) : (
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
      )}
      <span>{ok ? okText : `${INTEGRITY_FAILED}: ${failText}`}</span>
    </p>
  );
}

/**
 * The integrity status of a signed version, always shown (never hidden on failure): the stored
 * snapshot re-hashed against its recorded sha256, and the Ed25519 signature of the manifest.
 */
export function IntegrityStrip({
  integrity,
  onDownloadSignature,
  signaturePending = false,
}: {
  integrity: Integrity;
  onDownloadSignature?: () => void;
  signaturePending?: boolean;
}) {
  const failed = !integrity.snapshotOk || !integrity.signatureValid;
  return (
    <section
      aria-label="Integrity"
      role={failed ? "alert" : "status"}
      data-integrity={failed ? "failed" : "ok"}
      className={cn("mt-4 flex flex-col gap-2 rounded-md border p-3", failed && "border-destructive bg-destructive/5")}
    >
      <Check
        ok={integrity.snapshotOk}
        okText="Snapshot intact: the stored snapshot matches its recorded SHA-256."
        failText="the stored snapshot does not match its recorded SHA-256."
      />
      <Check
        ok={integrity.signatureValid}
        okText={`Signature valid (Ed25519, key ${integrity.kid}).`}
        failText={`the signature does not verify with key ${integrity.kid}.`}
      />
      <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">SHA-256</span>
        <code className="min-w-0 font-mono break-all">{integrity.sha256}</code>
        <CopyButton value={integrity.sha256} label="Copy the SHA-256" />
        {onDownloadSignature ? (
          <Button
            variant="outline"
            size="sm"
            className="h-7 print:hidden"
            disabled={signaturePending}
            onClick={onDownloadSignature}
          >
            <FileKey className="size-3.5" aria-hidden />
            Signature JSON
          </Button>
        ) : null}
      </div>
    </section>
  );
}
