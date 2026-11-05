"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useMutationState } from "@tanstack/react-query";
import { FileWarning, Lock, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { httpErrorText } from "@/lib/http-errors";
import { useOrg } from "@/lib/org-context";
import { runHref } from "@/lib/retention";

type Evidence = Schemas["EvidenceOut"];

// libmagic MIME types -> the family names the declared type is compared with (display only).
const MIME_FAMILY: readonly [RegExp, string][] = [
  [/^application\/(x-dosexec|x-msdownload|vnd\.microsoft\.portable-executable|x-ms-ne-executable)$/, "PE"],
  [/^application\/(x-executable|x-sharedlib|x-pie-executable|x-elf|x-object|x-coredump)$/, "ELF"],
  [/^application\/pdf$/, "PDF"],
  [/^application\/(vnd\.tcpdump\.pcap|x-pcap|x-pcapng|pcap)$/, "PCAP"],
  [/^application\/(zip|java-archive|vnd\.android\.package-archive|vnd\.openxmlformats-officedocument\..+)$/, "ZIP"],
  [/^application\/(msword|vnd\.ms-excel|vnd\.ms-powerpoint|x-ole-storage|cdfv2)$/i, "Office (legacy)"],
  [/^application\/(x-7z-compressed|x-rar|vnd\.rar|gzip|x-gzip|x-tar|x-bzip2|x-xz)$/, "archive"],
  [/^image\//, "image"],
  [/^(text\/|application\/json$)/, "text"],
];

const FAMILY_LABELS: Readonly<Record<string, string>> = {
  pcap: "PCAP",
  pe: "PE",
  elf: "ELF",
  pdf: "PDF",
  zip: "ZIP",
  office_legacy: "Office (legacy)",
  image: "image",
  text: "text",
  archive: "archive",
};

/** The detected type as a short family name ("PE"), else the MIME type itself (capped). */
export function detectedTypeLabel(mime: string): string {
  const value = mime.trim().toLowerCase();
  for (const [pattern, family] of MIME_FAMILY) if (pattern.test(value)) return family;
  const safe = value.replace(/[^a-z0-9.+/-]/g, "").slice(0, 64);
  return safe || "unknown";
}

/** The declared type as the file name's extension (".pdf"), else the declared family name. */
export function declaredTypeLabel(filename: string, declaredType: string | null | undefined): string {
  const ext = /\.([A-Za-z0-9]{1,10})$/.exec(filename.trim());
  if (ext) return `.${ext[1].toLowerCase()}`;
  if (declaredType && Object.hasOwn(FAMILY_LABELS, declaredType)) return FAMILY_LABELS[declaredType];
  return "unknown";
}

export function mismatchText(evidence: Pick<Evidence, "original_filename" | "declared_type" | "detected_mime">): string {
  return `Declared type (${declaredTypeLabel(evidence.original_filename, evidence.declared_type)}) differs from detected type (${detectedTypeLabel(evidence.detected_mime)})`;
}

export const MISMATCH_TOOLTIP =
  "The file was accepted as uploaded. Analysis follows the detected type, not the file name.";

/** "Bytes purged on … by a retention run; hashes and custody retained." */
export function purgedText(purgedAt: string): string {
  return `Bytes purged on ${formatDate(purgedAt).local} by a retention run; hashes and custody retained.`;
}

/** "run 1a2b3c4d": the purging run's short id (display only; the link is built from the full id). */
export function runLabel(runId: string): string {
  return `run ${runId.replace(/[^0-9a-f-]/gi, "").slice(0, 8)}`;
}

/** True for the API's `410 evidence_purged` (or any 410 Gone) from an evidence action. */
export function isPurgedError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 410;
}

/**
 * The pure strip (tests render it directly). `purgedError`: an action just answered 410.
 * `runLink`: the purging run's page, for members who may read retention runs (`audit.read`).
 */
export function EvidenceIntegrityStripView({
  evidence,
  purgedError = false,
  runLink = null,
}: {
  evidence: Evidence;
  purgedError?: boolean;
  runLink?: string | null;
}) {
  const runId = evidence.purged_by_run_id ?? null;
  const purgedAt = evidence.purged_at ?? null;
  const purged = Boolean(purgedAt) || purgedError;
  const mismatch = evidence.type_mismatch === true;
  if (!purged && !mismatch && !evidence.legal_hold) return null;
  return (
    <div className="mb-6 flex flex-col gap-3" data-slot="evidence-integrity-strip">
      {purged && (
        <Alert>
          <Trash2 className="size-4" aria-hidden />
          <AlertTitle>{purgedAt ? purgedText(purgedAt) : "The evidence bytes were purged."}</AlertTitle>
          <AlertDescription>
            {httpErrorText("evidence_purged")} Download, verification and new analyses are unavailable.
            {runId && (
              <span className="block" data-slot="purged-by-run">
                Purged by retention{" "}
                {runLink ? (
                  <Link href={runLink} className="font-mono underline-offset-4 hover:underline">
                    {runLabel(runId)}
                  </Link>
                ) : (
                  <span className="font-mono">{runLabel(runId)}</span>
                )}
                .
              </span>
            )}
          </AlertDescription>
        </Alert>
      )}
      {(mismatch || evidence.legal_hold) && (
        <div className="flex flex-wrap items-center gap-2">
          {mismatch && (
            <Badge variant="outline" className="h-auto whitespace-normal" title={MISMATCH_TOOLTIP}>
              <FileWarning aria-hidden />
              {mismatchText(evidence)}
              <span className="sr-only">. {MISMATCH_TOOLTIP}</span>
            </Badge>
          )}
          {evidence.legal_hold && (
            <Badge variant="secondary" title="A legal hold protects this evidence from retention purges.">
              <Lock aria-hidden />
              Legal hold
            </Badge>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * M7 slot (RT16), mounted once in the evidence page: purged bytes (`purged_at`, or a 410 from an
 * action on this page), the declared vs detected type mismatch and the legal hold.
 */
export function EvidenceIntegrityStrip({ evidence }: { evidence: Evidence }) {
  // Only mutations started on this page count (the cache may hold another evidence's errors).
  const [mountedAt] = useState(() => Date.now());
  const purgedErrors = useMutationState({
    filters: { status: "error", predicate: (mutation) => mutation.state.submittedAt >= mountedAt },
    select: (mutation) => isPurgedError(mutation.state.error),
  });
  const { orgId, can } = useOrg();
  const runId = evidence.purged_by_run_id;
  const runLink = runId && can("audit.read") ? runHref(orgId, runId) : null;
  return <EvidenceIntegrityStripView evidence={evidence} purgedError={purgedErrors.some(Boolean)} runLink={runLink} />;
}
