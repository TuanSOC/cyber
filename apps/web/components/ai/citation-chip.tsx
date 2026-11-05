import {
  Activity,
  Binary,
  BookText,
  Briefcase,
  Cpu,
  FileSearch,
  FileText,
  Flag,
  Fingerprint,
  FolderOpen,
  type LucideIcon,
  Network,
  Quote,
  ScrollText,
  ShieldAlert,
  Siren,
  Tag,
} from "lucide-react";
import Link from "next/link";

import { type AiCitation, citationChip } from "@/lib/ai";
import { cn } from "@/lib/utils";

const KIND_ICONS: Record<string, LucideIcon> = {
  job: Activity,
  finding: Flag,
  alert: Siren,
  flow: Network,
  record: ScrollText,
  ioc: Fingerprint,
  ti_result: ShieldAlert,
  sample: FileSearch,
  pe_summary: Binary,
  signature: Tag,
  capability: Cpu,
  string: Quote,
  timeline: BookText,
  evidence: FileText,
  investigation: Briefcase,
  digest_claim: FolderOpen,
};

const CHIP = "inline-flex max-w-56 items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[11px]";

/**
 * One citation. Verified: label + kind icon, linked to the exact cited record through the
 * API's descriptor (internal routes only); the tooltip shows the field and quote.
 * Unverified / invalid: grey text, never a link, with the reason in the tooltip.
 */
export function CitationChip({ orgId, citation }: { orgId: string; citation: AiCitation }) {
  const chip = citationChip(orgId, citation);
  const Icon = (citation.kind && KIND_ICONS[citation.kind]) || FileText;
  const body = (
    <>
      <Icon className="size-3 shrink-0" aria-hidden />
      <span className="truncate">{chip.text}</span>
      {citation.stale && <span className="text-muted-foreground">(stale)</span>}
    </>
  );
  if (chip.href) {
    return (
      <Link
        href={chip.href}
        className={cn(CHIP, "border-border text-foreground hover:bg-muted")}
        title={chip.title}
        data-citation="verified"
      >
        {body}
      </Link>
    );
  }
  return (
    <span
      className={cn(
        CHIP,
        chip.status === "verified"
          ? "border-border text-foreground"
          : "border-dashed border-muted-foreground/40 text-muted-foreground line-through decoration-muted-foreground/40",
      )}
      title={chip.title}
      data-citation={chip.status}
    >
      {body}
    </span>
  );
}

export function CitationChips({
  orgId,
  citations,
  className,
}: {
  orgId: string;
  citations: readonly AiCitation[];
  className?: string;
}) {
  if (citations.length === 0) return null;
  return (
    <span className={cn("flex flex-wrap gap-1", className)}>
      {citations.map((citation, index) => (
        <CitationChip key={`${citation.label}-${index}`} orgId={orgId} citation={citation} />
      ))}
    </span>
  );
}
