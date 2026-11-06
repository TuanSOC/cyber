"use client";

import type { Schemas } from "@cyberlab/contracts";
import {
  Archive,
  Download,
  FilePlus2,
  FlaskConical,
  HardDrive,
  Link2,
  Microscope,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";

import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

type Event = Schemas["CustodyEventOut"];
// M9 phase 10's custody actions (named here too until the contracts are regenerated; the
// union then simply repeats them).
type Action = Event["action"] | "export_requested" | "export_promoted" | "derived_from";
type Meta = { label: string; icon: typeof Upload; tone?: string };

const ACTIONS: Record<Action, Meta> = {
  uploaded: { label: "Uploaded", icon: Upload },
  downloaded: { label: "Downloaded", icon: Download },
  verified_ok: { label: "Verified: hashes match", icon: ShieldCheck, tone: "text-sev-low" },
  verified_mismatch: { label: "Verification FAILED", icon: ShieldAlert, tone: "text-destructive" },
  archived: { label: "Archived", icon: Archive },
  analysis_requested: { label: "Analysis requested", icon: ScanSearch },
  analyzed: { label: "Analyzed (worker read this version)", icon: Microscope },
  // M7: retention deleted the bytes (hashes and custody stay); sent_to_sandbox is reserved.
  purged: { label: "Bytes purged by the retention policy", icon: Trash2, tone: "text-muted-foreground" },
  sent_to_sandbox: { label: "Sent to the sandbox", icon: FlaskConical },
  // M9: a file export of a disk job (on every source segment), its promotion to evidence, and
  // the derivation recorded on the new evidence.
  export_requested: { label: "File export requested from a disk job", icon: HardDrive },
  export_promoted: { label: "Exported file added to the case", icon: FilePlus2 },
  derived_from: { label: "Derived from a disk image", icon: Link2 },
};
// An action this build does not know yet (a newer API) still renders instead of crashing.
const UNKNOWN: Meta = { label: "Custody event", icon: ScanSearch, tone: "text-muted-foreground" };

export function CustodyTimeline({ events }: { events: Event[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-muted-foreground">No custody events.</p>;
  }
  return (
    <ol className="relative flex flex-col gap-4 border-l pl-6">
      {events.map((event) => {
        const meta: Meta = (ACTIONS as Partial<Record<string, Meta>>)[event.action] ?? UNKNOWN;
        const when = formatDate(event.occurred_at);
        const reason = typeof event.details.reason === "string" ? event.details.reason : null;
        return (
          <li key={event.id} className="relative">
            <span className="absolute top-0.5 -left-[33px] flex size-5 items-center justify-center rounded-full border bg-background">
              <meta.icon className={cn("size-3", meta.tone)} aria-hidden />
            </span>
            <p className={cn("text-sm font-medium", meta.tone)}>
              {meta.label}
              {reason && <span className="font-normal text-muted-foreground"> ({reason})</span>}
            </p>
            <p className="text-xs text-muted-foreground">
              <span title={when.utc}>{when.local}</span> · {event.actor_name}
              {event.ip && <> · {event.ip}</>}
            </p>
          </li>
        );
      })}
    </ol>
  );
}
