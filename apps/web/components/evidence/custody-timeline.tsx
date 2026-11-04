"use client";

import type { Schemas } from "@cyberlab/contracts";
import { Archive, Download, Microscope, ScanSearch, ShieldAlert, ShieldCheck, Upload } from "lucide-react";

import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

type Event = Schemas["CustodyEventOut"];

const ACTIONS: Record<Event["action"], { label: string; icon: typeof Upload; tone?: string }> = {
  uploaded: { label: "Uploaded", icon: Upload },
  downloaded: { label: "Downloaded", icon: Download },
  verified_ok: { label: "Verified: hashes match", icon: ShieldCheck, tone: "text-sev-low" },
  verified_mismatch: { label: "Verification FAILED", icon: ShieldAlert, tone: "text-destructive" },
  archived: { label: "Archived", icon: Archive },
  analysis_requested: { label: "Analysis requested", icon: ScanSearch },
  analyzed: { label: "Analyzed (worker read this version)", icon: Microscope },
};

export function CustodyTimeline({ events }: { events: Event[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-muted-foreground">No custody events.</p>;
  }
  return (
    <ol className="relative flex flex-col gap-4 border-l pl-6">
      {events.map((event) => {
        const meta = ACTIONS[event.action];
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
