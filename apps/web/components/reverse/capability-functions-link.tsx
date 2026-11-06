"use client";

import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { inertText } from "@/lib/disk";
import { orgPath } from "@/lib/nav";
import { formatAddress, functionHref } from "@/lib/reverse";
import { useCapabilityFunctions } from "@/lib/use-re-job";

export const RELINK_HINT = "re-run static analysis to link capabilities";

/**
 * "Functions (n)" on a capability row of the Malware Lab (M10 phase 10 fills the phase-1
 * slot): when an RE job of the sample located the capability, a toggle lists the functions
 * that contain its locations (links to the RE function view); a capability without locations
 * (a static job from before M10) says "re-run static analysis to link capabilities"; nothing
 * when it has locations but no RE job linked them yet.
 */
export function CapabilityFunctionsLink({
  orgId,
  staticJobId,
  capabilityId,
  locations,
  functions,
}: {
  orgId: string;
  staticJobId: string;
  capabilityId: string;
  locations: readonly string[];
  functions: number | null | undefined;
}) {
  const [open, setOpen] = useState(false);
  const list = useCapabilityFunctions(orgId, staticJobId, capabilityId, open);
  if (locations.length === 0) {
    return <span className="block text-xs text-muted-foreground">{RELINK_HINT}</span>;
  }
  if (!functions) return null;
  const prefix = orgPath(orgId);
  return (
    <span className="block">
      <Button
        type="button"
        variant="link"
        size="sm"
        className="h-auto p-0 text-xs"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        Functions ({functions})
      </Button>
      {open ? (
        <span className="mt-1 flex flex-col items-end gap-0.5 text-xs" data-testid="capability-functions">
          {list.isPending ? <span className="text-muted-foreground">Loading…</span> : null}
          {list.isError ? <span className="text-destructive">Could not load the functions.</span> : null}
          {list.data?.functions.map((item) => {
            const href = functionHref(prefix, item.re_job_id, item.function.entry);
            const label = `${inertText(item.function.name, 80)} @ ${formatAddress(item.function.entry)}`;
            return href ? (
              <Link key={`${item.re_job_id}:${item.function.entry}`} href={href} className="font-mono underline-offset-4 hover:underline">
                {label}
              </Link>
            ) : (
              <span key={`${item.re_job_id}:${item.function.entry}`} className="font-mono">
                {label}
              </span>
            );
          })}
          {list.data && list.data.unlocated > 0 ? (
            <span className="text-muted-foreground">{list.data.unlocated} location(s) not inside a recovered function</span>
          ) : null}
        </span>
      ) : null}
    </span>
  );
}
