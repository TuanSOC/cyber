"use client";

import { Crosshair } from "lucide-react";
import { useEffect } from "react";

import { Button } from "@/components/ui/button";

/** Class of the highlighted cited row (also the scroll target). */
export const CITED_ROW = "cited-row bg-primary/5 ring-1 ring-inset ring-primary/40";

/**
 * Bar above a result list opened from a citation chip (`?ref=<row id>`): the list shows only
 * the cited row; "Clear filter" returns to the full list.
 */
export function CitedRefBar({ invalid, onClear }: { invalid?: boolean; onClear?: () => void }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 px-3 py-1.5 text-xs" role="status">
      <Crosshair className="size-3.5" aria-hidden />
      <span>{invalid ? "The cited reference in the link is not a valid record id." : "Showing 1 cited record"}</span>
      {onClear && (
        <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={onClear}>
          Clear filter
        </Button>
      )}
    </div>
  );
}

/** Scrolls the highlighted cited row into view once its page has loaded. */
export function useScrollToCited(active: boolean, loaded: boolean) {
  useEffect(() => {
    if (!active || !loaded) return;
    const row = document.querySelector(".cited-row");
    row?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [active, loaded]);
}
