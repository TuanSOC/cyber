"use client";

/**
 * Slot (M7 phase 1): the org search box in the shell header. Phase 8 fills it (a POST search
 * whose query never enters a URL, RT13). Renders nothing until then.
 */
export function SearchBox({ orgId }: { orgId: string }) {
  void orgId;
  return null;
}
