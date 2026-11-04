"use client";

import { useEffect, useState } from "react";

/** Current time, ticking every `intervalMs` only while `active` (e.g. a job is running). */
export function useNow(active: boolean, intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const tick = () => setNow(Date.now());
    const timer = setInterval(tick, intervalMs);
    return () => clearInterval(timer);
  }, [active, intervalMs]);
  return now;
}
