"use client";

import { useSyncExternalStore } from "react";

/*
 * The URL fragment as page state (search, M7 phase 8; the indicator history, phase 11): a
 * fragment never reaches a server, a request log or a referrer, so a query or an IOC value kept
 * there stays on the client (RT13). Next's router does not fire `hashchange` on `pushState`, so
 * every write here announces itself with FRAGMENT_EVENT.
 */

const FRAGMENT_EVENT = "cyberlab:fragment";

function subscribe(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  window.addEventListener("popstate", onChange);
  window.addEventListener(FRAGMENT_EVENT, onChange);
  return () => {
    window.removeEventListener("hashchange", onChange);
    window.removeEventListener("popstate", onChange);
    window.removeEventListener(FRAGMENT_EVENT, onChange);
  };
}

const readHash = () => window.location.hash;
const serverHash = () => "";

/** The current `location.hash` (with its `#`), kept in sync with history navigation. */
export function useLocationHash(): string {
  return useSyncExternalStore(subscribe, readHash, serverHash);
}

/**
 * Writes the fragment (without `#`) on the current page. `pushState` with a fragment only: no
 * request, and Next's router keeps its own state.
 */
export function setLocationFragment(fragment: string, { replace = false } = {}): void {
  const url = `${window.location.pathname}#${fragment}`;
  if (replace) window.history.replaceState(window.history.state, "", url);
  else window.history.pushState(null, "", url);
  window.dispatchEvent(new Event(FRAGMENT_EVENT));
}
