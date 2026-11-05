"use client";

import { useQuery } from "@tanstack/react-query";
import { useCallback, useState, useSyncExternalStore } from "react";

import {
  type SearchHit,
  type SearchState,
  type SearchType,
  type SectionState,
  checkQuery,
  parseSearchFragment,
  searchBody,
  searchFragment,
  searchOrg,
  sectionStates,
} from "@/lib/search";

/*
 * Hooks of the org search page. The query lives in the URL fragment and in memory only (React
 * state and the React Query cache): never in a query string, storage, analytics or the console
 * (RT13).
 */

const FRAGMENT_EVENT = "cyberlab:search-fragment";

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

/** The page's `#q=…&types=…`, kept in sync with history navigation. */
export function useSearchFragment(): SearchState {
  return parseSearchFragment(useSyncExternalStore(subscribe, readHash, serverHash));
}

/**
 * Writes the fragment on the current page (the search page). `pushState` with a fragment only:
 * no request, and Next's router keeps its own state.
 */
export function setSearchFragment(q: string, types: readonly SearchType[], { replace = false } = {}): void {
  const url = `${window.location.pathname}#${searchFragment(q, types)}`;
  if (replace) window.history.replaceState(window.history.state, "", url);
  else window.history.pushState(null, "", url);
  window.dispatchEvent(new Event(FRAGMENT_EVENT));
}

export const searchKeys = {
  all: (orgId: string) => ["org", orgId, "search"] as const,
  query: (orgId: string, q: string, types: readonly SearchType[]) => ["org", orgId, "search", q, [...types]] as const,
};

type MorePage = { hits: SearchHit[]; nextCursor: string | null; loading: boolean; error: unknown };

/**
 * The first page of every requested type, plus "load more" per type through its cursor (a
 * one-type POST). Extra pages are dropped when the query or the types change.
 */
export function useOrgSearch(orgId: string, q: string, types: readonly SearchType[]) {
  const check = checkQuery(q);
  const query = useQuery({
    queryKey: searchKeys.query(orgId, check.q, types),
    queryFn: () => searchOrg(orgId, searchBody(check.q, types)),
    enabled: check.ok,
    // A 429 is shown as "slow down", never retried behind the user's back.
    retry: false,
  });

  const identity = JSON.stringify([orgId, check.q, types]);
  const [more, setMore] = useState<{ identity: string; pages: Partial<Record<SearchType, MorePage>> }>({
    identity,
    pages: {},
  });
  const pages = more.identity === identity ? more.pages : {};

  const sections: SectionState[] | null = query.data
    ? sectionStates(query.data, types).map((section) => {
        const extra = pages[section.type];
        return extra
          ? { ...section, hits: [...section.hits, ...extra.hits], nextCursor: extra.nextCursor }
          : section;
      })
    : null;

  const update = useCallback(
    (type: SearchType, patch: (prev: MorePage | undefined) => MorePage) =>
      setMore((prev) => {
        const base = prev.identity === identity ? prev.pages : {};
        return { identity, pages: { ...base, [type]: patch(base[type]) } };
      }),
    [identity],
  );

  const loadMore = useCallback(
    async (section: SectionState) => {
      const cursor = section.nextCursor;
      if (!cursor || !check.ok) return;
      const type = section.type;
      update(type, (prev) => ({ hits: prev?.hits ?? [], nextCursor: cursor, loading: true, error: null }));
      try {
        const out = await searchOrg(orgId, searchBody(check.q, [type], cursor));
        const [next] = sectionStates(out, [type]);
        update(type, (prev) => ({
          hits: [...(prev?.hits ?? []), ...next.hits],
          nextCursor: next.nextCursor,
          loading: false,
          error: next.status === "timeout" ? "timeout" : null,
        }));
      } catch (error) {
        update(type, (prev) => ({ hits: prev?.hits ?? [], nextCursor: cursor, loading: false, error }));
      }
    },
    [check.ok, check.q, orgId, update],
  );

  return { check, query, sections, more: pages, loadMore };
}
