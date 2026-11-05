"use client";

import Link from "next/link";
import type { KeyboardEvent } from "react";

import { TlpBadge } from "@/components/tlp/tlp-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { errorMessage } from "@/lib/api";
import { kindLabel } from "@/lib/correlation";
import {
  MATCH_LABELS,
  SEARCH_TYPES,
  SEARCH_TYPE_LABELS,
  type SearchHit,
  type SearchType,
  type SectionState,
  type Segment,
  highlight,
  hitHref,
  sectionCountText,
  snippetSegments,
} from "@/lib/search";
import { cn } from "@/lib/utils";

/*
 * Presentational parts of the search page. Hit titles and snippets are untrusted text: they are
 * split into React text nodes and `<mark>` elements built from match ranges, never parsed as
 * HTML, and invisible characters are made visible (the M6 `vis` rule).
 */

/** Segments as React text nodes and `<mark>` elements (never HTML). */
export function Marked({ segments, className }: { segments: readonly Segment[]; className?: string }) {
  if (segments.length === 0) return null;
  return (
    <span className={className}>
      {segments.map((segment, index) =>
        segment.mark ? (
          <mark key={index} className="rounded-sm bg-yellow-500/30 px-0.5 text-inherit">
            {segment.text}
          </mark>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </span>
  );
}

/** Text with its matches marked. */
export function Highlighted({ text, q, className }: { text: string | null | undefined; q: string; className?: string }) {
  return <Marked segments={highlight(text, q)} className={className} />;
}

/** Type filter chips: none selected means every type. */
export function TypeChips({
  selected,
  onToggle,
}: {
  selected: readonly SearchType[];
  onToggle: (type: SearchType) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2" role="group" aria-label="Result types">
      {SEARCH_TYPES.map((type) => {
        const on = selected.includes(type);
        return (
          <button
            key={type}
            type="button"
            aria-pressed={on}
            onClick={() => onToggle(type)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs font-medium transition-colors outline-none",
              "focus-visible:ring-[3px] focus-visible:ring-ring/50",
              on ? "border-primary bg-primary text-primary-foreground" : "border-border hover:bg-muted",
            )}
          >
            {SEARCH_TYPE_LABELS[type]}
          </button>
        );
      })}
    </div>
  );
}

/** Arrow keys move between the result links of the page (Home / End jump to the ends). */
export function onResultsKeyDown(event: KeyboardEvent<HTMLElement>): void {
  const keys = ["ArrowDown", "ArrowUp", "Home", "End"];
  if (!keys.includes(event.key)) return;
  const links = Array.from(event.currentTarget.querySelectorAll<HTMLElement>("[data-search-hit]"));
  if (links.length === 0) return;
  const current = links.indexOf(document.activeElement as HTMLElement);
  let next = current;
  if (event.key === "ArrowDown") next = current < 0 ? 0 : Math.min(links.length - 1, current + 1);
  else if (event.key === "ArrowUp") next = current < 0 ? 0 : Math.max(0, current - 1);
  else if (event.key === "Home") next = 0;
  else next = links.length - 1;
  event.preventDefault();
  links[next]?.focus();
}

export function SearchHitItem({
  orgId,
  hit,
  q,
  onPivot,
}: {
  orgId: string;
  hit: SearchHit;
  q: string;
  /** Observable hits: open the key drawer ("where else was it observed"). */
  onPivot?: (hit: SearchHit) => void;
}) {
  const href = hitHref(orgId, hit);
  const title = <Highlighted text={hit.title || "(untitled)"} q={q} className="font-medium break-all" />;
  return (
    <li className="flex flex-col gap-1 rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        {href ? (
          <Link
            href={href}
            data-search-hit=""
            className="min-w-0 rounded-sm underline-offset-4 outline-none hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50"
          >
            {title}
          </Link>
        ) : (
          <span data-search-hit="" tabIndex={0} className="min-w-0 rounded-sm outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50">
            {title}
          </span>
        )}
        {hit.case_ref && (
          <Badge variant="outline" className="font-mono">
            {hit.case_ref}
          </Badge>
        )}
        {hit.tlp && <TlpBadge tlp={hit.tlp} />}
        {hit.type === "observable" && hit.kind && <Badge variant="secondary">{kindLabel(hit.kind)}</Badge>}
        <span className="text-xs text-muted-foreground">{MATCH_LABELS[hit.match] ?? hit.match}</span>
        {onPivot && hit.type === "observable" && hit.kind && (
          <Button variant="ghost" size="xs" className="ml-auto" onClick={() => onPivot(hit)}>
            Where else observed
          </Button>
        )}
      </div>
      {hit.snippet && (
        <p className="text-xs break-words whitespace-pre-wrap text-muted-foreground">
          <Marked segments={snippetSegments(hit, q)} />
        </p>
      )}
    </li>
  );
}

export function SearchSection({
  orgId,
  section,
  q,
  loadingMore = false,
  moreError,
  onLoadMore,
  onPivot,
}: {
  orgId: string;
  section: SectionState;
  q: string;
  loadingMore?: boolean;
  moreError?: unknown;
  onLoadMore?: () => void;
  onPivot?: (hit: SearchHit) => void;
}) {
  const label = SEARCH_TYPE_LABELS[section.type];
  const headingId = `search-section-${section.type}`;
  return (
    <section aria-labelledby={headingId} className="flex flex-col gap-2">
      <h2 id={headingId} className="flex items-baseline gap-2 text-sm font-semibold">
        {label}
        <span className="text-xs font-normal text-muted-foreground">{sectionCountText(section)}</span>
      </h2>
      {section.status === "timeout" ? (
        <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground" role="note">
          This type timed out. The other types are complete; refine the terms to search it again.
        </p>
      ) : section.hits.length === 0 ? (
        <p className="text-xs text-muted-foreground">No {label.toLowerCase()} match.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {section.hits.map((hit) => (
            <SearchHitItem key={`${hit.type}:${hit.id}`} orgId={orgId} hit={hit} q={q} onPivot={onPivot} />
          ))}
        </ul>
      )}
      {moreError ? (
        <p className="text-xs text-destructive" role="alert">
          {moreError === "timeout" ? "Loading more timed out." : errorMessage(moreError)}
        </p>
      ) : null}
      {section.nextCursor && onLoadMore && (
        <Button variant="outline" size="sm" className="w-fit" disabled={loadingMore} onClick={onLoadMore}>
          {loadingMore ? "Loading…" : `Load more ${label.toLowerCase()}`}
        </Button>
      )}
    </section>
  );
}
