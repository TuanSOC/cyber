"use client";

import { useState } from "react";

import { type KeyTarget } from "@/components/correlation/correlation-parts";
import { KeyDrawer } from "@/components/correlation/key-drawer";
import { PageHeader } from "@/components/page-header";
import { SearchForm } from "@/components/search/search-form";
import { SearchSection, TypeChips, onResultsKeyDown } from "@/components/search/search-results";
import { QueryError } from "@/components/query-error";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { isCorrelationKind } from "@/lib/correlation";
import { apiErrorText } from "@/lib/http-errors";
import { useOrg } from "@/lib/org-context";
import { type SearchHit, type SearchType, searchSummaryText, slowDownText } from "@/lib/search";
import { setSearchFragment, useOrgSearch, useSearchFragment } from "@/lib/use-search";

/**
 * Org search. The query is read from the URL fragment (`#q=…`) and sent in a POST body only
 * (RT13): it never appears in a query string, a request log or browser storage.
 */
export default function SearchPage() {
  const { orgId } = useOrg();
  const { q, types } = useSearchFragment();
  const [target, setTarget] = useState<KeyTarget | null>(null);

  const toggle = (type: SearchType) => {
    const next = types.includes(type) ? types.filter((t) => t !== type) : [...types, type];
    setSearchFragment(q, next, { replace: true });
  };
  const pivot = (hit: SearchHit) => {
    if (hit.kind && isCorrelationKind(hit.kind)) setTarget({ kind: hit.kind, value: hit.title });
  };

  return (
    <>
      <PageHeader
        title="Search"
        description="Search the cases, evidence, findings, alerts, notes and observables of this organization."
      />
      <div className="flex flex-col gap-4">
        <SearchForm key={q} orgId={orgId} initialQuery={q} types={types} className="max-w-2xl" />
        <TypeChips selected={types} onToggle={toggle} />
        <Results orgId={orgId} q={q} types={types} onPivot={pivot} />
      </div>
      <KeyDrawer orgId={orgId} target={target} onClose={() => setTarget(null)} />
    </>
  );
}

function Results({
  orgId,
  q,
  types,
  onPivot,
}: {
  orgId: string;
  q: string;
  types: SearchType[];
  onPivot: (hit: SearchHit) => void;
}) {
  const { check, query, sections, more, loadMore } = useOrgSearch(orgId, q, types);

  let status: React.ReactNode = null;
  let body: React.ReactNode = null;
  if (q.trim() === "") {
    body = <p className="text-sm text-muted-foreground">Enter at least two characters and press Enter.</p>;
  } else if (!check.ok) {
    body = <p className="text-sm text-destructive">{check.message}</p>;
  } else if (query.isError) {
    const slow = slowDownText(query.error);
    const known = apiErrorText(query.error);
    body = slow ? (
      <Alert>
        <AlertDescription>{slow}</AlertDescription>
      </Alert>
    ) : known ? (
      <p className="text-sm text-destructive" role="alert">
        {known}
      </p>
    ) : (
      <QueryError error={query.error} onRetry={() => void query.refetch()} />
    );
  } else if (!sections) {
    status = "Searching…";
  } else {
    status = searchSummaryText(sections);
    body = (
      // Arrow keys move through the result links.
      <div className="flex flex-col gap-6" onKeyDown={onResultsKeyDown}>
        {sections.map((section) => (
          <SearchSection
            key={section.type}
            orgId={orgId}
            section={section}
            q={check.q}
            loadingMore={more[section.type]?.loading}
            moreError={more[section.type]?.error}
            onLoadMore={() => void loadMore(section)}
            onPivot={onPivot}
          />
        ))}
      </div>
    );
  }

  return (
    <>
      <p className="text-sm text-muted-foreground" role="status" aria-live="polite">
        {status}
      </p>
      {body}
    </>
  );
}
