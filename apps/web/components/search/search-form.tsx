"use client";

import { Search } from "lucide-react";
import { usePathname, useRouter } from "next/navigation";
import { type Ref, useId, useState } from "react";

import { Input } from "@/components/ui/input";
import { MAX_QUERY_CHARS, type SearchType, checkQuery, searchPageHref, searchPagePath } from "@/lib/search";
import { setSearchFragment } from "@/lib/use-search";
import { cn } from "@/lib/utils";

/**
 * The search field (header box and search page). Enter goes to `/o/{org}/search#q=…`: the query
 * is kept in the fragment, so it never reaches a server, a request log or a query string (RT13).
 */
export function SearchForm({
  orgId,
  initialQuery = "",
  types = [],
  inputRef,
  compact = false,
  className,
}: {
  orgId: string;
  initialQuery?: string;
  types?: readonly SearchType[];
  inputRef?: Ref<HTMLInputElement>;
  compact?: boolean;
  className?: string;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [value, setValue] = useState(initialQuery);
  const [problem, setProblem] = useState<string | null>(null);
  const errorId = useId();

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const check = checkQuery(value);
    if (!check.ok) {
      setProblem(check.message);
      return;
    }
    setProblem(null);
    if (pathname === searchPagePath(orgId)) setSearchFragment(check.q, types);
    else router.push(searchPageHref(orgId, check.q, types));
  };

  return (
    <form role="search" onSubmit={submit} className={cn("relative flex flex-col gap-1", className)}>
      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
        <Input
          ref={inputRef}
          type="search"
          name="q"
          autoComplete="off"
          spellCheck={false}
          maxLength={MAX_QUERY_CHARS * 2}
          placeholder={compact ? "Search  ( / )" : "Search cases, evidence, findings, alerts, notes, observables"}
          aria-label="Search this organization"
          aria-invalid={problem ? true : undefined}
          aria-describedby={problem ? errorId : undefined}
          className={cn("pl-8", compact && "h-8")}
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            if (problem) setProblem(null);
          }}
        />
      </div>
      {problem && (
        <p
          id={errorId}
          role="alert"
          className={cn("text-xs text-destructive", compact && "absolute top-full left-0 mt-1 rounded bg-popover px-2 py-1 shadow")}
        >
          {problem}
        </p>
      )}
    </form>
  );
}
