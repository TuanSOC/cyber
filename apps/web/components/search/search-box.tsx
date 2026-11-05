"use client";

import { useEffect, useRef } from "react";

import { SearchForm } from "@/components/search/search-form";

/** Typing `/` outside a text field focuses the box (like most search UIs). */
function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/**
 * The org search box in the shell header (M7 phase 8, slot from phase 1). Enter opens the
 * search page with the query in the URL fragment; the page sends it in a POST body (RT13).
 */
export function SearchBox({ orgId }: { orgId: string }) {
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || isEditable(event.target)) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return <SearchForm orgId={orgId} inputRef={inputRef} compact className="ml-auto w-full max-w-xs print:hidden" />;
}
