"use client";

import { AlertTriangle, Copy } from "lucide-react";
import { type UIEvent, memo, useCallback, useMemo, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  type CodeLine,
  type Token,
  type TokenKind,
  codeLines,
  codeStats,
  escapedText,
  isHomoglyphIdentifier,
  plainTokens,
  tokenize,
  visibleParts,
} from "@/lib/c-tokenizer";
import { windowRange } from "@/lib/disk";
import { cn } from "@/lib/utils";

/**
 * The safe code viewer (M10 phase 10). Decompiled code is attacker-influenced text, so:
 * - our linear tokenizer (`lib/c-tokenizer.ts`) classifies it and every token is a React text
 *   node inside a `<span>`: no HTML string, no raw-HTML prop (lint: react/no-danger), no highlighter library;
 * - bidi / invisible / control characters are shown as visible escapes (`⟨U+202E⟩`) in a
 *   distinct style, identifiers with non-ASCII characters (homoglyphs) are marked, and the
 *   banner counts both (RT17);
 * - "Copy" copies the escaped text; "Copy raw" is secondary and warns first;
 * - lines are virtualized (fixed height, up to 5 000 lines), each line scrolls horizontally,
 *   nothing wraps; `disasm` code uses a plain style (no C highlighting).
 */

const LINE_HEIGHT = 20;
const VIEWPORT = 560;
export const MAX_VIEWER_LINES = 5_000;

const KIND_CLASS: Record<TokenKind, string> = {
  keyword: "text-violet-700 dark:text-violet-300",
  type: "text-sky-700 dark:text-sky-300",
  identifier: "",
  number: "text-amber-700 dark:text-amber-300",
  string: "text-emerald-700 dark:text-emerald-300",
  char: "text-emerald-700 dark:text-emerald-300",
  comment: "text-muted-foreground italic",
  preprocessor: "text-fuchsia-700 dark:text-fuchsia-300",
  punctuation: "text-muted-foreground",
  whitespace: "",
  invalid: "text-destructive",
};
const HIDDEN_CLASS = "rounded-sm bg-amber-500/25 px-0.5 text-amber-900 not-italic dark:text-amber-200";
const HOMOGLYPH_CLASS = "underline decoration-wavy decoration-amber-500";

/** One token: its plain runs as text, its hidden characters as escapes. */
const TokenView = memo(function TokenView({ token, plain }: { token: Token; plain: boolean }) {
  const parts = visibleParts(token.text);
  const homoglyph = isHomoglyphIdentifier(token);
  return (
    <span
      className={cn(!plain && KIND_CLASS[token.kind], homoglyph && HOMOGLYPH_CLASS)}
      data-token={token.kind}
      data-homoglyph={homoglyph ? "" : undefined}
      title={homoglyph ? "Identifier with non-ASCII characters (possible look-alike letters)" : undefined}
    >
      {parts.map((part, index) =>
        part.hidden ? (
          <span key={index} className={HIDDEN_CLASS} data-hidden-char="" title="Hidden or direction-changing character">
            {part.text}
          </span>
        ) : (
          part.text
        ),
      )}
    </span>
  );
});

export const LineView = memo(function LineView({ line, number, plain }: { line: CodeLine; number: number; plain: boolean }) {
  return (
    <div role="row" className="flex h-5 items-center leading-5" aria-rowindex={number}>
      <span role="rowheader" className="w-14 shrink-0 pr-3 text-right text-muted-foreground tabular-nums select-none">
        {number}
      </span>
      <span role="cell" className="min-w-0 flex-1 overflow-x-auto whitespace-pre [scrollbar-width:thin]">
        {line.map((token, index) => (
          <TokenView key={index} token={token} plain={plain} />
        ))}
      </span>
    </div>
  );
});

export type PreparedCode = { lines: CodeLine[]; hidden: number; homoglyphs: number; cut: number };

/** Tokens split into lines, counted, and capped at `MAX_VIEWER_LINES` (`cut` = lines left out). */
export function prepareCode(code: string, kind: "pseudo_c" | "disasm"): PreparedCode {
  const tokens = kind === "disasm" ? plainTokens(code) : tokenize(code);
  const stats = codeStats(tokens);
  const all = codeLines(tokens);
  return {
    lines: all.slice(0, MAX_VIEWER_LINES),
    hidden: stats.hidden,
    homoglyphs: stats.homoglyphs,
    cut: Math.max(0, all.length - MAX_VIEWER_LINES),
  };
}

/** "n hidden or direction-changing characters shown" / "n identifiers with non-ASCII letters". */
export function CodeBanner({ hidden, homoglyphs }: { hidden: number; homoglyphs: number }) {
  if (!hidden && !homoglyphs) return null;
  const parts = [];
  if (hidden) parts.push(`${hidden} hidden or direction-changing character${hidden === 1 ? "" : "s"} shown as ⟨U+…⟩`);
  if (homoglyphs) parts.push(`${homoglyphs} identifier${homoglyphs === 1 ? "" : "s"} with non-ASCII letters (underlined)`);
  return (
    <div role="status" data-testid="code-banner" className="mb-2 flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-2 text-xs">
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
      <span>
        {parts.join("; ")}. The code may read differently from what it does (Trojan Source); copying gives the escaped text.
      </span>
    </div>
  );
}

async function copy(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`${what} copied`);
  } catch {
    toast.error("Copying failed (clipboard not available)");
  }
}

export function CodeViewer({
  code,
  codeKind,
  truncated,
  label,
  height = VIEWPORT,
}: {
  code: string;
  codeKind: "pseudo_c" | "disasm";
  /** The engine cut the code (its marker is the last line). */
  truncated: boolean;
  /** Accessible name of the code grid (the function name, as text). */
  label: string;
  height?: number;
}) {
  const prepared = useMemo(() => prepareCode(code, codeKind), [code, codeKind]);
  const [scrollTop, setScrollTop] = useState(0);
  const [confirmRaw, setConfirmRaw] = useState(false);
  const { lines } = prepared;
  const { start, end } = windowRange(scrollTop, height, LINE_HEIGHT, lines.length);
  const onScroll = useCallback((event: UIEvent<HTMLDivElement>) => setScrollTop(event.currentTarget.scrollTop), []);
  const plain = codeKind === "disasm";
  const risky = prepared.hidden > 0 || prepared.homoglyphs > 0;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">{plain ? "Disassembly" : "Pseudo-C (decompiler output)"}</Badge>
        {truncated ? <Badge variant="secondary">Truncated</Badge> : null}
        <span className="text-xs text-muted-foreground tabular-nums">{lines.length.toLocaleString("en-US")} lines</span>
        <div className="ml-auto flex gap-1">
          <Button type="button" size="sm" variant="outline" onClick={() => void copy(escapedText(code), "Code (escaped)")}>
            <Copy className="size-3.5" aria-hidden />
            Copy
          </Button>
          {confirmRaw ? (
            <span className="flex items-center gap-1 text-xs">
              <span className={cn(risky && "text-destructive")}>
                {risky
                  ? "The raw text contains hidden or look-alike characters: pasted into an editor or shell it may read differently."
                  : "Copies the text exactly as the decompiler produced it."}
              </span>
              <Button
                type="button"
                size="sm"
                variant="destructive"
                onClick={() => {
                  setConfirmRaw(false);
                  void copy(code, "Raw code");
                }}
              >
                Copy raw anyway
              </Button>
              <Button type="button" size="sm" variant="ghost" onClick={() => setConfirmRaw(false)}>
                Cancel
              </Button>
            </span>
          ) : (
            <Button type="button" size="sm" variant="ghost" onClick={() => setConfirmRaw(true)}>
              Copy raw…
            </Button>
          )}
        </div>
      </div>
      <CodeBanner hidden={prepared.hidden} homoglyphs={prepared.homoglyphs} />
      <div
        role="table"
        aria-label={`Code of ${label}`}
        aria-rowcount={lines.length}
        tabIndex={0}
        className="overflow-y-auto rounded-md border bg-muted/20 font-mono text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        style={{ height: Math.min(height, Math.max(lines.length, 1) * LINE_HEIGHT + 2) }}
        onScroll={onScroll}
        onKeyDown={(event) => {
          const target = event.currentTarget;
          if (event.key === "PageDown") target.scrollTop += height - LINE_HEIGHT;
          else if (event.key === "PageUp") target.scrollTop -= height - LINE_HEIGHT;
          else if (event.key === "Home") target.scrollTop = 0;
          else if (event.key === "End") target.scrollTop = target.scrollHeight;
          else return;
          event.preventDefault();
        }}
      >
        <div role="rowgroup" style={{ height: lines.length * LINE_HEIGHT, position: "relative" }}>
          {lines.slice(start, end).map((line, offset) => {
            const index = start + offset;
            return (
              <div key={index} style={{ position: "absolute", top: index * LINE_HEIGHT, left: 0, right: 0 }}>
                <LineView line={line} number={index + 1} plain={plain} />
              </div>
            );
          })}
        </div>
      </div>
      {prepared.cut > 0 ? (
        <p className="text-xs text-muted-foreground">
          {prepared.cut.toLocaleString("en-US")} more lines are not shown (the viewer shows the first {MAX_VIEWER_LINES.toLocaleString("en-US")}).
        </p>
      ) : null}
    </div>
  );
}
