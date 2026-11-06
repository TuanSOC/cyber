---
phase: 10
title: "Reverse engineering frontend"
status: pending
priority: P2
effort: "15h"
dependencies: [1]
---

# Phase 10: Reverse engineering frontend (group B, 2i, web only)

## Overview
The Reverse Engineering module in the web app, built against the frozen phase-1 contracts: job list and job page, functions table, function view with a **safe code viewer**, imports and strings tabs, the run dialog, "Explain function" and the Malware Lab links. Everything attacker-derived (names, strings, code) is rendered as text.

**Owns:** `apps/web/lib/{reverse,c-tokenizer}.ts` (+ tests), `lib/use-re-job.ts`, `components/reverse/**` (including the three slots mounted by phase 1), `app/(app)/o/[orgId]/reverse-engineering/**`. No mount edits outside the slots.

## Requirements
- **Routes:** `/o/{org}/reverse-engineering` (RE jobs of the org, newest first, with status, sample name, engine, profile, function count) and `/reverse-engineering/{job}` with tabs **Overview** (program facts, source static job link, stage strip with ok / timeout / failed / skipped and `truncated` flags, decompile budget, `capa_linked` / `capa_unlocated`, the "synthetic metrics" note in help text), **Functions**, **Imports**, **Strings**, **Findings** and **IOCs** (the shared tabs). `?fn=<entry>&tab=code|facts` opens a function (deep links from AI citations).
- **Run dialog** (slot `run-re-analysis.tsx` on the Malware Lab job header, shown for succeeded static `full` PE / ELF jobs): profile (`full`; `quick` only when the API reports it available), an explanation of time and resource cost, the "never executed" statement; errors mapped through `lib/http-errors.ts`, with `429 heavy_analysis_busy` explained as "another memory, disk or RE analysis is running; try again when it finishes" (no queue position: there is no queue, RT2).
- **Functions table:** virtualized, server-paginated, filters (name, decompiled, has capability, calls suspicious import, references IOC string), sort (entry, size, rank, name); entries shown as `0x…` from the API's decimal strings via `BigInt` (never `Number`).
- **Function view:** facts (signature, name source with "named by the engine", flags), callers / callees (links), imports called, strings referenced, linked capabilities (ATT&CK ids), findings; "why (not) decompiled"; **Decompile this function** (creates a new `full` job with this entry first, after a confirmation that the sample is re-analysed (minutes) and the result is a new RE job; disabled while one is active; the page shows "a newer RE job of this sample exists" with a link, RT10); **Explain function** (slot `explain-function-button.tsx`; hidden with the M6 policy reason when blocked; opens the existing AI run view).
- **Code viewer** (`components/reverse/code-viewer.tsx` + `lib/c-tokenizer.ts`):
  - a hand-written linear-time scanner (one pass, no regular expressions with backtracking) producing tokens: keyword, type, identifier, number, string, char, comment, preprocessor, punctuation, whitespace, invalid; unit- and property-tested (random input, 1 MiB of `"`/`\`/`/*`, unterminated literals) for linear time and losslessness (concatenated tokens == input);
  - rendered as React `<span>` elements with Tailwind classes; **no `dangerouslySetInnerHTML`**, no HTML-producing highlighter; a lint rule (`react/no-danger`) enforced on `components/reverse/**`;
  - invisible and control characters (C0 / C1 except `\t`, bidi embeddings / overrides / isolates U+202A–U+202E and U+2066–U+2069, zero-width U+200B–U+200F, U+2060, U+FEFF, tag characters) are rendered as visible escapes `⟨U+202E⟩` in a distinct style and counted in a banner ("n hidden or direction-changing characters shown"); identifiers containing non-ASCII characters (homoglyphs such as a Cyrillic `а`) get a distinct style and are counted in the same banner (RT17); **"Copy" copies the escaped text**; "Copy raw" is a secondary action with a warning that the text contains them;
  - line numbers, line virtualization for up to 5 000 lines, horizontal scroll per line (no wrapping by default), a monospaced font; truncated code shows the engine marker and a "truncated" badge; `disasm` code kind uses a plain (non-C) token style.
- **No call-graph view** (RT24, ROADMAP "Later"): callers and callees are linked lists in the function view.
- **Malware Lab link** (slot `capability-functions-link.tsx`): on capability rows, "Functions (n)" when an RE job linked them, "re-run static analysis to link capabilities" when the static job predates locations, nothing otherwise.
- **Accessibility and performance:** keyboard navigation in the table and code viewer; the code viewer stays responsive on a 64 KiB function (measured in the component test with a generated input).

## Implementation Steps
1. `lib/reverse.ts` (typed client calls from `packages/contracts`, BigInt helpers) and `lib/use-re-job.ts` (polling like the other job hooks).
2. `c-tokenizer.ts` with its tests first (losslessness, linear time, hostile inputs).
3. Code viewer with the invisible-character rendering and banner; component tests (Vitest + Testing Library) including a Trojan Source sample whose rendered text shows the escapes.
4. Pages, tables, function view, run dialog, slots.
5. `pnpm --filter web test -- <own paths>`, `typecheck`, `lint`.

## Success Criteria
- [ ] The RE pages render the seeded fixture job (mocked API) with every tab, filter and deep link.
- [ ] The tokenizer is lossless and linear on hostile inputs; no `dangerouslySetInnerHTML` in `components/reverse/**` (lint).
- [ ] Bidi and invisible characters and non-ASCII identifiers are shown with the banner; "Copy" gives the escaped text, "Copy raw" the raw text after the warning.
- [ ] Long names (255 characters) never break the table or function view layout.

## Risk Assessment
- **XSS through names / strings / code:** React text rendering only, the lint rule, and the e2e in phase 12 with the injection twins.
- **Misleading code display:** the escapes make direction tricks visible; the viewer never interprets comments or markup.
- **Large functions:** line virtualization and the server-side 64 KiB cap.
