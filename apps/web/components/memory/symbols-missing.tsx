"use client";

import { RotateCcw } from "lucide-react";

import { CopyButton } from "@/components/analysis/result-parts";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { SYMBOLS_RUNBOOK, type SymbolsInfo, bannerText, windowsSymbolsCommand } from "@/lib/memory";

const ASK_OPERATOR = "Ask your operator to add these symbols, then re-run the analysis.";

/**
 * The `symbols_missing` state (RT12): never shown as "no findings". Windows gets the exact
 * operator command, built from the validated PDB name, GUID and age only; a Linux banner is
 * attacker-chosen text, shown quoted and inert (never in a command or a copy button). Members
 * without `org.update` are told to ask their operator. "Re-run" is always offered: the API
 * cannot see the symbol store.
 */
export function SymbolsMissing({
  symbols,
  canOperate,
  canRerun,
  rerunPending,
  rerunError,
  onRerun,
}: {
  symbols: SymbolsInfo | null | undefined;
  /** `org.update` (operators / admins) sees the command. */
  canOperate: boolean;
  canRerun: boolean;
  rerunPending?: boolean;
  rerunError?: string | null;
  onRerun: () => void;
}) {
  const pdb = symbols?.windows_pdb ?? null;
  const banner = bannerText(symbols?.linux_banner?.banner);
  const command = pdb ? windowsSymbolsCommand(pdb) : null;

  return (
    <Alert className="mb-6 border-amber-500/60" data-testid="symbols-missing">
      <AlertTitle>Not analyzed: the symbols for this kernel are missing</AlertTitle>
      <AlertDescription className="flex flex-col gap-3">
        <p>
          This is not a clean result. Without the kernel&apos;s symbol table no analysis step ran, so there are no
          processes, connections or findings to show. Symbols are never fetched automatically.
        </p>

        {pdb ? (
          <div className="flex flex-col gap-2">
            <p className="font-medium text-foreground">Windows kernel symbols needed</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-xs">
              <dt>PDB</dt>
              <dd className="font-mono break-all">{pdb.name}</dd>
              <dt>GUID</dt>
              <dd className="font-mono break-all">{pdb.guid}</dd>
              <dt>Age</dt>
              <dd className="font-mono">{pdb.age}</dd>
            </dl>
            {!canOperate ? (
              <p>{ASK_OPERATOR}</p>
            ) : command ? (
              <div className="flex flex-col gap-1">
                <p className="text-xs">Run on the platform host, then re-run this analysis:</p>
                <div className="flex items-start gap-1 rounded-md border bg-muted/40 p-2">
                  <pre className="min-w-0 flex-1 overflow-x-auto font-mono text-xs whitespace-pre-wrap break-all" data-testid="symbols-command">
                    <code>{command}</code>
                  </pre>
                  <CopyButton value={command} label="Copy the symbols command" />
                </div>
              </div>
            ) : (
              <p>The recorded PDB identity does not match the expected format, so no command is offered. Ask your operator to inspect this job.</p>
            )}
          </div>
        ) : null}

        {banner ? (
          <div className="flex flex-col gap-2">
            <p className="font-medium text-foreground">Linux kernel symbols needed for the kernel that reports:</p>
            {/* Attacker-chosen text: quoted, inert, never part of a command or a copy button. */}
            <blockquote className="border-l-2 pl-3 font-mono text-xs whitespace-pre-wrap break-all" data-testid="linux-banner">
              “{banner}”
            </blockquote>
            {canOperate ? (
              <p className="text-xs">
                Build an ISF for this exact kernel with dwarf2json on a machine that has its debug kernel, place it in the
                import folder, and import it with <span className="font-mono">memory:symbols -- import</span>. Runbook:{" "}
                {SYMBOLS_RUNBOOK}.
              </p>
            ) : (
              <p>{ASK_OPERATOR}</p>
            )}
          </div>
        ) : null}

        {!pdb && !banner ? (
          <p>The kernel identity that needs symbols was not recorded. {canOperate ? `Runbook: ${SYMBOLS_RUNBOOK}.` : ASK_OPERATOR}</p>
        ) : null}

        <div className="flex flex-wrap items-center gap-3">
          {canRerun ? (
            <Button size="sm" variant="outline" disabled={rerunPending} onClick={onRerun}>
              <RotateCcw className="size-4" aria-hidden />
              {rerunPending ? "Requesting…" : "Re-run"}
            </Button>
          ) : null}
          <span className="text-xs">
            The platform cannot see the symbol store: re-run once the symbols are imported. A re-run that still misses
            them ends in this same state.
          </span>
        </div>
        {rerunError ? (
          <p role="alert" className="text-destructive">
            {rerunError}
          </p>
        ) : null}
      </AlertDescription>
    </Alert>
  );
}
