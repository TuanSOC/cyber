"use client";

import { useState } from "react";

import { QueryError } from "@/components/query-error";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { contextJson, shortSha } from "@/lib/ai";
import { useOrg } from "@/lib/org-context";
import { useAiRunContext } from "@/lib/use-ai";

/**
 * "View sent context": the frozen context(s) exactly as sent (plain text). "Show original
 * names" adds the pseudonym map (`reveal`, audited): analysts and up only (the API answers
 * 403 to viewers, so the toggle is not offered to them).
 */
export function ContextViewer({ orgId, runId }: { orgId: string; runId: string }) {
  const { can } = useOrg();
  const canReveal = can("evidence.write");
  const [open, setOpen] = useState(false);
  const [reveal, setReveal] = useState(false);
  const context = useAiRunContext(orgId, runId, reveal && canReveal, open);
  const data = context.data;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="link" size="sm" className="h-auto p-0 text-xs">
          View sent context
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Context sent to the provider</DialogTitle>
          <DialogDescription>
            The redacted evidence exactly as sent, with internal names as pseudonyms. Shown as text only.
          </DialogDescription>
        </DialogHeader>
        {canReveal && (
          <div className="flex items-center gap-2 text-xs">
            <input
              id={`reveal-${runId}`}
              type="checkbox"
              checked={reveal}
              onChange={(event) => setReveal(event.target.checked)}
            />
            <Label htmlFor={`reveal-${runId}`} className="text-xs">
              Show original names (pseudonym map, audited)
            </Label>
          </div>
        )}
        {context.isError && <QueryError error={context.error} onRetry={() => void context.refetch()} />}
        {context.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
        {data && (
          <div className="flex flex-col gap-3">
            <p className="font-mono text-xs text-muted-foreground" title={data.context_sha256}>
              sha256 {shortSha(data.context_sha256)}
            </p>
            {data.stages.map((stage) => (
              <section key={stage.stage} className="flex flex-col gap-1">
                <h3 className="text-xs font-medium">
                  {stage.stage === "base" ? "Evidence context" : "Incident reduce context"} · {stage.items.length} items
                </h3>
                {reveal && canReveal && stage.pseudonym_map && Object.keys(stage.pseudonym_map).length > 0 && (
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 rounded-md border p-2 font-mono text-[11px]">
                    {Object.entries(stage.pseudonym_map).map(([pseudonym, original]) => (
                      <div key={pseudonym} className="contents">
                        <dt className="text-muted-foreground">{pseudonym}</dt>
                        <dd className="break-all">{original}</dd>
                      </div>
                    ))}
                  </dl>
                )}
                <pre className="max-h-96 overflow-auto rounded-md border p-3 font-mono text-[11px] break-all whitespace-pre-wrap">
                  {contextJson(stage.items)}
                </pre>
              </section>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
