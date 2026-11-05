"use client";

import { Loader2 } from "lucide-react";
import { type ReactNode, useState } from "react";

import { ContextSummary } from "@/components/ai/context-summary";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { type AiRunCreate, aiRequestErrorText, contextJson, taskLabel } from "@/lib/ai";
import { ApiError, errorMessage } from "@/lib/api";
import { useContextPreview } from "@/lib/use-ai";

export function aiErrorMessage(error: unknown): string {
  return aiRequestErrorText(error instanceof ApiError ? error.code : undefined, errorMessage(error));
}

/**
 * "What will be sent": the preview of a run's context (counts, truncation, pseudonymization,
 * inclusion toggles and the exact JSON as plain text), then an explicit "Run" confirmation.
 */
export function ContextPreviewDialog({
  orgId,
  request,
  canManage,
  onRun,
  pending,
  children,
  title,
}: {
  orgId: string;
  request: AiRunCreate;
  canManage: boolean;
  onRun: () => void;
  pending?: boolean;
  /** Trigger button content. */
  children: ReactNode;
  title?: string;
}) {
  const [open, setOpen] = useState(false);
  const preview = useContextPreview(orgId);
  const data = preview.data;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) preview.mutate(request);
        else preview.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={pending}>
          {children}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title ?? taskLabel(request.task)}: what will be sent</DialogTitle>
          <DialogDescription>
            The evidence excerpts below leave the platform for the AI provider when you run this analysis. Nothing is
            sent or stored by this preview.
          </DialogDescription>
        </DialogHeader>
        {preview.isPending && (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden /> Building the context…
          </p>
        )}
        {preview.isError && (
          <p className="text-sm text-destructive" role="alert">
            {aiErrorMessage(preview.error)}
          </p>
        )}
        {data && (
          <div className="flex flex-col gap-3">
            <p className="text-xs text-muted-foreground">
              Provider <span className="font-medium text-foreground">{data.provider}</span> · model{" "}
              <span className="font-mono text-foreground">{data.model}</span> · {data.items.length} items
            </p>
            <ContextSummary
              orgId={orgId}
              stats={data.context_stats}
              inclusions={data.inclusions}
              categories={data.categories}
              canManage={canManage}
            />
            <details className="rounded-md border">
              <summary className="cursor-pointer px-3 py-2 text-xs font-medium">Exact context (JSON)</summary>
              <pre className="max-h-80 overflow-auto border-t p-3 font-mono text-[11px] break-all whitespace-pre-wrap">
                {contextJson(data.items)}
              </pre>
            </details>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            disabled={!data || pending}
            onClick={() => {
              setOpen(false);
              onRun();
            }}
          >
            Run analysis
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
