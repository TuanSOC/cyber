"use client";

import { RotateCcw, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/format";

export type UploadItem = {
  id: number;
  file: File;
  description: string;
  progress: number;
  state: "queued" | "uploading" | "done" | "failed";
  error?: string;
};

export function UploadRow({
  item,
  onCancel,
  onRetry,
  onRemove,
}: {
  item: UploadItem;
  onCancel: () => void;
  onRetry: () => void;
  onRemove: () => void;
}) {
  return (
    <li className="rounded-md border p-2 text-sm">
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate" title={item.file.name}>
          {item.file.name}
        </span>
        <span className="text-xs text-muted-foreground">{formatBytes(item.file.size)}</span>
        {item.state === "uploading" && (
          <Button variant="ghost" size="icon" aria-label={`Cancel upload of ${item.file.name}`}
            onClick={onCancel}>
            <X className="size-4" aria-hidden />
          </Button>
        )}
        {item.state === "failed" && (
          <Button variant="ghost" size="icon" aria-label={`Retry ${item.file.name}`} onClick={onRetry}>
            <RotateCcw className="size-4" aria-hidden />
          </Button>
        )}
        {(item.state === "queued" || item.state === "failed" || item.state === "done") && (
          <Button variant="ghost" size="icon" aria-label={`Remove ${item.file.name} from the list`}
            onClick={onRemove}>
            <X className="size-4" aria-hidden />
          </Button>
        )}
      </div>
      {item.state === "uploading" && (
        <div className="mt-2 h-1.5 overflow-hidden rounded bg-muted" role="progressbar"
          aria-label={`Uploading ${item.file.name}`} aria-valuenow={Math.round(item.progress * 100)}
          aria-valuemin={0} aria-valuemax={100}>
          <div className="h-full bg-primary transition-all" style={{ width: `${item.progress * 100}%` }} />
        </div>
      )}
      {item.state === "queued" && <p className="mt-1 text-xs text-muted-foreground">Queued</p>}
      {item.state === "done" && <p className="mt-1 text-xs text-sev-low">Uploaded and hashed</p>}
      {item.state === "failed" && <p className="mt-1 text-xs text-destructive">{item.error}</p>}
    </li>
  );
}
