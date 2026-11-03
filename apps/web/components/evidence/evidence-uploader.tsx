"use client";

import { useQueryClient } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { UploadRow, type UploadItem } from "@/components/evidence/upload-row";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError, errorMessage } from "@/lib/api";
import { type UploadHandle, uploadEvidence } from "@/lib/upload";

type Item = UploadItem;

let nextId = 1;

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "payload_too_large") return "File exceeds the maximum evidence size.";
    if (error.code === "aborted") return "Cancelled.";
  }
  return errorMessage(error);
}

/**
 * Uploads one file at a time (the API caps concurrent uploads per user). Files added while an
 * upload runs join the same queue; leaving the page aborts the running upload.
 */
export function EvidenceUploader({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const queryClient = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const queue = useRef<Item[]>([]);
  const current = useRef<UploadHandle | null>(null);
  const running = useRef(false);
  const dragDepth = useRef(0);
  const [items, setItems] = useState<Item[]>([]);
  const [description, setDescription] = useState("");
  const [dragging, setDragging] = useState(false);
  const busy = items.some((item) => item.state === "uploading" || item.state === "queued");

  const update = (id: number, patch: Partial<Item>) =>
    setItems((all) => all.map((item) => (item.id === id ? { ...item, ...patch } : item)));

  useEffect(() => {
    if (!busy) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [busy]);

  // Leaving the page cancels the running upload and drops the queue.
  useEffect(
    () => () => {
      queue.current = [];
      current.current?.abort();
    },
    [],
  );

  async function drain() {
    if (running.current) return;
    running.current = true;
    let item: Item | undefined;
    while ((item = queue.current.shift())) {
      const { id } = item;
      update(id, { state: "uploading", progress: 0, error: undefined });
      current.current = uploadEvidence(orgId, investigationId, item.file, item.description, (p) =>
        update(id, { progress: p }),
      );
      try {
        const evidence = await current.current.promise;
        update(id, { state: "done", progress: 1 });
        toast.success(`Uploaded ${evidence.original_filename}`);
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence-list", investigationId] }),
          queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigation", investigationId] }),
          queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigations"] }),
        ]);
      } catch (error) {
        update(id, { state: "failed", error: describe(error) });
      }
    }
    current.current = null;
    running.current = false;
  }

  function enqueue(newItems: Item[]) {
    queue.current.push(...newItems);
    void drain();
  }

  function add(files: FileList | null) {
    if (!files?.length) return;
    const added = Array.from(files).map((file) => ({
      id: nextId++,
      file,
      description: description.trim(),
      progress: 0,
      state: "queued" as const,
    }));
    setItems((all) => [...all, ...added]);
    enqueue(added);
  }

  function retry(item: Item) {
    update(item.id, { state: "queued", error: undefined, progress: 0 });
    enqueue([{ ...item, state: "queued" }]);
  }

  function remove(item: Item) {
    queue.current = queue.current.filter((queued) => queued.id !== item.id);
    setItems((all) => all.filter((other) => other.id !== item.id));
  }

  return (
    <div className="flex flex-col gap-3">
      <Input
        aria-label="Description for the next uploaded files (optional)"
        placeholder="Description for the next files (optional)"
        maxLength={2000}
        value={description}
        onChange={(event) => setDescription(event.target.value)}
      />
      <button
        type="button"
        onClick={() => input.current?.click()}
        onDragEnter={(event) => {
          event.preventDefault();
          dragDepth.current += 1;
          setDragging(true);
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={() => {
          dragDepth.current -= 1;
          if (dragDepth.current <= 0) setDragging(false);
        }}
        onDrop={(event) => {
          event.preventDefault();
          dragDepth.current = 0;
          setDragging(false);
          add(event.dataTransfer.files);
        }}
        className={`flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-sm text-muted-foreground transition-colors hover:border-primary/60 ${dragging ? "border-primary bg-primary/5" : ""}`}
      >
        <Upload className="size-5" aria-hidden />
        Drop files here or click to choose. Files are stored as-is, hashed, and never opened.
      </button>
      <input
        ref={input}
        type="file"
        multiple
        hidden
        onChange={(event) => {
          add(event.target.files);
          event.target.value = "";
        }}
      />
      {items.length > 0 && (
        <ul className="flex flex-col gap-2" aria-live="polite">
          {items.map((item) => (
            <UploadRow
              key={item.id}
              item={item}
              onCancel={() => current.current?.abort()}
              onRetry={() => retry(item)}
              onRemove={() => remove(item)}
            />
          ))}
        </ul>
      )}
      {items.some((item) => item.state === "done") && (
        <Button variant="ghost" size="sm" className="self-start"
          onClick={() => setItems((all) => all.filter((item) => item.state !== "done"))}>
          Clear finished
        </Button>
      )}
    </div>
  );
}
