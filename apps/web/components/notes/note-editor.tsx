"use client";

import { useId, useState } from "react";

import { RefChips } from "@/components/notes/note-parts";
import { RefPicker } from "@/components/notes/ref-picker";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import type { JobRoute } from "@/lib/ai";
import { type NoteRef, addRef, canSubmitNote, noteCounter, removeRef } from "@/lib/notes";

export type NoteDraft = { body: string; refs: NoteRef[]; pinned: boolean; include_in_reports: boolean };

/**
 * Plain-text note editor: a `<textarea>` with a character counter (20 000), linked records
 * through the picker, and the pinned / include-in-reports flags. No Markdown or rich text.
 */
export function NoteEditor({
  orgId,
  investigationId,
  routes,
  initial,
  pending,
  submitLabel,
  onSubmit,
  onCancel,
  showFlags = true,
}: {
  orgId: string;
  investigationId: string;
  routes: ReadonlyMap<string, JobRoute>;
  initial?: Partial<NoteDraft>;
  pending: boolean;
  submitLabel: string;
  onSubmit: (draft: NoteDraft) => void;
  onCancel?: () => void;
  showFlags?: boolean;
}) {
  const id = useId();
  const [body, setBody] = useState(initial?.body ?? "");
  const [refs, setRefs] = useState<NoteRef[]>(initial?.refs ?? []);
  const [pinned, setPinned] = useState(initial?.pinned ?? false);
  const [include, setInclude] = useState(initial?.include_in_reports ?? false);
  const counter = noteCounter(body);
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (canSubmitNote(body)) onSubmit({ body, refs, pinned, include_in_reports: include });
      }}
    >
      <label htmlFor={id} className="sr-only">
        Note text
      </label>
      <Textarea
        id={id}
        rows={5}
        value={body}
        placeholder="Plain text. Formatting characters are kept as typed."
        aria-describedby={`${id}-count`}
        aria-invalid={counter.over}
        onChange={(event) => setBody(event.target.value)}
      />
      <p id={`${id}-count`} className={counter.over ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
        {counter.text} characters{counter.over ? " — too long" : ""}
      </p>
      <RefChips orgId={orgId} refs={refs} routes={routes} onRemove={(ref) => setRefs((r) => removeRef(r, ref))} />
      <div className="flex flex-wrap items-center gap-3">
        <RefPicker
          orgId={orgId}
          investigationId={investigationId}
          count={refs.length}
          onAdd={(ref) => setRefs((r) => addRef(r, ref))}
        />
        {showFlags ? (
          <>
            <label className="flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={pinned} onChange={(event) => setPinned(event.target.checked)} />
              Pinned
            </label>
            <label className="flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={include} onChange={(event) => setInclude(event.target.checked)} />
              Include in reports and the timeline
            </label>
          </>
        ) : null}
        <div className="ml-auto flex gap-2">
          {onCancel ? (
            <Button type="button" variant="outline" size="sm" onClick={onCancel}>
              Cancel
            </Button>
          ) : null}
          <Button type="submit" size="sm" disabled={pending || !canSubmitNote(body)}>
            {submitLabel}
          </Button>
        </div>
      </div>
    </form>
  );
}
