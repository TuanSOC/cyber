"use client";

import { History, Pencil, Pin, PinOff, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmButton } from "@/components/confirm-button";
import { NoteEditor } from "@/components/notes/note-editor";
import { NoteBody, NoteMeta, NoteTombstone, RefChips, VersionList } from "@/components/notes/note-parts";
import { AddToReportButton } from "@/components/reports/add-to-report";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { JobRoute } from "@/lib/ai";
import { type Investigation, caseErrorMessage } from "@/lib/case";
import { type Note, type NoteDetail, canEditNote, isStaleNote, sortNotes } from "@/lib/notes";
import type { Permission } from "@/lib/roles";
import {
  useCreateNote,
  useDeleteNote,
  useJobRoutes,
  useMemberNames,
  useNote,
  useNotes,
  useUpdateNote,
} from "@/lib/use-case";
import { useMe } from "@/lib/use-me";

/** Notes tab: versioned plain-text notes, pinned first, with linked records and history. */
export function NotesTab({
  orgId,
  inv,
  can,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
}) {
  const [showDeleted, setShowDeleted] = useState(false);
  const [composerKey, setComposerKey] = useState(0);
  const [historyOf, setHistoryOf] = useState<string | null>(null);
  const me = useMe();
  const names = useMemberNames(orgId).data ?? new Map<string, string>();
  const routes = useJobRoutes(orgId, inv.id);
  const notes = useNotes(orgId, inv.id, showDeleted);
  const create = useCreateNote(orgId, inv.id);
  const archived = inv.status === "archived";
  const writable = can("investigation.write") && !archived;
  const items = sortNotes(notes.data?.pages.flatMap((page) => page.items) ?? []);
  const perms = { write: writable, orgUpdate: can("org.update") };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Notes</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {writable ? (
          <NoteEditor
            key={composerKey}
            orgId={orgId}
            investigationId={inv.id}
            routes={routes}
            pending={create.isPending}
            submitLabel="Add note"
            onSubmit={(draft) =>
              create.mutate(draft, {
                onSuccess: () => {
                  setComposerKey((k) => k + 1);
                  toast.success("Note added");
                },
                onError: (error) => toast.error(caseErrorMessage(error)),
              })
            }
          />
        ) : (
          <p className="text-xs text-muted-foreground">
            {archived ? "This investigation is archived: notes are read-only." : "Your role can read notes but not write them."}
          </p>
        )}
        <label className="flex w-fit items-center gap-1.5 text-sm">
          <input type="checkbox" checked={showDeleted} onChange={(event) => setShowDeleted(event.target.checked)} />
          Show deleted notes
        </label>
        {notes.isError ? (
          <p className="text-sm text-destructive" role="alert">
            {caseErrorMessage(notes.error)}
          </p>
        ) : notes.isPending ? (
          <p className="text-sm text-muted-foreground">Loading notes…</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No notes yet.</p>
        ) : (
          <ul className="flex flex-col gap-3">
            {items.map((note) => (
              <NoteCard
                key={note.id}
                orgId={orgId}
                note={note}
                names={names}
                routes={routes}
                editable={canEditNote(note, me.data?.user.id, perms)}
                canCite={writable}
                onHistory={() => setHistoryOf(note.id)}
              />
            ))}
          </ul>
        )}
        {notes.hasNextPage && (
          <Button variant="outline" size="sm" className="w-fit" disabled={notes.isFetchingNextPage} onClick={() => void notes.fetchNextPage()}>
            Load more notes
          </Button>
        )}
        <NoteHistorySheet orgId={orgId} noteId={historyOf} routes={routes} onClose={() => setHistoryOf(null)} />
      </CardContent>
    </Card>
  );
}

function NoteCard({
  orgId,
  note,
  names,
  routes,
  editable,
  canCite,
  onHistory,
}: {
  orgId: string;
  note: Note;
  names: ReadonlyMap<string, string>;
  routes: ReadonlyMap<string, JobRoute>;
  editable: boolean;
  /** "Add to report" (a report draft can be changed: investigation.write, case not archived). */
  canCite: boolean;
  onHistory: () => void;
}) {
  const [editing, setEditing] = useState(false);
  // The version the edit is based on; moves forward when the user takes over a newer version.
  const [baseVersion, setBaseVersion] = useState(note.version);
  const [stale, setStale] = useState(false);
  const [editorKey, setEditorKey] = useState(0);
  const [initial, setInitial] = useState<{ body: string; refs: Note["refs"] } | null>(null);
  const update = useUpdateNote(orgId, note.investigation_id);
  const remove = useDeleteNote(orgId, note.investigation_id);

  const flag = (body: { pinned?: boolean; include_in_reports?: boolean }) =>
    update.mutate(
      { noteId: note.id, body: { expected_version: note.version, ...body } },
      { onError: (error) => toast.error(caseErrorMessage(error)) },
    );

  if (note.deleted) {
    return (
      <li className="flex flex-col gap-1 rounded-md border border-dashed p-3">
        <NoteTombstone note={note} names={names} />
        <Button variant="link" size="sm" className="h-auto w-fit p-0 text-xs" onClick={onHistory}>
          Version history
        </Button>
      </li>
    );
  }

  return (
    <li className="flex flex-col gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-start gap-2">
        <NoteMeta note={note} />
        <div className="ml-auto flex gap-1">
          {canCite && !editing ? (
            <AddToReportButton orgId={orgId} investigationId={note.investigation_id} row={{ kind: "note", ref_id: note.id }} />
          ) : null}
          <Button variant="ghost" size="icon" className="size-7" aria-label="Version history" onClick={onHistory}>
            <History className="size-4" aria-hidden />
          </Button>
          {editable && !editing ? (
            <>
              <Button
                variant="ghost"
                size="icon"
                className="size-7"
                aria-label={note.pinned ? "Unpin note" : "Pin note"}
                disabled={update.isPending}
                onClick={() => flag({ pinned: !note.pinned })}
              >
                {note.pinned ? <PinOff className="size-4" aria-hidden /> : <Pin className="size-4" aria-hidden />}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="size-7"
                aria-label="Edit note"
                onClick={() => {
                  setBaseVersion(note.version);
                  setInitial({ body: note.body ?? "", refs: note.refs });
                  setStale(false);
                  setEditing(true);
                }}
              >
                <Pencil className="size-4" aria-hidden />
              </Button>
              <ConfirmButton
                variant="ghost"
                size="icon"
                className="size-7"
                aria-label="Delete note"
                title="Delete this note?"
                description="The note is hidden and marked deleted. Its versions stay in the history."
                confirmLabel="Delete"
                pending={remove.isPending}
                onConfirm={() =>
                  remove.mutate(note.id, {
                    onSuccess: () => toast.success("Note deleted"),
                    onError: (error) => toast.error(caseErrorMessage(error)),
                  })
                }
              >
                <Trash2 className="size-4" aria-hidden />
              </ConfirmButton>
            </>
          ) : null}
        </div>
      </div>
      {editing && initial ? (
        <>
          {stale ? (
            <StaleNotePrompt
              orgId={orgId}
              noteId={note.id}
              onUseNewer={(detail) => {
                setInitial({ body: detail.note.body ?? "", refs: detail.note.refs });
                setBaseVersion(detail.note.version);
                setEditorKey((k) => k + 1);
                setStale(false);
              }}
              onKeepMine={(version) => {
                setBaseVersion(version);
                setStale(false);
              }}
            />
          ) : null}
          <NoteEditor
            key={editorKey}
            orgId={orgId}
            investigationId={note.investigation_id}
            routes={routes}
            initial={initial}
            pending={update.isPending}
            submitLabel="Save new version"
            showFlags={false}
            onCancel={() => {
              setEditing(false);
              setStale(false);
            }}
            onSubmit={(draft) =>
              update.mutate(
                { noteId: note.id, body: { expected_version: baseVersion, body: draft.body, refs: draft.refs } },
                {
                  onSuccess: () => {
                    setEditing(false);
                    toast.success("Note saved");
                  },
                  onError: (error) => {
                    if (isStaleNote(error)) setStale(true);
                    else toast.error(caseErrorMessage(error));
                  },
                },
              )
            }
          />
        </>
      ) : (
        <>
          <NoteBody body={note.body ?? ""} />
          <RefChips orgId={orgId} refs={note.refs} routes={routes} />
          {editable ? (
            <label className="flex w-fit items-center gap-1.5 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={note.include_in_reports}
                disabled={update.isPending}
                onChange={(event) => flag({ include_in_reports: event.target.checked })}
              />
              Include in reports and the timeline
            </label>
          ) : null}
        </>
      )}
    </li>
  );
}

/** `409 stale_note`: show the newer text and let the user reload it or keep their edit. */
function StaleNotePrompt({
  orgId,
  noteId,
  onUseNewer,
  onKeepMine,
}: {
  orgId: string;
  noteId: string;
  onUseNewer: (detail: NoteDetail) => void;
  onKeepMine: (version: number) => void;
}) {
  const detail = useNote(orgId, noteId);
  return (
    <div className="flex flex-col gap-2 rounded-md border border-dashed p-3 text-sm" role="alert">
      <p className="font-medium">Someone saved a newer version of this note.</p>
      {detail.isError ? (
        <p className="text-muted-foreground">{caseErrorMessage(detail.error)}</p>
      ) : !detail.data ? (
        <p className="text-muted-foreground">Loading the newer version…</p>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            v{detail.data.note.version} by {detail.data.note.author_name}:
          </p>
          <div className="max-h-48 overflow-y-auto rounded border bg-muted/40 p-2">
            <NoteBody body={detail.data.note.body ?? ""} />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => detail.data && onUseNewer(detail.data)}>
              Reload the newer version
            </Button>
            <Button size="sm" variant="outline" onClick={() => detail.data && onKeepMine(detail.data.note.version)}>
              Keep my text and save over it
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function NoteHistorySheet({
  orgId,
  noteId,
  routes,
  onClose,
}: {
  orgId: string;
  noteId: string | null;
  routes: ReadonlyMap<string, JobRoute>;
  onClose: () => void;
}) {
  const detail = useNote(orgId, noteId);
  return (
    <Sheet open={noteId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>Version history</SheetTitle>
          <SheetDescription>Every saved version of the note, newest first, as plain text.</SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">
          {detail.isError ? (
            <p className="text-sm text-destructive" role="alert">
              {caseErrorMessage(detail.error)}
            </p>
          ) : !detail.data ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <VersionList orgId={orgId} versions={detail.data.versions} routes={routes} />
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
