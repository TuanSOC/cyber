import { Link2, X } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import type { JobRoute } from "@/lib/ai";
import { visText } from "@/lib/case";
import { formatDate } from "@/lib/format";
import {
  type Note,
  type NoteRef,
  type NoteVersion,
  editedBadge,
  noteRefHref,
  noteRefLabel,
  refKey,
  tombstoneText,
} from "@/lib/notes";

/*
 * Presentational parts of the notes tab (no data fetching). Note text is rendered only as a
 * React text node: no Markdown, no HTML, no auto-linking; invisible characters are shown.
 */

/** A note body as plain text (newlines kept, invisible characters made visible). */
export function NoteBody({ body }: { body: string }) {
  return <p className="text-sm whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{visText(body)}</p>;
}

/** Ref chips; each links to its row through the M5 deep-link helper (or is plain text). */
export function RefChips({
  orgId,
  refs,
  routes,
  onRemove,
}: {
  orgId: string;
  refs: readonly NoteRef[];
  routes: ReadonlyMap<string, JobRoute>;
  onRemove?: (ref: NoteRef) => void;
}) {
  if (refs.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Linked records">
      {refs.map((ref) => {
        const href = noteRefHref(orgId, ref, routes);
        const text = noteRefLabel(ref);
        return (
          <li key={refKey(ref)} className="inline-flex items-center gap-1 rounded border px-1.5 text-[11px]">
            <Link2 className="size-3" aria-hidden />
            {href ? (
              <Link href={href} className="hover:underline" title={`Open the linked ${text}`}>
                {text}
              </Link>
            ) : (
              <span title="The linked record has no page in this view">{text}</span>
            )}
            {onRemove ? (
              <button
                type="button"
                className="rounded hover:bg-muted"
                aria-label={`Remove link ${text}`}
                onClick={() => onRemove(ref)}
              >
                <X className="size-3" aria-hidden />
              </button>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

/** Header line of a note: author, time, edited badge, pinned / report flags. */
export function NoteMeta({ note }: { note: Note }) {
  const when = formatDate(note.updated_at);
  const edited = editedBadge(note);
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <span className="font-medium text-foreground">{note.author_name}</span>
      <time dateTime={note.updated_at} title={when.utc}>
        {when.local}
      </time>
      {edited ? <Badge variant="outline">{edited}</Badge> : null}
      {note.pinned ? <Badge variant="secondary">Pinned</Badge> : null}
      {note.include_in_reports ? <Badge variant="outline">In reports</Badge> : null}
    </div>
  );
}

/** A deleted note: only the tombstone, never the body. */
export function NoteTombstone({ note, names }: { note: Note; names: ReadonlyMap<string, string> }) {
  return (
    <p className="text-sm text-muted-foreground italic" data-note-tombstone="">
      {tombstoneText(note, names)}. The earlier versions are kept in the history.
    </p>
  );
}

/** The versions of a note, newest first, as plain text. */
export function VersionList({
  orgId,
  versions,
  routes,
}: {
  orgId: string;
  versions: readonly NoteVersion[];
  routes: ReadonlyMap<string, JobRoute>;
}) {
  const sorted = [...versions].sort((a, b) => b.version - a.version);
  return (
    <ol className="flex flex-col gap-4">
      {sorted.map((v) => {
        const when = formatDate(v.created_at);
        return (
          <li key={v.version} className="flex flex-col gap-1 border-l-2 pl-3">
            <p className="text-xs text-muted-foreground">
              <span className="font-medium text-foreground">v{v.version}</span> · {v.author_name} ·{" "}
              <time dateTime={v.created_at} title={when.utc}>
                {when.local}
              </time>
            </p>
            <NoteBody body={v.body} />
            <RefChips orgId={orgId} refs={v.refs} routes={routes} />
          </li>
        );
      })}
    </ol>
  );
}
