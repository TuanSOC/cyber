import { InertText } from "@/components/disk/inert-text";
import { Badge } from "@/components/ui/badge";
import {
  type DiskFile,
  FILE_FLAG_HINTS,
  FILE_FLAG_LABELS,
  FILE_TYPE_LABELS,
  KNOWN_LABELS,
  TIME_BASIS_LOCAL,
  inertText,
  pathMarkers,
  visibleFlags,
} from "@/lib/disk";
import { formatBytes, formatDate, shortHash } from "@/lib/format";
import { cn } from "@/lib/utils";

/** The grid of a file row and its header (shared so the columns line up). */
export const FILE_GRID = "grid grid-cols-[minmax(10rem,1.2fr)_minmax(12rem,2fr)_6rem_10rem_7rem_9rem_7rem] items-center gap-2 px-2";
export const FILE_ROW_HEIGHT = 40;

/** A file time: local display, UTC tooltip; FAT times are wall-clock times with no zone. */
export function FileTime({ iso, basis }: { iso: string | null | undefined; basis: DiskFile["time_basis"] }) {
  if (!iso) return <span className="text-muted-foreground">—</span>;
  if (basis === "local_unknown") {
    // The stored instant is the image's wall-clock value labelled UTC: shown as written.
    const text = iso.replace("T", " ").replace(/(\.\d+)?(Z|[+-]\d\d:\d\d)$/, "");
    return (
      <span title={`${text} (${TIME_BASIS_LOCAL})`}>
        {text} <span className="text-xs text-muted-foreground">({TIME_BASIS_LOCAL})</span>
      </span>
    );
  }
  const when = formatDate(iso);
  return (
    <span className="text-muted-foreground" title={when.utc}>
      {when.local}
    </span>
  );
}

export function FileFlags({ file, className }: { file: Pick<DiskFile, "flags" | "known" | "yara_rules" | "stream">; className?: string }) {
  const flags = visibleFlags(file.flags);
  return (
    <span className={cn("flex flex-wrap gap-1", className)}>
      {file.known ? (
        <Badge variant={file.known === "good" ? "outline" : "secondary"} className="text-[10px] font-normal" title={KNOWN_LABELS[file.known].hint}>
          {KNOWN_LABELS[file.known].label}
        </Badge>
      ) : null}
      {file.yara_rules.length > 0 ? (
        <Badge variant="secondary" className="text-[10px] font-normal" title={`YARA rules: ${file.yara_rules.join(", ")}`}>
          YARA ({file.yara_rules.length})
        </Badge>
      ) : null}
      {file.stream ? (
        <Badge variant="outline" className="text-[10px] font-normal" title="An NTFS alternate data stream">
          stream
        </Badge>
      ) : null}
      {flags.map((flag) => (
        <Badge key={flag} variant="outline" className="text-[10px] font-normal" title={FILE_FLAG_HINTS[flag] ?? flag}>
          {FILE_FLAG_LABELS[flag] ?? flag}
        </Badge>
      ))}
    </span>
  );
}

export function FileHeader() {
  return (
    <div role="row" className={cn(FILE_GRID, "h-9 text-xs font-medium text-muted-foreground")}>
      <span role="columnheader">Name</span>
      <span role="columnheader">Path</span>
      <span role="columnheader" className="text-right">
        Size
      </span>
      <span role="columnheader">Modified</span>
      <span role="columnheader">Type</span>
      <span role="columnheader">Flags</span>
      <span role="columnheader">sha256</span>
    </div>
  );
}

/** One file row (pure). The whole row is a button that opens the detail drawer. */
export function FileRow({ file, onOpen, selected }: { file: DiskFile; onOpen: (id: string) => void; selected?: boolean }) {
  const markers = pathMarkers(file);
  const name = file.stream ? `${file.name}:${file.stream}` : file.name;
  return (
    <div
      role="row"
      tabIndex={0}
      aria-selected={selected}
      className={cn(FILE_GRID, "h-10 cursor-pointer border-b text-sm hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none", selected && "bg-muted/40")}
      onClick={() => onOpen(file.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen(file.id);
        }
      }}
    >
      <span role="cell" className={cn("min-w-0", file.flags.includes("deleted") && "text-muted-foreground line-through decoration-muted-foreground/50")}>
        <InertText value={name} />
      </span>
      <span role="cell" className="flex min-w-0 items-center gap-1">
        <InertText value={file.path} mono className="min-w-0 flex-1" />
        {markers.length > 0 ? (
          <span className="shrink-0 text-xs text-amber-700 dark:text-amber-400" title={markers.join("; ")} aria-label={markers.join("; ")}>
            ⚠
          </span>
        ) : null}
      </span>
      <span role="cell" className="text-right tabular-nums">
        {file.size === null || file.size === undefined ? "—" : formatBytes(file.size)}
      </span>
      <span role="cell" className="min-w-0 truncate text-xs">
        <FileTime iso={file.mtime} basis={file.time_basis} />
      </span>
      <span role="cell" className="min-w-0 truncate text-xs text-muted-foreground">
        {FILE_TYPE_LABELS[file.type]}
        {file.magic ? <span title={inertText(file.magic)}> · {inertText(file.magic, 24)}</span> : null}
      </span>
      <span role="cell" className="min-w-0 overflow-hidden">
        <FileFlags file={file} className="max-h-8 overflow-hidden" />
      </span>
      <span role="cell" className="font-mono text-xs text-muted-foreground" title={file.sha256 ?? undefined}>
        {file.sha256 ? shortHash(file.sha256, 10) : "—"}
      </span>
    </div>
  );
}

