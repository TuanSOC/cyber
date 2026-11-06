"use client";

import { useId } from "react";

import { DISK_MAX_UPLOAD_BYTES_DEFAULT, DISK_UPLOAD_NOTICE } from "@/lib/disk";
import { formatBytes } from "@/lib/format";

/**
 * "Disk image (segment)" option of the evidence uploader (M9 phase 11, mounted once in
 * `evidence-uploader.tsx`). When `value` is true the next files are uploaded with `?kind=disk`
 * (phase 7), each file as its own segment, one after the other with its own progress (the
 * uploader's queue; no new upload protocol): restricted from the upload, never analyzed
 * automatically.
 */
export function DiskUploadOption({
  value,
  onChange,
  disabled,
}: {
  value: boolean;
  onChange: (disk: boolean) => void;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1 text-sm">
      <label htmlFor={id} className="flex items-center gap-2">
        <input
          id={id}
          type="checkbox"
          checked={value}
          disabled={disabled}
          aria-describedby={`${id}-hint`}
          onChange={(event) => onChange(event.target.checked)}
        />
        <span>Disk image (segment)</span>
      </label>
      <p id={`${id}-hint`} className="text-xs text-muted-foreground" data-testid="disk-upload-hint">
        {value ? (
          <>
            {DISK_UPLOAD_NOTICE} Up to {formatBytes(DISK_MAX_UPLOAD_BYTES_DEFAULT)} per segment by default. Select every
            segment (.E01, .E02 … or .001, .002 …) at once: they upload in turn.
          </>
        ) : (
          "Tick before choosing a disk image (raw / dd, split raw or EWF E01 segments) so it is restricted from the start."
        )}
      </p>
    </div>
  );
}
