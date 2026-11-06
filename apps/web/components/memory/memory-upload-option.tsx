"use client";

import { useId } from "react";

import { formatBytes } from "@/lib/format";
import { MEMORY_MAX_BYTES_DEFAULT, UPLOAD_NOTICE } from "@/lib/memory";

/**
 * "This is a memory image" option of the evidence uploader (M8 phase 9, mounted once in
 * `evidence-uploader.tsx`). When `value` is true the next files are uploaded with `?kind=memory`:
 * their own size limit, restricted from the upload (TLP:RED material) and never analyzed
 * automatically (RT3).
 */
export function MemoryUploadOption({
  value,
  onChange,
  disabled,
}: {
  value: boolean;
  onChange: (memory: boolean) => void;
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
        <span>This is a memory image</span>
      </label>
      <p id={`${id}-hint`} className="text-xs text-muted-foreground">
        {value ? (
          <>
            {UPLOAD_NOTICE} Up to {formatBytes(MEMORY_MAX_BYTES_DEFAULT)} by default (the platform operator may set
            another limit).
          </>
        ) : (
          "Tick before choosing a RAM capture (raw, LiME, AVML, ELF core, .vmem, crash dump) so it is restricted from the start."
        )}
      </p>
    </div>
  );
}
