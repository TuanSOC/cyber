"use client";

/**
 * "This is a disk image (segment)" option of the evidence uploader (M9 slot, mounted once in
 * `evidence-uploader.tsx`; phase 11 owns the body). When `value` is true the next files are
 * uploaded with `?kind=disk` (phase 7): restricted from the upload, never analyzed
 * automatically. Phase 1 renders nothing (the API does not accept `kind=disk` yet).
 */
export function DiskUploadOption(_props: {
  value: boolean;
  onChange: (disk: boolean) => void;
  disabled?: boolean;
}) {
  return null;
}
