"use client";

/**
 * "This is a memory image" option of the evidence uploader (M8 phase 1 slot, mounted once in
 * `evidence-uploader.tsx`; phase 9 implements the control and its TLP:RED notice). When `value`
 * is true the next files are uploaded with `?kind=memory` (their own size limit, restricted
 * from the upload, never analyzed automatically; RT3). Renders nothing until phase 9.
 */
export function MemoryUploadOption(props: {
  value: boolean;
  onChange: (memory: boolean) => void;
  disabled?: boolean;
}): null {
  void props;
  return null;
}
