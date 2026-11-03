import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";

export const PAGE_SIZE = 25;

/** Offset pagination for the API's {items, total} envelope. */
export function Pager({
  offset,
  total,
  pageSize = PAGE_SIZE,
  onChange,
}: {
  offset: number;
  total: number;
  pageSize?: number;
  onChange: (offset: number) => void;
}) {
  if (total <= pageSize) return null;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + pageSize, total);
  return (
    <div className="flex items-center justify-end gap-2 text-sm text-muted-foreground">
      <span>
        {from}–{to} of {total}
      </span>
      <Button
        variant="outline"
        size="icon"
        aria-label="Previous page"
        disabled={offset === 0}
        onClick={() => onChange(Math.max(0, offset - pageSize))}
      >
        <ChevronLeft className="size-4" />
      </Button>
      <Button
        variant="outline"
        size="icon"
        aria-label="Next page"
        disabled={to >= total}
        onClick={() => onChange(offset + pageSize)}
      >
        <ChevronRight className="size-4" />
      </Button>
    </div>
  );
}
