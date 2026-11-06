"use client";

import { type ReactNode, type UIEvent, useCallback, useRef, useState } from "react";

import { windowRange } from "@/lib/disk";

/**
 * Windowed rendering of a long list (500 000 rows): fixed-height rows, only the visible slice
 * (plus overscan) is in the DOM; `onNearEnd` asks for the next page when the slice nears the
 * end of what is loaded. Rows are `role="row"` inside a `role="table"` grid of divs.
 */
export function WindowedRows<T>({
  items,
  rowHeight,
  height,
  header,
  renderRow,
  onNearEnd,
  label,
  footer,
}: {
  items: readonly T[];
  rowHeight: number;
  /** Viewport height in px. */
  height: number;
  header: ReactNode;
  renderRow: (item: T, index: number) => ReactNode;
  onNearEnd?: () => void;
  label: string;
  footer?: ReactNode;
}) {
  const [scrollTop, setScrollTop] = useState(0);
  const asked = useRef(-1);
  const { start, end } = windowRange(scrollTop, height, rowHeight, items.length);
  const onScroll = useCallback(
    (event: UIEvent<HTMLDivElement>) => {
      const top = event.currentTarget.scrollTop;
      setScrollTop(top);
      const range = windowRange(top, height, rowHeight, items.length);
      if (onNearEnd && range.end >= items.length - 20 && asked.current !== items.length) {
        asked.current = items.length;
        onNearEnd();
      }
    },
    [height, rowHeight, items.length, onNearEnd],
  );
  return (
    <div role="table" aria-label={label} aria-rowcount={items.length + 1} className="min-w-0 rounded-lg border text-sm">
      <div role="rowgroup" className="border-b bg-muted/30">
        {header}
      </div>
      <div role="rowgroup" className="overflow-y-auto" style={{ height }} onScroll={onScroll} tabIndex={0}>
        <div style={{ height: items.length * rowHeight, position: "relative" }}>
          {items.slice(start, end).map((item, offset) => {
            const index = start + offset;
            return (
              <div
                key={index}
                style={{ position: "absolute", top: index * rowHeight, left: 0, right: 0, height: rowHeight }}
                aria-rowindex={index + 2}
              >
                {renderRow(item, index)}
              </div>
            );
          })}
        </div>
      </div>
      {footer ? <div className="border-t p-2 text-xs text-muted-foreground">{footer}</div> : null}
    </div>
  );
}
