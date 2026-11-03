"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { shortHash } from "@/lib/format";

export function HashValue({ value, short = false }: { value: string; short?: boolean }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable (insecure context / permission): the value stays selectable
    }
  }

  return (
    <span className="inline-flex max-w-full items-center gap-1">
      <code className="min-w-0 font-mono text-xs break-all select-all" title={value}>
        {short ? shortHash(value) : value}
      </code>
      <Button
        variant="ghost"
        size="icon"
        className="size-6 shrink-0"
        aria-label="Copy hash"
        onClick={copy}
      >
        {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      </Button>
      <span className="sr-only" aria-live="polite">
        {copied ? "Copied" : ""}
      </span>
    </span>
  );
}
