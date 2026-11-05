"use client";

import { Download } from "lucide-react";
import { useId, useState } from "react";
import { toast } from "sonner";

import { ExportNotice } from "@/components/ioc-collections/ioc-parts";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { caseErrorMessage } from "@/lib/case";
import { EXPORT_FORMATS } from "@/lib/ioc-collections";
import type { Tlp } from "@/lib/tlp";
import { useExportCollection } from "@/lib/use-case";

/**
 * Export of a collection (CSV, JSON, STIX 2.1) through the API's attachment, saved under the
 * server's filename. Values are defanged unless an `evidence.write` holder asks for clear text.
 */
export function CollectionExportMenu({
  orgId,
  collectionId,
  name,
  tlp,
  canWrite,
}: {
  orgId: string;
  collectionId: string;
  name: string;
  tlp: Tlp;
  canWrite: boolean;
}) {
  const id = useId();
  const [clearText, setClearText] = useState(false);
  const exporter = useExportCollection(orgId);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-3">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" disabled={exporter.isPending}>
              <Download className="size-4" aria-hidden /> Export
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>{clearText && canWrite ? "Clear-text values" : "Defanged values"}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {EXPORT_FORMATS.map(([format, label]) => (
              <DropdownMenuItem
                key={format}
                onSelect={() =>
                  exporter.mutate(
                    { collectionId, name, format, clearText, canWrite },
                    {
                      onSuccess: (filename) => toast.success(`Downloaded ${filename}`),
                      onError: (error) => toast.error(caseErrorMessage(error)),
                    },
                  )
                }
              >
                {label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
        {canWrite ? (
          <label htmlFor={id} className="flex items-center gap-1.5 text-xs">
            <input id={id} type="checkbox" checked={clearText} onChange={(event) => setClearText(event.target.checked)} />
            Export clear-text values (not defanged)
          </label>
        ) : null}
      </div>
      <ExportNotice tlp={tlp} />
    </div>
  );
}
