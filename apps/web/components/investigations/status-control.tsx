"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { STATUS_LABELS } from "@/lib/format";

type Status = Schemas["InvestigationStatus"];

/** Status select limited to the API's allowed transitions; archiving (terminal) is confirmed. */
export function StatusControl({
  status,
  allowed,
  pending,
  onChange,
}: {
  status: Status;
  allowed: Status[];
  pending: boolean;
  onChange: (next: Status) => void;
}) {
  const [confirmArchive, setConfirmArchive] = useState(false);
  return (
    <>
      <Select
        value={status}
        disabled={pending}
        onValueChange={(value) => {
          const next = value as Status;
          if (next === "archived") setConfirmArchive(true);
          else if (next !== status) onChange(next);
        }}
      >
        <SelectTrigger className="w-40" aria-label="Investigation status">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {[status, ...allowed].map((s) => (
            <SelectItem key={s} value={s}>
              {STATUS_LABELS[s]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Dialog open={confirmArchive} onOpenChange={setConfirmArchive}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Archive this investigation?</DialogTitle>
            <DialogDescription>
              Archived investigations are read-only: no new evidence, no edits, no status changes.
              This cannot be undone in M1.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmArchive(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                setConfirmArchive(false);
                onChange("archived");
              }}
            >
              Archive
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
