"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useId, useState } from "react";

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
import { Textarea } from "@/components/ui/textarea";
import { STATUS_REASON_MAX, checkStatusReason, needsStatusReason, statusActionLabel } from "@/lib/case";
import { STATUS_LABELS } from "@/lib/format";

type Status = Schemas["InvestigationStatus"];

/**
 * Status select limited to the API's allowed transitions. Closing, reopening and archiving
 * open a reason dialog (required, at most 500 characters); archiving is terminal and says so.
 */
export function StatusControl({
  status,
  allowed,
  pending,
  onChange,
}: {
  status: Status;
  allowed: Status[];
  pending: boolean;
  onChange: (next: Status, reason?: string) => void;
}) {
  const [target, setTarget] = useState<Status | null>(null);
  return (
    <>
      <Select
        value={status}
        disabled={pending}
        onValueChange={(value) => {
          const next = value as Status;
          if (next === status) return;
          if (needsStatusReason(status, next)) setTarget(next);
          else onChange(next);
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
      <StatusReasonDialog
        from={status}
        to={target}
        pending={pending}
        onCancel={() => setTarget(null)}
        onConfirm={(reason) => {
          const next = target;
          setTarget(null);
          if (next) onChange(next, reason);
        }}
      />
    </>
  );
}

/** The reason dialog of a status change (Radix dialog: focus is trapped while open). */
export function StatusReasonDialog({
  from,
  to,
  pending,
  onCancel,
  onConfirm,
}: {
  from: Status;
  to: Status | null;
  pending: boolean;
  onCancel: () => void;
  onConfirm: (reason: string) => void;
}) {
  const id = useId();
  const [text, setText] = useState("");
  const [touched, setTouched] = useState(false);
  const check = checkStatusReason(text);
  const action = to ? statusActionLabel(from, to) : "";
  return (
    <Dialog
      open={to !== null}
      onOpenChange={(open) => {
        if (!open) {
          setText("");
          setTouched(false);
          onCancel();
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{action} this investigation?</DialogTitle>
          <DialogDescription>
            {to === "archived"
              ? "Archived investigations are read-only: no new evidence, notes, edits or status changes. This cannot be undone."
              : `The status changes from ${STATUS_LABELS[from]} to ${to ? STATUS_LABELS[to] : ""}.`}{" "}
            The reason is kept in the status history and the case timeline.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            setTouched(true);
            if (check.ok) {
              setText("");
              setTouched(false);
              onConfirm(check.reason);
            }
          }}
        >
          <label htmlFor={id} className="text-sm font-medium">
            Reason (required)
          </label>
          <Textarea
            id={id}
            rows={4}
            required
            maxLength={STATUS_REASON_MAX}
            value={text}
            aria-invalid={touched && !check.ok}
            aria-describedby={`${id}-count`}
            onChange={(event) => setText(event.target.value)}
          />
          <p id={`${id}-count`} className="text-xs text-muted-foreground tabular-nums">
            {text.length} / {STATUS_REASON_MAX}
            {touched && !check.ok ? <span className="ml-2 text-destructive">{check.message}</span> : null}
          </p>
          <DialogFooter className="mt-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setText("");
                setTouched(false);
                onCancel();
              }}
            >
              Cancel
            </Button>
            <Button type="submit" variant={to === "archived" ? "destructive" : "default"} disabled={pending || !check.ok}>
              {action}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
