"use client";

import type { Schemas } from "@cyberlab/contracts";
import { Pencil } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

type Investigation = Schemas["InvestigationOut"];
type Severity = Schemas["Severity"];
export type InvestigationEdit = { title?: string; severity?: Severity; description?: string };

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export function EditInvestigationDialog({
  investigation,
  pending,
  onSave,
}: {
  investigation: Investigation;
  pending: boolean;
  onSave: (changes: InvestigationEdit) => Promise<unknown>;
}) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState(investigation.title);
  const [severity, setSeverity] = useState<Severity>(investigation.severity);
  const [description, setDescription] = useState(investigation.description);

  function reset(nextOpen: boolean) {
    if (nextOpen) {
      setTitle(investigation.title);
      setSeverity(investigation.severity);
      setDescription(investigation.description);
    }
    setOpen(nextOpen);
  }

  async function save() {
    const changes: InvestigationEdit = {};
    if (title.trim() !== investigation.title) changes.title = title.trim();
    if (severity !== investigation.severity) changes.severity = severity;
    if (description !== investigation.description) changes.description = description;
    if (Object.keys(changes).length > 0) await onSave(changes);
    setOpen(false);
  }

  return (
    <Dialog open={open} onOpenChange={reset}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Pencil className="size-4" aria-hidden /> Edit
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit {investigation.case_ref}</DialogTitle>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          <Label htmlFor="edit-title">Title</Label>
          <Input id="edit-title" required minLength={3} maxLength={200} value={title}
            onChange={(event) => setTitle(event.target.value)} />
          <Label htmlFor="edit-severity">Severity</Label>
          <Select value={severity} onValueChange={(value) => setSeverity(value as Severity)}>
            <SelectTrigger id="edit-severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s} className="capitalize">
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Label htmlFor="edit-description">Description</Label>
          <Textarea id="edit-description" rows={5} maxLength={10_000} value={description}
            onChange={(event) => setDescription(event.target.value)} />
          <DialogFooter className="mt-2">
            <Button type="submit" disabled={pending || title.trim().length < 3}>
              Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
