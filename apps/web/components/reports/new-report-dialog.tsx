"use client";

import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { errorMessage } from "@/lib/api";
import { reportsHref } from "@/lib/report-format";
import { TITLE_MAX_CHARS, reportErrorText } from "@/lib/reports";
import { useCreateReport, useReportableCases } from "@/lib/use-reports";

/**
 * "New report": pick a case (unless given), a title; the TLP defaults to the case TLP and the
 * profile to internal (both editable in the builder). Opens the builder on success.
 */
export function NewReportDialog({
  orgId,
  investigationId,
  disabled = false,
}: {
  orgId: string;
  investigationId?: string;
  disabled?: boolean;
}) {
  const id = useId();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [caseId, setCaseId] = useState(investigationId ?? "");
  const [title, setTitle] = useState("");
  const cases = useReportableCases(orgId, open && !investigationId);
  const create = useCreateReport(orgId);
  const target = investigationId ?? caseId;
  const ready = Boolean(target) && title.trim().length > 0;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) create.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" disabled={disabled}>
          <Plus className="size-4" aria-hidden />
          New report
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New report</DialogTitle>
          <DialogDescription>
            A draft you can edit, preview and finalize into signed versions. Its TLP starts at the case TLP.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (!ready || create.isPending) return;
            create.mutate(
              {
                investigationId: target,
                body: { title: title.trim(), template: "incident_v1", profile: "internal", acknowledge_tlp_downgrade: false },
              },
              { onSuccess: (report) => router.push(reportsHref(orgId, report.id)) },
            );
          }}
        >
          {!investigationId ? (
            <div className="flex flex-col gap-1">
              <label htmlFor={`${id}-case`} className="text-sm font-medium">
                Case
              </label>
              <select
                id={`${id}-case`}
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                value={caseId}
                required
                onChange={(event) => setCaseId(event.target.value)}
              >
                <option value="">{cases.isLoading ? "Loading cases…" : "Choose a case…"}</option>
                {(cases.data ?? []).map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.case_ref} · {inv.title}
                  </option>
                ))}
              </select>
              {cases.isError ? <span className="text-xs text-destructive">{errorMessage(cases.error)}</span> : null}
            </div>
          ) : null}
          <div className="flex flex-col gap-1">
            <label htmlFor={`${id}-title`} className="text-sm font-medium">
              Title
            </label>
            <Input
              id={`${id}-title`}
              value={title}
              maxLength={TITLE_MAX_CHARS}
              required
              placeholder="For example: Beaconing from the finance workstation"
              onChange={(event) => setTitle(event.target.value)}
            />
          </div>
          {create.isError ? (
            <p role="alert" className="text-sm text-destructive">
              {reportErrorText(create.error) ?? errorMessage(create.error)}
            </p>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!ready || create.isPending}>
              {create.isPending ? "Creating…" : "Create draft"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
