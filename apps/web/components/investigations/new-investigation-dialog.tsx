"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

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
import { api, errorMessage, unwrap } from "@/lib/api";
import { orgPath } from "@/lib/nav";

type Severity = Schemas["Severity"];
const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export function NewInvestigationDialog({ orgId }: { orgId: string }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");

  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/investigations", {
          params: { path: { org_id: orgId } },
          body: { title, description, severity },
        }),
      ),
    onSuccess: async (investigation) => {
      await queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigations"] });
      toast.success(`${investigation.case_ref} created`);
      setOpen(false);
      setTitle("");
      setDescription("");
      setSeverity("medium");
      router.push(orgPath(orgId, `investigations/${investigation.id}`));
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="size-4" aria-hidden /> New investigation
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New investigation</DialogTitle>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate();
          }}
        >
          <Label htmlFor="inv-title">Title</Label>
          <Input
            id="inv-title"
            required
            minLength={3}
            maxLength={200}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
          <Label htmlFor="inv-severity">Severity</Label>
          <Select value={severity} onValueChange={(value) => setSeverity(value as Severity)}>
            <SelectTrigger id="inv-severity">
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
          <Label htmlFor="inv-description">Description</Label>
          <Textarea
            id="inv-description"
            rows={4}
            maxLength={10_000}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
          <DialogFooter className="mt-2">
            <Button type="submit" disabled={create.isPending || title.trim().length < 3}>
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
