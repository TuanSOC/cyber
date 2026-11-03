"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, type MemberRole, errorMessage, unwrap } from "@/lib/api";
import { ROLE_LABELS } from "@/lib/roles";

export function AddMemberDialog({ orgId, roles }: { orgId: string; roles: MemberRole[] }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<MemberRole>("analyst");

  const add = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/members", {
          params: { path: { org_id: orgId } },
          body: { email, role },
        }),
      ),
    onSuccess: async (member) => {
      await queryClient.invalidateQueries({ queryKey: ["org", orgId, "members"] });
      toast.success(`Added ${member.email}`);
      setOpen(false);
      setEmail("");
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <UserPlus className="size-4" aria-hidden /> Add member
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add member</DialogTitle>
          <DialogDescription>
            The person must already have a CyberLab account. They get access immediately.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            add.mutate();
          }}
        >
          <Label htmlFor="member-email">Email</Label>
          <Input
            id="member-email"
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <Label htmlFor="member-role">Role</Label>
          <Select value={role} onValueChange={(value) => setRole(value as MemberRole)}>
            <SelectTrigger id="member-role">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {roles.map((r) => (
                <SelectItem key={r} value={r}>
                  {ROLE_LABELS[r]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <DialogFooter className="mt-2">
            <Button type="submit" disabled={add.isPending || !email}>
              Add
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
