"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Building2, Check, ChevronsUpDown, Plus } from "lucide-react";
import { useRouter } from "next/navigation";
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
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { api, errorMessage, unwrap } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { ROLE_LABELS } from "@/lib/roles";
import { ME_QUERY_KEY, useMe } from "@/lib/use-me";

export function OrgSwitcher() {
  const { orgId, orgName } = useOrg();
  const me = useMe();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");

  const create = useMutation({
    mutationFn: async () => unwrap(await api.POST("/api/v1/orgs", { body: { name } })),
    onSuccess: async (org) => {
      await queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY });
      setCreating(false);
      setName("");
      toast.success(`Created ${org.name}`);
      router.push(orgPath(org.id));
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" tooltip={orgName}>
              <Building2 aria-hidden />
              <span className="truncate font-medium">{orgName}</span>
              <ChevronsUpDown className="ml-auto size-4" aria-hidden />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-64" align="start">
            <DropdownMenuLabel>Organizations</DropdownMenuLabel>
            {me.data?.memberships.map((m) => (
              <DropdownMenuItem
                key={m.organization_id}
                onSelect={() => router.push(orgPath(m.organization_id))}
              >
                <span className="truncate">{m.organization_name}</span>
                <span className="ml-auto text-xs text-muted-foreground">{ROLE_LABELS[m.role]}</span>
                {m.organization_id === orgId && <Check className="size-4" aria-hidden />}
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden /> New organization
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New organization</DialogTitle>
            <DialogDescription>You become its owner.</DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              create.mutate();
            }}
          >
            <Label htmlFor="org-name">Name</Label>
            <Input
              id="org-name"
              value={name}
              minLength={2}
              maxLength={120}
              required
              onChange={(event) => setName(event.target.value)}
            />
            <DialogFooter className="mt-2">
              <Button type="submit" disabled={create.isPending || name.trim().length < 2}>
                Create
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </SidebarMenu>
  );
}
