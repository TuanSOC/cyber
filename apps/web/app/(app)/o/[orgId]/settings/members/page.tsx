"use client";

import type { Schemas } from "@cyberlab/contracts";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";

import { ConfirmButton } from "@/components/confirm-button";
import { InvitationsCard } from "@/components/members/invitations-card";
import { InviteDialog } from "@/components/members/invite-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, type MemberRole, errorMessage, unwrap } from "@/lib/api";
import { useOrg } from "@/lib/org-context";
import { ROLE_LABELS, assignableRoles } from "@/lib/roles";
import { useMe } from "@/lib/use-me";

type Member = Schemas["MemberOut"];

export default function MembersPage() {
  const { orgId, role, can } = useOrg();
  const me = useMe();
  const queryClient = useQueryClient();
  const queryKey = ["org", orgId, "members"];
  const manage = can("members.manage");

  const members = useQuery({
    queryKey,
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/members", {
          params: { path: { org_id: orgId }, query: { limit: 100 } },
        }),
      ),
  });

  const onDone = (message: string) => async () => {
    await queryClient.invalidateQueries({ queryKey });
    toast.success(message);
  };
  const onError = (error: Error) => toast.error(errorMessage(error));

  const changeRole = useMutation({
    mutationFn: async ({ member, next }: { member: Member; next: MemberRole }) =>
      unwrap(
        await api.PATCH("/api/v1/orgs/{org_id}/members/{member_id}", {
          params: { path: { org_id: orgId, member_id: member.id } },
          body: { role: next },
        }),
      ),
    onSuccess: onDone("Role updated"),
    onError,
  });

  const remove = useMutation({
    mutationFn: async (member: Member) => {
      const result = await api.DELETE("/api/v1/orgs/{org_id}/members/{member_id}", {
        params: { path: { org_id: orgId, member_id: member.id } },
      });
      if (!result.response.ok) unwrap({ ...result, data: undefined });
    },
    onSuccess: onDone("Member removed"),
    onError,
  });

  const editable = (member: Member) =>
    manage && member.user_id !== me.data?.user.id && (role === "owner" || member.role !== "owner");

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {members.data
            ? `${members.data.total} member${members.data.total === 1 ? "" : "s"}`
            : members.isError
              ? ""
              : "Loading members…"}
        </p>
        {/* M11 slot (phase 11): members join through invitations. */}
        {manage && <InviteDialog orgId={orgId} roles={assignableRoles(role)} />}
      </div>
      {members.isError && (
        <div className="flex items-center gap-3 rounded-lg border border-destructive/40 p-3 text-sm">
          <span className="text-destructive">{errorMessage(members.error)}</span>
          <Button variant="outline" size="sm" onClick={() => void members.refetch()}>
            Retry
          </Button>
        </div>
      )}
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead className="w-44">Role</TableHead>
              {manage && <TableHead className="w-16" />}
            </TableRow>
          </TableHeader>
          <TableBody>
            {members.data?.items.map((member) => (
              <TableRow key={member.id}>
                <TableCell className="max-w-48 truncate" title={member.display_name}>
                  {member.display_name}
                  {member.user_id === me.data?.user.id && (
                    <Badge variant="outline" className="ml-2">
                      you
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="max-w-64 truncate" title={member.email}>
                  {member.email}
                </TableCell>
                <TableCell>
                  {editable(member) ? (
                    <Select
                      value={member.role}
                      disabled={changeRole.isPending || remove.isPending}
                      onValueChange={(next) =>
                        changeRole.mutate({ member, next: next as MemberRole })
                      }
                    >
                      <SelectTrigger size="sm" aria-label={`Role of ${member.display_name}`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {assignableRoles(role).map((r) => (
                          <SelectItem key={r} value={r}>
                            {ROLE_LABELS[r]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Badge variant="secondary">{ROLE_LABELS[member.role]}</Badge>
                  )}
                </TableCell>
                {manage && (
                  <TableCell>
                    {editable(member) && (
                      <ConfirmButton
                        variant="ghost"
                        size="icon"
                        aria-label={`Remove ${member.display_name}`}
                        title={`Remove ${member.display_name}?`}
                        description="They lose access to this organization immediately."
                        confirmLabel="Remove"
                        pending={remove.isPending}
                        onConfirm={() => remove.mutate(member)}
                      >
                        <Trash2 className="size-4" />
                      </ConfirmButton>
                    )}
                  </TableCell>
                )}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {/* M11 slot (phase 11): pending invitations, resend and revoke. */}
      <InvitationsCard orgId={orgId} />
    </div>
  );
}
