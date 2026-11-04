"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, errorMessage, unwrap } from "@/lib/api";
import { useOrg } from "@/lib/org-context";
import { ME_QUERY_KEY } from "@/lib/use-me";

import { StorageCard } from "./storage-card";

export default function OrganizationSettingsPage() {
  const { orgId, orgName, can } = useOrg();
  const queryClient = useQueryClient();
  const [name, setName] = useState(orgName);
  const editable = can("org.update");

  const rename = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/api/v1/orgs/{org_id}", {
          params: { path: { org_id: orgId } },
          body: { name },
        }),
      ),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY });
      toast.success("Organization renamed");
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  return (
    <div className="flex flex-col gap-6">
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle>Organization</CardTitle>
          <CardDescription>
            {editable ? "Rename your organization." : "Only owners and admins can change these settings."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              rename.mutate();
            }}
          >
            <Label htmlFor="org-name">Name</Label>
            <Input
              id="org-name"
              value={name}
              disabled={!editable}
              minLength={2}
              maxLength={120}
              onChange={(event) => setName(event.target.value)}
            />
            {editable && (
              <Button
                type="submit"
                className="self-start"
                disabled={rename.isPending || name.trim().length < 2 || name.trim() === orgName}
              >
                Save
              </Button>
            )}
          </form>
        </CardContent>
      </Card>
      <StorageCard orgId={orgId} />
    </div>
  );
}
