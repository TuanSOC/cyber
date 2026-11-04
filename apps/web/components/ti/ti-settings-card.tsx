"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, unwrap } from "@/lib/api";
import { parseSuffixes, tiErrorMessage } from "@/lib/ti";
import { tiKeys, useTiSettings } from "@/lib/use-ti";

const MAX_SUFFIXES = 50;

/** Org-wide TI settings: domain suffixes that are never sent to any provider. */
export function TiSettingsCard({ orgId, canManage }: { orgId: string; canManage: boolean }) {
  const settings = useTiSettings(orgId);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Excluded domain suffixes</CardTitle>
        <CardDescription>
          Domains, URL hosts and email domains under these suffixes are never sent to any provider. Add your
          organization&apos;s own internal domains (for example corp.example.org) before enabling providers.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {settings.isPending ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : settings.isError ? (
          <p className="text-sm text-destructive">{tiErrorMessage(settings.error)}</p>
        ) : canManage ? (
          <SuffixForm
            key={settings.data.updated_at ?? "new"}
            orgId={orgId}
            initial={settings.data.excluded_suffixes}
          />
        ) : settings.data.excluded_suffixes.length === 0 ? (
          <p className="text-sm text-muted-foreground">No suffix is excluded.</p>
        ) : (
          <ul className="flex flex-wrap gap-1">
            {settings.data.excluded_suffixes.map((s) => (
              <li key={s} className="rounded border px-1.5 font-mono text-xs">
                {s}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function SuffixForm({ orgId, initial }: { orgId: string; initial: string[] }) {
  const queryClient = useQueryClient();
  const [text, setText] = useState(initial.join("\n"));
  const suffixes = parseSuffixes(text);
  const tooMany = suffixes.length > MAX_SUFFIXES;

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/api/v1/orgs/{org_id}/ti/settings", {
          params: { path: { org_id: orgId } },
          body: { excluded_suffixes: suffixes },
        }),
      ),
    onSuccess: async (out) => {
      queryClient.setQueryData(tiKeys.settings(orgId), out);
      toast.success("Excluded suffixes saved");
    },
    onError: (error) => toast.error(tiErrorMessage(error)),
  });

  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate();
      }}
    >
      <Label htmlFor="ti-suffixes">One suffix per line</Label>
      <Textarea
        id="ti-suffixes"
        rows={4}
        className="max-w-md font-mono text-xs"
        placeholder={"corp.example.org\ninternal.example.com"}
        value={text}
        onChange={(event) => setText(event.target.value)}
      />
      {tooMany && <span className="text-xs text-destructive">At most {MAX_SUFFIXES} suffixes.</span>}
      <Button type="submit" size="sm" className="self-start" disabled={save.isPending || tooMany}>
        Save suffixes
      </Button>
    </form>
  );
}
