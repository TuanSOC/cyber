"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Sparkles } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { PolicyBlocked } from "@/components/ai/policy-blocked";
import { NoProvidersNotice, ProviderPicker } from "@/components/ti/provider-picker";
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
import { api, unwrap } from "@/lib/api";
import { useOrg } from "@/lib/org-context";
import { type ProviderName, enabledProviders, skipReasonText, tiErrorMessage } from "@/lib/ti";
import { tiKeys, useIntegrations } from "@/lib/use-ti";

/**
 * "Enrich IOCs" for one analysis job: pick among the enabled providers, then start a run.
 * Only eligible values are planned by the API; the report explains the rest.
 */
export function EnrichButton({ orgId, jobId, busy }: { orgId: string; jobId: string; busy: boolean }) {
  const { can } = useOrg();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const integrations = useIntegrations(orgId);
  const providers = enabledProviders(integrations.data?.items);
  // null = every enabled provider (the default until the user unticks one).
  const [picked, setPicked] = useState<ProviderName[] | null>(null);
  const selected = (picked ?? providers.map((p) => p.name)).filter((name) => providers.some((p) => p.name === name));

  const start = useMutation({
    mutationFn: async (chosen: ProviderName[]) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/analyses/{job_id}/enrichments", {
          params: { path: { org_id: orgId, job_id: jobId } },
          body: { providers: chosen },
        }),
      ),
    onSuccess: async (out) => {
      await queryClient.invalidateQueries({ queryKey: tiKeys.runs(orgId) });
      if (!out.run) {
        const reasons = Object.keys((out.summary.skipped as Record<string, number> | undefined) ?? {});
        toast.info(
          reasons.length
            ? `Nothing was sent: ${reasons.map((r) => skipReasonText(r)).join("; ")}.`
            : "Nothing eligible to look up for the selected providers.",
        );
      } else if (out.deduplicated) {
        toast.info("An enrichment run for this analysis is already in progress.");
      } else {
        toast.success(`Enrichment started: ${out.items} lookups planned.`);
      }
      setOpen(false);
      setPicked(null);
    },
    onError: (error) => toast.error(tiErrorMessage(error)),
  });

  if (!can("evidence.write")) return null;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" disabled={busy}>
          <Sparkles className="size-4" aria-hidden /> Enrich IOCs
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Enrich IOCs</DialogTitle>
          <DialogDescription>
            The selected providers receive this analysis&apos;s eligible indicators (at most 200, sample hashes first).
            Private IPs, internal names, URL query strings, emails (except MISP), file paths and registry keys are
            never sent. Results are attributed to each provider and cached per organization.
          </DialogDescription>
        </DialogHeader>
        {integrations.isPending ? (
          <p className="text-sm text-muted-foreground">Loading providers…</p>
        ) : providers.length === 0 ? (
          <NoProvidersNotice orgId={orgId} canManage={can("integrations.manage")} />
        ) : (
          <ProviderPicker providers={providers} selected={selected} onChange={setPicked} idPrefix={`enrich-${jobId}`} />
        )}
        {start.isError && <PolicyBlocked orgId={orgId} error={start.error} jobId={jobId} what="This threat-intel enrichment" />}
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            disabled={start.isPending || selected.length === 0 || providers.length === 0}
            onClick={() => start.mutate(selected)}
          >
            Start lookup
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
