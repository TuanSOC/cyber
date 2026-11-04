"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { NoProvidersNotice, ProviderPicker } from "@/components/ti/provider-picker";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, unwrap } from "@/lib/api";
import { useOrg } from "@/lib/org-context";
import {
  MAX_LOOKUP_VALUES,
  type ProviderName,
  type ValueReport,
  enabledProviders,
  noteText,
  parseLookupInput,
  providerLabel,
  providerSkipText,
  refang,
  skipReasonText,
  tiErrorMessage,
  tiIocTypeLabel,
} from "@/lib/ti";
import { tiKeys, useIntegrations } from "@/lib/use-ti";

export type LookupOutcome = { runId: string | null; values: string[]; report: ValueReport[] };

/** Manual lookup: up to 20 values (one per line), sent only to the chosen enabled providers. */
export function LookupForm({ orgId, onDone }: { orgId: string; onDone: (outcome: LookupOutcome) => void }) {
  const { can } = useOrg();
  const queryClient = useQueryClient();
  const integrations = useIntegrations(orgId);
  const providers = enabledProviders(integrations.data?.items);
  const [text, setText] = useState("");
  const [picked, setPicked] = useState<ProviderName[] | null>(null);
  const selected = (picked ?? providers.map((p) => p.name)).filter((name) => providers.some((p) => p.name === name));
  const parsed = parseLookupInput(text);
  const preview = parsed.values.map(refang);

  const lookup = useMutation({
    mutationFn: async ({ values, chosen }: { values: string[]; chosen: ProviderName[] }) =>
      unwrap(
        await api.POST("/api/v1/orgs/{org_id}/ti/lookups", {
          params: { path: { org_id: orgId } },
          body: { values: values.map((value) => ({ value })), providers: chosen },
        }),
      ),
    onSuccess: async (out, { values }) => {
      await queryClient.invalidateQueries({ queryKey: tiKeys.runs(orgId) });
      if (!out.run) toast.info("Nothing was sent: no value is eligible for the selected providers.");
      onDone({ runId: out.run?.id ?? null, values, report: out.report });
    },
    onError: (error) => toast.error(tiErrorMessage(error)),
  });

  if (!can("evidence.write")) {
    return <p className="text-sm text-muted-foreground">Analysts, admins and owners can run lookups.</p>;
  }

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (parsed.error || parsed.values.length === 0 || selected.length === 0) return;
        lookup.mutate({ values: parsed.values, chosen: selected });
      }}
    >
      <Label htmlFor="ti-lookup-values">Indicators (one per line, at most {MAX_LOOKUP_VALUES})</Label>
      <Textarea
        id="ti-lookup-values"
        rows={6}
        className="font-mono text-xs"
        placeholder={"203.0.113.7\nexample[.]net\nhxxps://example.org/path\n44d88612fea8a8f36de82e1278abb02f"}
        spellCheck={false}
        value={text}
        onChange={(event) => setText(event.target.value)}
      />
      {parsed.error ? (
        <span className="text-xs text-destructive">{parsed.error}</span>
      ) : (
        preview.length > 0 && (
          <p className="text-xs text-muted-foreground" title={preview.join("\n")}>
            {preview.length} {preview.length === 1 ? "value" : "values"}, refanged for display:{" "}
            <span className="font-mono break-all">{preview.slice(0, 5).join(", ")}</span>
            {preview.length > 5 ? ", …" : ""}
          </p>
        )
      )}
      {integrations.isPending ? (
        <p className="text-sm text-muted-foreground">Loading providers…</p>
      ) : providers.length === 0 ? (
        <NoProvidersNotice orgId={orgId} canManage={can("integrations.manage")} />
      ) : (
        <ProviderPicker providers={providers} selected={selected} onChange={setPicked} idPrefix="lookup" />
      )}
      <Button
        type="submit"
        className="self-start"
        disabled={
          lookup.isPending || Boolean(parsed.error) || parsed.values.length === 0 || selected.length === 0
        }
      >
        <Search className="size-4" aria-hidden /> Look up
      </Button>
    </form>
  );
}

/** How each value was normalized and who receives it (eligible / skipped / query removed). */
export function NormalizationReport({ outcome }: { outcome: LookupOutcome }) {
  return (
    <div className="min-w-0 overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th className="px-3 py-2 font-medium">Entered</th>
            <th className="px-3 py-2 font-medium">Looked up as</th>
            <th className="px-3 py-2 font-medium">Type</th>
            <th className="px-3 py-2 font-medium">Sent to</th>
          </tr>
        </thead>
        <tbody>
          {outcome.report.map((r) => {
            const entered = outcome.values[r.index] ?? "";
            const skips = Object.entries(r.provider_skips);
            return (
              <tr key={r.index} className="border-b align-top last:border-0">
                <td className="max-w-64 px-3 py-2">
                  <span className="block truncate font-mono text-xs" title={entered}>
                    {entered}
                  </span>
                </td>
                <td className="max-w-80 px-3 py-2">
                  <span className="block truncate font-mono text-xs" title={r.value_norm ?? ""}>
                    {r.value_norm ?? "—"}
                  </span>
                  {r.notes.length > 0 && (
                    <span className="text-[11px] text-muted-foreground">{r.notes.map(noteText).join(" · ")}</span>
                  )}
                </td>
                <td className="px-3 py-2 text-xs">{tiIocTypeLabel(r.ioc_type)}</td>
                <td className="px-3 py-2 text-xs">
                  {r.skipped ? (
                    <span className="text-muted-foreground">{skipReasonText(r.skipped)}</span>
                  ) : (
                    <span>{r.providers.map(providerLabel).join(", ") || "—"}</span>
                  )}
                  {skips.length > 0 && !r.skipped && (
                    <span className="block text-[11px] text-muted-foreground">
                      not sent to{" "}
                      {skips.map(([provider, reason]) => `${providerLabel(provider)} (${providerSkipText(reason)})`).join(", ")}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
