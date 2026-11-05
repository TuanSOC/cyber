"use client";

import { ShieldOff } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ShareToggles } from "@/components/investigations/share-policy-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { type Evidence, caseErrorMessage, evidenceExclusionBadges, sharePolicyLine } from "@/lib/case";
import { useOrg } from "@/lib/org-context";
import { useEvidenceSharePolicy, usePutEvidenceSharePolicy } from "@/lib/use-case";

/** "No AI" / "No TI" badges of an excluded evidence item (text, never colour alone). */
export function EvidenceExclusionBadges({ evidence }: { evidence: Pick<Evidence, "ai_excluded" | "ti_excluded"> }) {
  const badges = evidenceExclusionBadges(evidence);
  if (badges.length === 0) return null;
  return (
    <>
      {badges.map((label) => (
        <Badge key={label} variant="outline" className="ml-2 gap-1" title={`Share policy: ${label}`}>
          <ShieldOff className="size-3" aria-hidden />
          {label}
        </Badge>
      ))}
    </>
  );
}

/**
 * The share-policy toggles of one evidence item, with its effective policy (the case flags and
 * TLP:RED apply on top). Turning a flag on needs `evidence.write`, off `integrations.manage`.
 */
export function EvidenceSharePolicyControl({
  orgId,
  evidenceId,
  investigationId,
  tlpRed,
  readOnly,
}: {
  orgId: string;
  evidenceId: string;
  investigationId?: string;
  tlpRed: boolean;
  readOnly: boolean;
}) {
  const { can } = useOrg();
  const policy = useEvidenceSharePolicy(orgId, evidenceId);
  const put = usePutEvidenceSharePolicy(orgId, evidenceId, investigationId);
  if (policy.isError) {
    return (
      <p className="text-sm text-muted-foreground" role="alert">
        {caseErrorMessage(policy.error)}
      </p>
    );
  }
  if (!policy.data) return <p className="text-sm text-muted-foreground">Loading the share policy…</p>;
  const data = policy.data;
  return (
    <div className="flex flex-col gap-3">
      <ShareToggles
        flags={{ ai_excluded: data.ai_excluded, ti_excluded: data.ti_excluded }}
        tlpRed={tlpRed}
        canTurnOn={can("evidence.write")}
        canTurnOff={can("integrations.manage")}
        readOnly={readOnly}
        pending={put.isPending}
        onChange={(next) =>
          put.mutate(next, {
            onSuccess: () => toast.success("Share policy updated"),
            onError: (error) => toast.error(caseErrorMessage(error)),
          })
        }
      />
      <p className="rounded-md border bg-muted/40 px-3 py-2 text-xs" role="status">
        Effective: {sharePolicyLine(data.effective)}
      </p>
    </div>
  );
}

/** Card on the evidence page. */
export function EvidenceSharePolicyCard(props: Parameters<typeof EvidenceSharePolicyControl>[0]) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Share policy</CardTitle>
      </CardHeader>
      <CardContent>
        <EvidenceSharePolicyControl {...props} />
      </CardContent>
    </Card>
  );
}

/** Row action of the case evidence table: the same control in a dialog. */
export function EvidenceSharePolicyButton(
  props: Parameters<typeof EvidenceSharePolicyControl>[0] & { filename: string },
) {
  const [open, setOpen] = useState(false);
  const { filename, ...rest } = props;
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="xs" aria-label={`Share policy of ${filename}`}>
          Share policy
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Share policy</DialogTitle>
          <DialogDescription className="break-all">{filename}</DialogDescription>
        </DialogHeader>
        {open ? <EvidenceSharePolicyControl {...rest} /> : null}
      </DialogContent>
    </Dialog>
  );
}
