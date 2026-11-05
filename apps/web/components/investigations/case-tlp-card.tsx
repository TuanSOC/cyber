"use client";

import { useState } from "react";

import { TlpBadge } from "@/components/tlp/tlp-badge";
import { TlpSelect } from "@/components/tlp/tlp-select";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { type Tlp, isDowngrade } from "@/lib/tlp";

/**
 * TLP of the case. Raising it needs `investigation.write`; lowering it needs `org.update` and
 * the acknowledgement (the shared `TlpSelect` enforces the checkbox; the API re-checks).
 */
export function CaseTlpCard({
  tlp,
  canWrite,
  canDowngrade,
  pending,
  onSave,
}: {
  tlp: Tlp;
  canWrite: boolean;
  canDowngrade: boolean;
  pending: boolean;
  onSave: (tlp: Tlp, acknowledgeDowngrade: boolean) => void;
}) {
  const [draft, setDraft] = useState<{ tlp: Tlp; ack: boolean } | null>(null);
  const value = draft?.tlp ?? tlp;
  const downgrade = isDowngrade(value, tlp);
  const ready = value !== tlp && (!downgrade || (canDowngrade && draft?.ack === true));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Traffic Light Protocol</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <TlpBadge tlp={tlp} withDefinition />
        {canWrite ? (
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (!ready) return;
              onSave(value, downgrade);
              setDraft(null);
            }}
          >
            <TlpSelect
              value={value}
              current={tlp}
              canDowngrade={canDowngrade}
              disabled={pending}
              label="Change the case TLP"
              onChange={(next, ack) => setDraft(next === tlp ? null : { tlp: next, ack })}
            />
            {value === "red" && tlp !== "red" ? (
              <p className="text-xs text-muted-foreground">
                TLP:RED also stops every AI run and threat-intel enrichment of this case.
              </p>
            ) : null}
            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={!ready || pending}>
                Save TLP
              </Button>
              {draft ? (
                <Button type="button" size="sm" variant="outline" onClick={() => setDraft(null)}>
                  Cancel
                </Button>
              ) : null}
            </div>
          </form>
        ) : (
          <p className="text-xs text-muted-foreground">Your role cannot change the TLP of this case.</p>
        )}
        <p className="text-[11px] text-muted-foreground">
          Reports default to the case TLP and cannot be less restrictive without an admin&apos;s acknowledgement.
        </p>
      </CardContent>
    </Card>
  );
}
