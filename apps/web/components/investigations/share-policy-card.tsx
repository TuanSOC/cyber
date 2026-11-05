"use client";

import { useId } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  SHARE_FLAG_LABELS,
  SHARE_POLICY_ANCHOR,
  type ShareFlag,
  type SharePolicy,
  shareToggleState,
  sharePolicyLine,
} from "@/lib/case";

export type ShareFlags = { ai_excluded: boolean; ti_excluded: boolean };

const FLAG_FIELD: Record<ShareFlag, keyof ShareFlags> = { ai: "ai_excluded", ti: "ti_excluded" };

const FLAG_HELP: Record<ShareFlag, string> = {
  ai: "AI runs, context previews and incident summaries that would include it are refused; in-flight runs stop before the provider call.",
  ti: "Threat-intel enrichments of its analyses are refused. Manual lookups on the Intel page are not case-scoped and cannot be checked.",
};

/**
 * The two exclusion toggles with the rules of the API: TLP:RED forces both on; turning one on
 * needs the write permission; turning one off needs `integrations.manage`. The reason a toggle
 * is disabled is always shown next to it.
 */
export function ShareToggles({
  flags,
  tlpRed,
  canTurnOn,
  canTurnOff,
  readOnly = false,
  pending = false,
  onChange,
}: {
  flags: ShareFlags;
  tlpRed: boolean;
  canTurnOn: boolean;
  canTurnOff: boolean;
  readOnly?: boolean;
  pending?: boolean;
  onChange: (next: ShareFlags) => void;
}) {
  const id = useId();
  return (
    <ul className="flex flex-col gap-3">
      {(["ai", "ti"] as const).map((flag) => {
        const field = FLAG_FIELD[flag];
        const state = shareToggleState({ flag: flags[field], tlpRed, canTurnOn, canTurnOff, readOnly });
        const inputId = `${id}-${flag}`;
        return (
          <li key={flag} className="flex items-start gap-3">
            <input
              id={inputId}
              type="checkbox"
              role="switch"
              className="mt-1 size-4"
              checked={state.checked}
              disabled={state.disabled || pending}
              aria-checked={state.checked}
              aria-describedby={`${inputId}-help`}
              onChange={(event) => onChange({ ...flags, [field]: event.target.checked })}
            />
            <div className="flex flex-col gap-0.5">
              <label htmlFor={inputId} className="text-sm font-medium">
                {SHARE_FLAG_LABELS[flag]}
                <span className="ml-2 text-xs font-normal text-muted-foreground">{state.checked ? "on" : "off"}</span>
              </label>
              <p id={`${inputId}-help`} className="text-xs text-muted-foreground">
                {FLAG_HELP[flag]}
                {state.note ? <span className="mt-0.5 block text-foreground">{state.note}</span> : null}
              </p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** Share policy of a case (`#share-policy`, the target of the policy-blocked links). */
export function SharePolicyCard({
  flags,
  policy,
  tlpRed,
  canTurnOn,
  canTurnOff,
  readOnly,
  pending,
  onChange,
}: {
  flags: ShareFlags;
  policy: SharePolicy;
  tlpRed: boolean;
  canTurnOn: boolean;
  canTurnOff: boolean;
  readOnly: boolean;
  pending: boolean;
  onChange: (next: ShareFlags) => void;
}) {
  return (
    <Card id={SHARE_POLICY_ANCHOR} className="scroll-mt-20">
      <CardHeader>
        <CardTitle>Share policy</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <ShareToggles
          flags={flags}
          tlpRed={tlpRed}
          canTurnOn={canTurnOn}
          canTurnOff={canTurnOff}
          readOnly={readOnly}
          pending={pending}
          onChange={onChange}
        />
        <p className="rounded-md border bg-muted/40 px-3 py-2 text-xs" role="status">
          {sharePolicyLine(policy)}
        </p>
        <p className="text-[11px] text-muted-foreground">
          Evidence items can also be excluded one by one on the Evidence tab. Changes are audited.
        </p>
      </CardContent>
    </Card>
  );
}
