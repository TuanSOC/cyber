"use client";

import { useId, useState } from "react";

import { TlpBadge } from "@/components/tlp/tlp-badge";
import { TLP_DEFINITIONS, TLP_LABELS, TLP_VALUES, isDowngrade, isTlp, type Tlp } from "@/lib/tlp";

/**
 * TLP picker with the downgrade rule of the API: choosing a label less restrictive than
 * `current` needs `org.update` (`canDowngrade`) and an explicit acknowledgement checkbox.
 * `onChange` receives the label and whether the downgrade was acknowledged; without the
 * permission, less restrictive labels are disabled.
 */
export function TlpSelect({
  value,
  current,
  canDowngrade,
  onChange,
  disabled = false,
  label = "Traffic Light Protocol",
}: {
  value: Tlp;
  current: Tlp;
  canDowngrade: boolean;
  onChange: (tlp: Tlp, acknowledgeDowngrade: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  const id = useId();
  const [acknowledged, setAcknowledged] = useState(false);
  const downgrade = isDowngrade(value, current);
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        aria-describedby={`${id}-definition`}
        className="border-input bg-background h-9 w-fit rounded-md border px-3 text-sm"
        onChange={(event) => {
          const next = event.target.value;
          if (!isTlp(next)) return;
          setAcknowledged(false);
          onChange(next, false);
        }}
      >
        {TLP_VALUES.map((tlp) => (
          <option key={tlp} value={tlp} disabled={!canDowngrade && isDowngrade(tlp, current)}>
            {TLP_LABELS[tlp]}
          </option>
        ))}
      </select>
      <span id={`${id}-definition`} className="flex items-center gap-2">
        <TlpBadge tlp={value} />
        <span className="text-muted-foreground text-xs">{TLP_DEFINITIONS[value]}</span>
      </span>
      {downgrade ? (
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={acknowledged}
            disabled={disabled || !canDowngrade}
            onChange={(event) => {
              setAcknowledged(event.target.checked);
              onChange(value, event.target.checked);
            }}
          />
          <span>
            I confirm lowering the marking from {TLP_LABELS[current]} to {TLP_LABELS[value]}. This is
            audited.
            {!canDowngrade ? " Only an admin can lower the TLP." : null}
          </span>
        </label>
      ) : null}
    </div>
  );
}
