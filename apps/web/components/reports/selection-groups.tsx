"use client";

import { useId } from "react";

import { Group } from "@/components/reports/builder-fields";
import { Input } from "@/components/ui/input";
import {
  ALERTS_MAX,
  type AttackStatus,
  type DraftInclude,
  FINDINGS_MAX,
  IOCS_MAX,
  SEVERITIES,
  type Severity,
  TIMELINE_KINDS,
  TIMELINE_KIND_LABELS,
  TIMELINE_MAX,
  type TimelineKind,
  clampInt,
  isoToLocalInput,
  localInputToIso,
  toggleId,
} from "@/lib/reports";

/*
 * The selection groups that need no case data: evidence and custody, findings and alerts,
 * IOCs (the collections come from the caller), ATT&CK statuses and the timeline. Each one edits
 * its slice of `draft.include` and hands back the whole include.
 */

type GroupProps = { include: DraftInclude; onChange: (include: DraftInclude) => void; disabled: boolean };

export function Toggle({
  label,
  description,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled: boolean;
}) {
  return (
    <label className="flex items-start gap-2 text-sm">
      <input
        type="checkbox"
        className="mt-1"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>
        {label}
        {description ? <span className="block text-xs text-muted-foreground">{description}</span> : null}
      </span>
    </label>
  );
}

export function NumberField({
  label,
  value,
  min,
  max,
  onChange,
  disabled,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
  disabled: boolean;
}) {
  const id = useId();
  return (
    <span className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium">
        {label}
      </label>
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        className="h-8 w-28"
        min={min}
        max={max}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(clampInt(event.target.value, min, max))}
      />
    </span>
  );
}

export function EvidenceGroup({ include, onChange, disabled }: GroupProps) {
  return (
    <Group title="Evidence and custody">
      <Toggle
        label="Evidence inventory"
        description="File names, sizes, types and trusted hashes."
        checked={include.evidence}
        disabled={disabled}
        onChange={(evidence) => onChange({ ...include, evidence })}
      />
      <Toggle
        label="Chain of custody"
        description="Custody events (IP addresses and user agents only in internal reports)."
        checked={include.custody}
        disabled={disabled}
        onChange={(custody) => onChange({ ...include, custody })}
      />
    </Group>
  );
}

function SeverityPick({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: Severity;
  onChange: (value: Severity) => void;
  disabled: boolean;
}) {
  const id = useId();
  return (
    <span className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium">
        {label}
      </label>
      <select
        id={id}
        className="h-8 w-32 rounded-md border border-input bg-background px-2 text-sm"
        value={value}
        disabled={disabled}
        onChange={(event) => {
          const next = SEVERITIES.find((s) => s === event.target.value);
          if (next) onChange(next);
        }}
      >
        {SEVERITIES.map((severity) => (
          <option key={severity} value={severity}>
            {severity}
          </option>
        ))}
      </select>
    </span>
  );
}

export function FindingsAlertsGroup({ include, onChange, disabled }: GroupProps) {
  return (
    <Group title="Findings and alerts" description="Rows at or above the minimum severity, highest first, up to the maximum.">
      <div className="flex flex-wrap gap-4">
        <SeverityPick
          label="Findings: minimum severity"
          value={include.findings.min_severity}
          disabled={disabled}
          onChange={(min_severity) => onChange({ ...include, findings: { ...include.findings, min_severity } })}
        />
        <NumberField
          label="Findings: maximum"
          value={include.findings.max}
          min={0}
          max={FINDINGS_MAX}
          disabled={disabled}
          onChange={(max) => onChange({ ...include, findings: { ...include.findings, max } })}
        />
      </div>
      <div className="flex flex-wrap gap-4">
        <SeverityPick
          label="Alerts: minimum severity"
          value={include.alerts.min_severity}
          disabled={disabled}
          onChange={(min_severity) => onChange({ ...include, alerts: { ...include.alerts, min_severity } })}
        />
        <NumberField
          label="Alerts: maximum"
          value={include.alerts.max}
          min={0}
          max={ALERTS_MAX}
          disabled={disabled}
          onChange={(max) => onChange({ ...include, alerts: { ...include.alerts, max } })}
        />
      </div>
    </Group>
  );
}

export function IocsGroup({
  include,
  onChange,
  disabled,
  collections,
  collectionsNote,
}: GroupProps & {
  collections: readonly { id: string; name: string; item_count: number }[];
  collectionsNote?: string | null;
}) {
  return (
    <Group title="IOCs and threat intelligence">
      <Toggle
        label="Case-wide IOCs"
        description="Every IOC of the case's latest analyses, deduplicated."
        checked={include.iocs.case_iocs}
        disabled={disabled}
        onChange={(case_iocs) => onChange({ ...include, iocs: { ...include.iocs, case_iocs } })}
      />
      <div className="flex flex-col gap-1">
        <span className="text-xs font-medium">IOC collections</span>
        {collectionsNote ? <span className="text-xs text-muted-foreground">{collectionsNote}</span> : null}
        {collections.length === 0 && !collectionsNote ? (
          <span className="text-xs text-muted-foreground">This case has no IOC collections.</span>
        ) : null}
        {collections.map((collection) => (
          <Toggle
            key={collection.id}
            label={`${collection.name} (${collection.item_count})`}
            checked={include.iocs.collections.includes(collection.id)}
            disabled={disabled}
            onChange={(on) =>
              onChange({ ...include, iocs: { ...include.iocs, collections: toggleId(include.iocs.collections, collection.id, on, 50) } })
            }
          />
        ))}
      </div>
      <NumberField
        label="IOCs: maximum"
        value={include.iocs.max}
        min={0}
        max={IOCS_MAX}
        disabled={disabled}
        onChange={(max) => onChange({ ...include, iocs: { ...include.iocs, max } })}
      />
      <Toggle
        label="Threat intelligence"
        description="Provider results for the included IOCs, attributed to each provider."
        checked={include.ti}
        disabled={disabled}
        onChange={(ti) => onChange({ ...include, ti })}
      />
    </Group>
  );
}

const ATTACK_STATUSES: readonly [AttackStatus, string][] = [
  ["confirmed", "Confirmed techniques"],
  ["suspected", "Suspected techniques"],
];

export function AttackGroup({ include, onChange, disabled }: GroupProps) {
  return (
    <Group title="ATT&CK" description="The case's technique mappings (rejected mappings are never included).">
      {ATTACK_STATUSES.map(([status, label]) => (
        <Toggle
          key={status}
          label={label}
          checked={include.attack.statuses.includes(status)}
          disabled={disabled}
          onChange={(on) => {
            const statuses = ATTACK_STATUSES.map(([s]) => s).filter((s) => (s === status ? on : include.attack.statuses.includes(s)));
            onChange({ ...include, attack: { statuses } });
          }}
        />
      ))}
    </Group>
  );
}

export function TimelineGroup({ include, onChange, disabled }: GroupProps) {
  const fromId = useId();
  const toId = useId();
  const kinds = include.timeline.kinds ?? null;
  const setKinds = (next: TimelineKind[] | null) => onChange({ ...include, timeline: { ...include.timeline, kinds: next } });
  return (
    <Group title="Timeline" description="Merged case timeline entries in the range, oldest first, up to the maximum.">
      <Toggle
        label="All kinds"
        checked={kinds === null}
        disabled={disabled}
        onChange={(all) => setKinds(all ? null : [...TIMELINE_KINDS])}
      />
      {kinds !== null ? (
        <div className="grid grid-cols-2 gap-1 pl-5">
          {TIMELINE_KINDS.map((kind) => (
            <Toggle
              key={kind}
              label={TIMELINE_KIND_LABELS[kind]}
              checked={kinds.includes(kind)}
              disabled={disabled}
              onChange={(on) => setKinds(TIMELINE_KINDS.filter((k) => (k === kind ? on : kinds.includes(k))))}
            />
          ))}
        </div>
      ) : null}
      <div className="flex flex-wrap gap-4">
        <span className="flex flex-col gap-1">
          <label htmlFor={fromId} className="text-xs font-medium">
            From (local time)
          </label>
          <Input
            id={fromId}
            type="datetime-local"
            className="h-8 w-56"
            value={isoToLocalInput(include.timeline.from)}
            disabled={disabled}
            onChange={(event) => onChange({ ...include, timeline: { ...include.timeline, from: localInputToIso(event.target.value) } })}
          />
        </span>
        <span className="flex flex-col gap-1">
          <label htmlFor={toId} className="text-xs font-medium">
            To (local time)
          </label>
          <Input
            id={toId}
            type="datetime-local"
            className="h-8 w-56"
            value={isoToLocalInput(include.timeline.to)}
            disabled={disabled}
            onChange={(event) => onChange({ ...include, timeline: { ...include.timeline, to: localInputToIso(event.target.value) } })}
          />
        </span>
        <NumberField
          label="Maximum entries"
          value={include.timeline.max}
          min={0}
          max={TIMELINE_MAX}
          disabled={disabled}
          onChange={(max) => onChange({ ...include, timeline: { ...include.timeline, max } })}
        />
      </div>
    </Group>
  );
}
