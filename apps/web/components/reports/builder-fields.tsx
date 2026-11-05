"use client";

import { TriangleAlert } from "lucide-react";
import { type ReactNode, useId } from "react";

import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  ANALYST_SECTIONS,
  DISTRIBUTION_MAX_CHARS,
  type DraftSections,
  EXTERNAL_REVIEW_WARNING,
  PROFILE_TEXT,
  type ReportProfile,
  SECTION_MAX_CHARS,
  TITLE_MAX_CHARS,
  charCounter,
} from "@/lib/reports";
import { cn } from "@/lib/utils";

/** A group of builder controls with a legend (one per selection group). */
export function Group({ title, description, children }: { title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <fieldset className="min-w-0 rounded-md border p-4">
      <legend className="px-1 text-sm font-semibold">{title}</legend>
      {description ? <div className="mb-3 text-xs text-muted-foreground">{description}</div> : null}
      <div className="flex flex-col gap-3">{children}</div>
    </fieldset>
  );
}

export function Counter({ id, value, max }: { id: string; value: string; max: number }) {
  const counter = charCounter(value, max);
  return (
    <span
      id={id}
      className={cn("text-xs tabular-nums", counter.over ? "font-semibold text-destructive" : counter.near ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground")}
    >
      {counter.text} characters{counter.over ? " (over the limit)" : ""}
    </span>
  );
}

export function TitleField({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium">
        Title
      </label>
      <Input
        id={id}
        value={value}
        maxLength={TITLE_MAX_CHARS}
        disabled={disabled}
        aria-invalid={!value.trim() || undefined}
        aria-describedby={`${id}-count`}
        onChange={(event) => onChange(event.target.value)}
      />
      <Counter id={`${id}-count`} value={value} max={TITLE_MAX_CHARS} />
    </div>
  );
}

/** Internal / external, with what `external` removes and the human-review warning (RT8). */
export function ProfileField({
  value,
  onChange,
  disabled,
}: {
  value: ReportProfile;
  onChange: (value: ReportProfile) => void;
  disabled: boolean;
}) {
  const name = useId();
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="text-sm font-medium">Profile</legend>
      {(Object.keys(PROFILE_TEXT) as ReportProfile[]).map((profile) => (
        <label key={profile} className="flex items-start gap-2 text-sm">
          <input
            type="radio"
            name={name}
            value={profile}
            checked={value === profile}
            disabled={disabled}
            onChange={() => onChange(profile)}
            className="mt-1"
          />
          <span>
            <span className="font-medium">{PROFILE_TEXT[profile].label}</span>
            <span className="block text-xs text-muted-foreground">{PROFILE_TEXT[profile].summary}</span>
          </span>
        </label>
      ))}
      {value === "external" ? (
        <p role="note" className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-2 text-xs">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>{EXTERNAL_REVIEW_WARNING}</span>
        </p>
      ) : null}
    </fieldset>
  );
}

export const DISTRIBUTION_REQUIRED_TEXT = "Required for this marking or profile: say who may receive the report.";

export function DistributionField({
  value,
  required,
  onChange,
  disabled,
}: {
  value: string;
  required: boolean;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  const id = useId();
  const missing = required && !value.trim();
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium">
        Distribution {required ? <span className="text-destructive">(required)</span> : <span className="text-muted-foreground">(optional)</span>}
      </label>
      <Textarea
        id={id}
        value={value}
        rows={2}
        maxLength={DISTRIBUTION_MAX_CHARS}
        disabled={disabled}
        required={required}
        aria-invalid={missing || undefined}
        aria-describedby={`${id}-count ${id}-help`}
        placeholder="For example: SOC team and IT management only"
        onChange={(event) => onChange(event.target.value)}
      />
      <span className="flex flex-wrap justify-between gap-2">
        <span id={`${id}-help`} className={cn("text-xs", missing ? "font-medium text-destructive" : "text-muted-foreground")}>
          {missing ? DISTRIBUTION_REQUIRED_TEXT : "Printed on the cover."}
        </span>
        <Counter id={`${id}-count`} value={value} max={DISTRIBUTION_MAX_CHARS} />
      </span>
    </div>
  );
}

/** The analyst sections: plain `<textarea>`s with counters (no Markdown, no rich text). */
export function SectionsEditor({
  sections,
  onChange,
  disabled,
}: {
  sections: DraftSections;
  onChange: (sections: DraftSections) => void;
  disabled: boolean;
}) {
  const base = useId();
  return (
    <Group title="Analyst sections" description="Plain text. Line breaks are kept; nothing is interpreted as Markdown or HTML.">
      {ANALYST_SECTIONS.map((section) => {
        const id = `${base}-${section.key}`;
        return (
          <div key={section.key} className="flex flex-col gap-1">
            <label htmlFor={id} className="text-sm font-medium">
              {section.label}
            </label>
            <span id={`${id}-hint`} className="text-xs text-muted-foreground">
              {section.hint}
            </span>
            <Textarea
              id={id}
              value={sections[section.key]}
              rows={section.key === "executive_summary" ? 6 : 3}
              maxLength={SECTION_MAX_CHARS}
              disabled={disabled}
              aria-describedby={`${id}-hint ${id}-count`}
              onChange={(event) => onChange({ ...sections, [section.key]: event.target.value })}
            />
            <Counter id={`${id}-count`} value={sections[section.key]} max={SECTION_MAX_CHARS} />
          </div>
        );
      })}
    </Group>
  );
}
