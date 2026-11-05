"use client";

import { useId, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TI_IOC_TYPE_LABELS } from "@/lib/ti";
import {
  ITEM_NOTE_MAX,
  type IocItemManual,
  MANUAL_TYPES,
  type ManualIocType,
  checkManualIoc,
  refangInput,
} from "@/lib/ioc-collections";

/**
 * Manual add (type + value + optional note) with a client-side shape check. The server
 * normalizes the value and answers `added / duplicate / invalid` per item.
 */
export function ManualAddForm({ pending, onAdd }: { pending: boolean; onAdd: (item: IocItemManual) => void }) {
  const id = useId();
  const [type, setType] = useState<ManualIocType>("domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const problem = value ? checkManualIoc(type, value) : null;
  return (
    <form
      className="flex flex-col gap-2 rounded-md border p-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (checkManualIoc(type, value)) return;
        onAdd({ type, value: refangInput(value), ...(note.trim() ? { note: note.trim() } : {}) });
        setValue("");
        setNote("");
      }}
    >
      <p className="text-sm font-medium">Add an indicator</p>
      <div className="flex flex-wrap gap-2">
        <label className="sr-only" htmlFor={`${id}-type`}>
          Type
        </label>
        <select
          id={`${id}-type`}
          className="h-9 rounded-md border border-input bg-background px-2 text-sm"
          value={type}
          onChange={(event) => setType(event.target.value as ManualIocType)}
        >
          {MANUAL_TYPES.map((t) => (
            <option key={t} value={t}>
              {TI_IOC_TYPE_LABELS[t]}
            </option>
          ))}
        </select>
        <label className="sr-only" htmlFor={`${id}-value`}>
          Value
        </label>
        <Input
          id={`${id}-value`}
          className="min-w-0 flex-1 font-mono"
          placeholder="Value (defanged input is accepted)"
          maxLength={2048}
          value={value}
          aria-invalid={problem !== null}
          aria-describedby={`${id}-problem`}
          onChange={(event) => setValue(event.target.value)}
        />
      </div>
      <Input
        aria-label="Note (optional)"
        placeholder="Note (optional)"
        maxLength={ITEM_NOTE_MAX}
        value={note}
        onChange={(event) => setNote(event.target.value)}
      />
      <div className="flex items-center gap-2">
        <p id={`${id}-problem`} className="text-xs text-muted-foreground">
          {problem ?? "The server normalizes and checks every value."}
        </p>
        <Button type="submit" size="sm" className="ml-auto" disabled={pending || !value || problem !== null}>
          Add
        </Button>
      </div>
    </form>
  );
}
