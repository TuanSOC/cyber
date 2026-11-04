"use client";

import Link from "next/link";

import { type Integration, type ProviderName, providerLabel } from "@/lib/ti";

/** Checkbox list of the org's enabled providers (`selected` is the chosen subset). */
export function ProviderPicker({
  providers,
  selected,
  onChange,
  idPrefix,
}: {
  providers: readonly Integration[];
  selected: readonly ProviderName[];
  onChange: (next: ProviderName[]) => void;
  idPrefix: string;
}) {
  return (
    <fieldset className="flex flex-wrap gap-x-4 gap-y-2">
      <legend className="sr-only">Providers</legend>
      {providers.map((p) => {
        const id = `${idPrefix}-${p.name}`;
        const checked = selected.includes(p.name);
        return (
          <label key={p.name} htmlFor={id} className="flex items-center gap-2 text-sm">
            <input
              id={id}
              type="checkbox"
              className="size-4 accent-primary"
              checked={checked}
              onChange={(event) =>
                onChange(event.target.checked ? [...selected, p.name] : selected.filter((n) => n !== p.name))
              }
            />
            {providerLabel(p.name)}
          </label>
        );
      })}
    </fieldset>
  );
}

/** Shown when no provider is enabled: admins get a link to the Integrations page. */
export function NoProvidersNotice({ orgId, canManage }: { orgId: string; canManage: boolean }) {
  return (
    <p className="text-sm text-muted-foreground">
      No threat intel provider is enabled for this organization.{" "}
      {canManage ? (
        <Link href={`/o/${orgId}/settings/integrations`} className="text-primary underline-offset-4 hover:underline">
          Configure providers
        </Link>
      ) : (
        "An owner or admin can enable providers under Settings → Integrations."
      )}
    </p>
  );
}
