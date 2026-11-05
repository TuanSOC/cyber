"use client";

import { useState } from "react";
import { toast } from "sonner";

import {
  AttackMatrix,
  RationaleText,
  SourceList,
  StatusChip,
  TechniqueLabelText,
} from "@/components/case-attack/attack-parts";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { JobRoute } from "@/lib/ai";
import { type Investigation, caseErrorMessage } from "@/lib/case";
import {
  type AttackMapping,
  type AttackSuggestion,
  MAPPING_STATUSES,
  MAPPING_STATUS_LABELS,
  type MappingStatus,
  RATIONALE_MAX,
  parseTechniqueId,
  techniqueText,
  toSourceRefs,
} from "@/lib/case-attack";
import { formatDate } from "@/lib/format";
import type { Permission } from "@/lib/roles";
import { useAttackSuggestions, useCaseAttack, useCreateMapping, useJobRoutes, useUpdateMapping } from "@/lib/use-case";
import { useAttackLabels } from "@/lib/use-ti";

/**
 * ATT&CK tab: the tactic matrix, the mappings with their status and rationale, suggestions
 * from capa, findings and verified AI citations (never auto-confirmed), and add by id.
 */
export function AttackTab({
  orgId,
  inv,
  can,
}: {
  orgId: string;
  inv: Investigation;
  can: (permission: Permission) => boolean;
}) {
  const attack = useCaseAttack(orgId, inv.id);
  const routes = useJobRoutes(orgId, inv.id);
  const writable = can("investigation.write") && inv.status !== "archived";
  const data = attack.data;
  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>ATT&amp;CK matrix</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {attack.isError ? (
            <p className="text-sm text-destructive" role="alert">
              {caseErrorMessage(attack.error)}
            </p>
          ) : !data ? (
            <p className="text-sm text-muted-foreground">Loading mappings…</p>
          ) : (
            <AttackMatrix matrix={data.matrix} />
          )}
          {writable ? <AddTechnique orgId={orgId} investigationId={inv.id} /> : null}
        </CardContent>
      </Card>
      {data ? (
        <Card>
          <CardHeader>
            <CardTitle>Mappings</CardTitle>
          </CardHeader>
          <CardContent>
            {data.mappings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No technique mapped yet.</p>
            ) : (
              <ul className="flex flex-col divide-y rounded-md border">
                {data.mappings.map((m) => (
                  <MappingRow key={m.id} orgId={orgId} investigationId={inv.id} mapping={m} routes={routes} writable={writable} />
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      ) : null}
      <SuggestionsPanel orgId={orgId} investigationId={inv.id} routes={routes} writable={writable} />
      {data ? (
        <p className="text-[11px] text-muted-foreground">
          MITRE ATT&amp;CK® Enterprise v{data.index_version} (offline index). {data.notice}
        </p>
      ) : null}
    </div>
  );
}

function MappingRow({
  orgId,
  investigationId,
  mapping,
  routes,
  writable,
}: {
  orgId: string;
  investigationId: string;
  mapping: AttackMapping;
  routes: ReadonlyMap<string, JobRoute>;
  writable: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [rationale, setRationale] = useState(mapping.rationale);
  const update = useUpdateMapping(orgId, investigationId);
  const when = formatDate(mapping.updated_at);
  const save = (body: { status?: MappingStatus; rationale?: string }) =>
    update.mutate(
      { mappingId: mapping.id, body },
      {
        onSuccess: () => setEditing(false),
        onError: (error) => toast.error(caseErrorMessage(error)),
      },
    );
  return (
    <li className="flex flex-col gap-2 px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip status={mapping.status} />
        <TechniqueLabelText label={mapping.label} />
        <span className="ml-auto text-xs text-muted-foreground" title={when.utc}>
          {mapping.updated_by_name} · {when.local}
        </span>
      </div>
      {editing ? (
        <form
          className="flex flex-col gap-1"
          onSubmit={(event) => {
            event.preventDefault();
            save({ rationale });
          }}
        >
          <Textarea aria-label="Rationale" rows={3} maxLength={RATIONALE_MAX} value={rationale}
            onChange={(event) => setRationale(event.target.value)} />
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground tabular-nums">
              {rationale.length} / {RATIONALE_MAX}
            </span>
            <Button type="button" size="sm" variant="outline" className="ml-auto" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={update.isPending}>
              Save rationale
            </Button>
          </div>
        </form>
      ) : (
        <RationaleText text={mapping.rationale} />
      )}
      <SourceList
        orgId={orgId}
        sources={mapping.sources}
        routes={routes}
        citeIn={writable && mapping.status !== "rejected" ? investigationId : undefined}
      />
      {writable && !editing ? (
        <div className="flex flex-wrap gap-1">
          {MAPPING_STATUSES.filter((s) => s !== mapping.status).map((s) => (
            <Button key={s} size="xs" variant="outline" disabled={update.isPending} onClick={() => save({ status: s })}>
              Mark {MAPPING_STATUS_LABELS[s].toLowerCase()}
            </Button>
          ))}
          <Button
            size="xs"
            variant="ghost"
            onClick={() => {
              setRationale(mapping.rationale);
              setEditing(true);
            }}
          >
            Edit rationale
          </Button>
        </div>
      ) : null}
    </li>
  );
}

function SuggestionsPanel({
  orgId,
  investigationId,
  routes,
  writable,
}: {
  orgId: string;
  investigationId: string;
  routes: ReadonlyMap<string, JobRoute>;
  writable: boolean;
}) {
  const suggestions = useAttackSuggestions(orgId, investigationId);
  const create = useCreateMapping(orgId, investigationId);
  const items = suggestions.data?.items ?? [];
  const act = (s: AttackSuggestion, status: MappingStatus) =>
    create.mutate(
      { technique_id: s.technique_id, status, rationale: "", sources: toSourceRefs(s.sources) },
      {
        onSuccess: () => toast.success(`${s.technique_id} marked ${MAPPING_STATUS_LABELS[status].toLowerCase()}`),
        onError: (error) => toast.error(caseErrorMessage(error)),
      },
    );
  return (
    <Card>
      <CardHeader>
        <CardTitle>Suggestions</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-xs text-muted-foreground">
          From capa capabilities, finding ATT&amp;CK ids and AI techniques with a verified citation. Nothing is mapped
          until an analyst confirms, suspects or rejects it.
        </p>
        {suggestions.isError ? (
          <p className="text-sm text-destructive" role="alert">
            {caseErrorMessage(suggestions.error)}
          </p>
        ) : suggestions.isPending ? (
          <p className="text-sm text-muted-foreground">Loading suggestions…</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No suggestions from the evidence of this case.</p>
        ) : (
          <ul className="flex flex-col divide-y rounded-md border">
            {items.map((s) => (
              <li key={s.technique_id} className="flex flex-col gap-1.5 px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <TechniqueLabelText label={s.label} />
                  {s.already_mapped ? <span className="text-xs text-muted-foreground">already mapped</span> : null}
                </div>
                <SourceList orgId={orgId} sources={s.sources} routes={routes} />
                {writable && !s.already_mapped ? (
                  <div className="flex flex-wrap gap-1">
                    {MAPPING_STATUSES.map((status) => (
                      <Button key={status} size="xs" variant="outline" disabled={create.isPending} onClick={() => act(s, status)}>
                        {status === "confirmed" ? "Confirm" : status === "suspected" ? "Suspect" : "Reject"}
                      </Button>
                    ))}
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

/** Add by id: the id is checked against the offline index (`GET /attack/techniques?ids=`). */
function AddTechnique({ orgId, investigationId }: { orgId: string; investigationId: string }) {
  const [input, setInput] = useState("");
  const [status, setStatus] = useState<MappingStatus>("suspected");
  const [rationale, setRationale] = useState("");
  const id = parseTechniqueId(input);
  const lookup = useAttackLabels(id ? [id] : []);
  const label = lookup.data?.techniques.find((t) => t.id === id);
  const unknown = Boolean(id && lookup.data && !label);
  const unusable = Boolean(label && (label.revoked || label.deprecated));
  const create = useCreateMapping(orgId, investigationId);
  const problem = !input.trim()
    ? null
    : !id
      ? "Use the ATT&CK id form T1234 or T1234.001."
      : unknown
        ? "Unknown in the offline ATT&CK index."
        : unusable
          ? "Revoked or deprecated techniques cannot be mapped."
          : null;
  return (
    <form
      className="flex flex-col gap-2 rounded-md border p-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (!id || !label || unusable) return;
        create.mutate(
          { technique_id: id, status, rationale: rationale.trim(), sources: [] },
          {
            onSuccess: () => {
              setInput("");
              setRationale("");
              toast.success(`${id} mapped`);
            },
            onError: (error) => toast.error(caseErrorMessage(error)),
          },
        );
      }}
    >
      <p className="text-sm font-medium">Add a technique by id</p>
      <div className="flex flex-wrap gap-2">
        <Input className="w-40 font-mono" aria-label="Technique id" placeholder="T1059.001" maxLength={9} value={input}
          aria-invalid={problem !== null} onChange={(event) => setInput(event.target.value)} />
        <select
          aria-label="Status"
          className="h-9 rounded-md border border-input bg-background px-2 text-sm"
          value={status}
          onChange={(event) => setStatus(event.target.value as MappingStatus)}
        >
          {MAPPING_STATUSES.map((s) => (
            <option key={s} value={s}>
              {MAPPING_STATUS_LABELS[s]}
            </option>
          ))}
        </select>
      </div>
      <p className="text-xs text-muted-foreground" role="status">
        {problem ?? (label ? techniqueText({ technique_id: label.id, name: label.name }) : "Enter an id to check it.")}
      </p>
      <Textarea aria-label="Rationale (optional)" placeholder="Rationale (optional, plain text)" rows={2}
        maxLength={RATIONALE_MAX} value={rationale} onChange={(event) => setRationale(event.target.value)} />
      <Button type="submit" size="sm" className="w-fit" disabled={create.isPending || !label || unusable}>
        Add mapping
      </Button>
    </form>
  );
}
