"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { ALL, FilterSelect, usePageOffset } from "@/components/analysis/result-parts";
import { PageHeader } from "@/components/page-header";
import { PAGE_SIZE, Pager } from "@/components/pager";
import { QueryError } from "@/components/query-error";
import { MitreNoticeFooter } from "@/components/ti/attack-chips";
import { ResultPanel } from "@/components/ti/result-panel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, unwrap } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import {
  type LookupType,
  PROVIDERS,
  type ProviderName,
  historyDeltas,
  historyHref,
  noteText,
  providerLabel,
  skipReasonText,
  tiIocTypeLabel,
} from "@/lib/ti";
import { tiKeys } from "@/lib/use-ti";

const LOOKUP_TYPES: LookupType[] = ["ip", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"];
const TYPE_OPTIONS = LOOKUP_TYPES.map((t) => [t, t === "ip" ? "IP" : tiIocTypeLabel(t)] as const);
const PROVIDER_OPTIONS = PROVIDERS.map((p) => [p, providerLabel(p)] as const);
const AUTO = "auto";

function asLookupType(value: string | null): LookupType | undefined {
  return value && (LOOKUP_TYPES as string[]).includes(value) ? (value as LookupType) : undefined;
}

/** Every stored provider answer for one indicator, newest first (the per-IOC history). */
export default function IocHistoryPage() {
  const { orgId } = useOrg();
  return (
    <>
      <Link
        href={orgPath(orgId, "intel")}
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-4" aria-hidden /> Threat Intel
      </Link>
      <PageHeader
        title="Indicator history"
        description="Every answer stored for this indicator, across providers and runs. Each entry is the provider's own statement on that date."
      />
      <Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
        <History />
      </Suspense>
      <MitreNoticeFooter className="mt-8" />
    </>
  );
}

function SearchForm({ initialValue, initialType }: { initialValue: string; initialType?: LookupType }) {
  const { orgId } = useOrg();
  const router = useRouter();
  const [value, setValue] = useState(initialValue);
  const [type, setType] = useState<LookupType | typeof AUTO>(initialType ?? AUTO);
  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        const v = value.trim();
        if (v) router.push(historyHref(orgId, type === AUTO ? null : type, v));
      }}
    >
      <Input
        className="w-96 font-mono text-xs"
        aria-label="Indicator value"
        placeholder="IP, domain, URL or hash"
        maxLength={2048}
        value={value}
        onChange={(event) => setValue(event.target.value)}
      />
      <FilterSelect
        value={type === AUTO ? ALL : type}
        onChange={(next) => setType(next === ALL ? AUTO : next)}
        options={TYPE_OPTIONS}
        allLabel="Detect type"
        label="Indicator type"
        className="w-36"
      />
      <Button type="submit" size="sm" disabled={!value.trim()}>
        Show history
      </Button>
    </form>
  );
}

function History() {
  const { orgId } = useOrg();
  const searchParams = useSearchParams();
  const value = (searchParams.get("value") ?? "").slice(0, 2048);
  const type = asLookupType(searchParams.get("type"));
  const [provider, setProvider] = useState<ProviderName | typeof ALL>(ALL);
  const filters = { value, type, provider: provider === ALL ? undefined : provider };
  const [offset, setOffset] = usePageOffset(JSON.stringify(filters));

  const history = useQuery({
    queryKey: [...tiKeys.history(orgId), { ...filters, offset }],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/ti/results", {
          params: { path: { org_id: orgId }, query: { ...filters, limit: PAGE_SIZE, offset } },
        }),
      ),
    enabled: value !== "",
    placeholderData: keepPreviousData,
  });

  const data = history.data;
  const deltas = historyDeltas(data?.items ?? []);

  return (
    <div className="flex flex-col gap-4">
      <SearchForm key={`${value}|${type ?? ""}`} initialValue={value} initialType={type} />
      {value === "" ? (
        <p className="text-sm text-muted-foreground">Enter an indicator to see its stored answers.</p>
      ) : history.isError ? (
        <QueryError error={history.error} onRetry={() => void history.refetch()} />
      ) : !data ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <div className="flex flex-col gap-1 rounded-lg border p-3 text-sm">
            <p>
              <span className="text-muted-foreground">Indicator </span>
              <span className="font-mono text-xs break-all">{data.value_norm ?? value}</span>
              <span className="text-muted-foreground"> · {tiIocTypeLabel(data.ioc_type)}</span>
            </p>
            {data.notes.length > 0 && (
              <p className="text-xs text-muted-foreground">{data.notes.map(noteText).join(" · ")}</p>
            )}
            {data.skipped && (
              <p className="text-xs text-muted-foreground">
                No provider would receive this value: {skipReasonText(data.skipped)}.
              </p>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <FilterSelect
              value={provider}
              onChange={setProvider}
              options={PROVIDER_OPTIONS}
              allLabel="All providers"
              label="Provider filter"
              className="w-48"
            />
            <span className="text-xs text-muted-foreground">
              {data.total} {data.total === 1 ? "answer" : "answers"}
            </span>
          </div>
          {data.items.length === 0 ? (
            <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">
              No stored answer for this indicator{provider !== ALL ? ` from ${providerLabel(provider)}` : ""}.
            </p>
          ) : (
            <ol className="flex flex-col gap-3 border-l pl-4">
              {data.items.map((result) => (
                <li key={result.id} className="relative flex flex-col gap-1">
                  <span className="absolute top-3 -left-[1.3rem] size-2 rounded-full bg-border" aria-hidden />
                  {deltas.get(result.id) && (
                    <p className="text-xs text-muted-foreground">
                      Since the previous {providerLabel(result.provider)} answer: {deltas.get(result.id)?.join(", ")}
                    </p>
                  )}
                  <ResultPanel result={result} />
                </li>
              ))}
            </ol>
          )}
          <Pager offset={offset} total={data.total} onChange={setOffset} />
        </>
      )}
    </div>
  );
}
