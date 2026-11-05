"use client";

import { type QueryClient, useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api";
import type { AiProviderName, AiProviderPage, AiProviderSaved } from "@/lib/ai-settings";

/*
 * React Query hooks for the AI settings and provider routes. Nothing here ever holds an API
 * key: keys are sent once by `storeAiKey` (never through a mutation's cached variables) and
 * no response carries one.
 */

export const aiSettingsKeys = {
  providers: (orgId: string) => ["org", orgId, "ai", "providers"] as const,
  settings: (orgId: string) => ["org", orgId, "ai", "settings"] as const,
  usage: (orgId: string) => ["org", orgId, "ai", "usage"] as const,
  members: (orgId: string) => ["org", orgId, "members"] as const,
};

export function useAiProviders(
  orgId: string,
  poll: number | false | ((data: AiProviderPage | undefined) => number | false) = false,
) {
  return useQuery({
    queryKey: aiSettingsKeys.providers(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/ai/providers", { params: { path: { org_id: orgId } } })),
    refetchInterval: typeof poll === "function" ? (query) => poll(query.state.data) : poll,
  });
}

export function useAiSettings(orgId: string) {
  return useQuery({
    queryKey: aiSettingsKeys.settings(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/ai/settings", { params: { path: { org_id: orgId } } })),
  });
}

/** Today's (UTC) usage, refreshed every minute while the page is open. */
export function useAiUsage(orgId: string) {
  return useQuery({
    queryKey: aiSettingsKeys.usage(orgId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/orgs/{org_id}/ai/usage", { params: { path: { org_id: orgId } } })),
    refetchInterval: 60_000,
  });
}

/** Display name of a member (who acknowledged the privacy notice); same query as the Members page. */
export function useMemberName(orgId: string, userId: string | null) {
  const members = useQuery({
    queryKey: aiSettingsKeys.members(orgId),
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/orgs/{org_id}/members", {
          params: { path: { org_id: orgId }, query: { limit: 100 } },
        }),
      ),
    enabled: userId !== null,
  });
  if (userId === null) return null;
  if (!members.data) return members.isError ? "a member" : "…";
  return members.data.items.find((m) => m.user_id === userId)?.display_name ?? "a former member";
}

type PutKey = (args: {
  orgId: string;
  provider: AiProviderName;
  apiKey: string;
}) => Promise<{ data?: AiProviderSaved; error?: unknown; response: Response }>;

const putKey: PutKey = ({ orgId, provider, apiKey }) =>
  api.PUT("/api/v1/orgs/{org_id}/ai/providers/{provider}", {
    params: { path: { org_id: orgId, provider } },
    body: { api_key: apiKey },
  });

/**
 * Store a write-only key. The key is read from the (uncontrolled) password input at submit
 * time and goes straight into the request body: never into React state, the query cache, a
 * mutation's variables, logs or storage. The input is cleared right after the request,
 * whatever its outcome. Only the key-less answer is used to refresh the provider list.
 * Throws the request's `ApiError`.
 */
export async function storeAiKey({
  orgId,
  provider,
  input,
  queryClient,
  put = putKey,
}: {
  orgId: string;
  provider: AiProviderName;
  input: { value: string };
  queryClient: QueryClient;
  put?: PutKey;
}): Promise<{ verifyQueued: boolean }> {
  let result: Awaited<ReturnType<PutKey>>;
  try {
    result = await put({ orgId, provider, apiKey: input.value });
  } finally {
    input.value = "";
  }
  const saved = unwrap(result);
  await queryClient.invalidateQueries({ queryKey: aiSettingsKeys.providers(orgId) });
  return { verifyQueued: saved.verify_queued };
}
