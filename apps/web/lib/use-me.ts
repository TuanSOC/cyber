"use client";

import { useQuery } from "@tanstack/react-query";

import { ApiError, api, type Me, unwrap } from "@/lib/api";

export const ME_QUERY_KEY = ["me"] as const;

export function useMe() {
  return useQuery<Me, ApiError>({
    queryKey: ME_QUERY_KEY,
    queryFn: async () => unwrap(await api.GET("/api/v1/auth/me")),
    retry: false,
    staleTime: 60_000,
  });
}
