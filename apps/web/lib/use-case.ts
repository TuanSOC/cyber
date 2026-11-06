"use client";

import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo } from "react";

import { useInvestigationAnalyses } from "@/components/analysis/investigation-analyses";
import type { JobRoute } from "@/lib/ai";
import { ANALYZER_ROUTES } from "@/lib/analysis";
import { api } from "@/lib/api";
import type { AttackMappingCreate, AttackMappingUpdate } from "@/lib/case-attack";
import {
  type Investigation,
  type InvestigationUpdate,
  type RefKindName,
  ensureCaseOk,
  saveDownload,
  unwrapCase,
} from "@/lib/case";
import { type ExportFormat, type IocItemManual, exportFallbackName, exportQuery } from "@/lib/ioc-collections";
import type { NoteCreate, NoteUpdate } from "@/lib/notes";

/*
 * React Query hooks of the case workspace (M6 phase 6). Errors keep the `policy_blocked`
 * reason (`unwrapCase`); every mutation invalidates the lists it changes.
 */

export const caseKeys = {
  investigation: (orgId: string, invId: string) => ["org", orgId, "investigation", invId] as const,
  statusEvents: (orgId: string, invId: string) => ["org", orgId, "investigation", invId, "status-events"] as const,
  notes: (orgId: string, invId: string) => ["org", orgId, "investigation", invId, "notes"] as const,
  note: (orgId: string, noteId: string) => ["org", orgId, "note", noteId] as const,
  caseIocs: (orgId: string, invId: string) => ["org", orgId, "investigation", invId, "iocs"] as const,
  collections: (orgId: string, invId: string) => ["org", orgId, "investigation", invId, "ioc-collections"] as const,
  collection: (orgId: string, collectionId: string) => ["org", orgId, "ioc-collection", collectionId] as const,
  attack: (orgId: string, invId: string) => ["org", orgId, "investigation", invId, "attack"] as const,
  timeline: (orgId: string, invId: string) => ["org", orgId, "investigation", invId, "timeline"] as const,
  evidencePolicy: (orgId: string, evidenceId: string) => ["org", orgId, "evidence", evidenceId, "share-policy"] as const,
  members: (orgId: string) => ["org", orgId, "members", "names"] as const,
};

// ---------------------------------------------------------------------------------------------
// Investigation, status, share policy

export function useInvestigation(orgId: string, invId: string | undefined) {
  return useQuery({
    queryKey: caseKeys.investigation(orgId, invId ?? ""),
    enabled: Boolean(invId),
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}", {
          params: { path: { org_id: orgId, investigation_id: invId ?? "" } },
        }),
      ),
  });
}

export function useUpdateInvestigation(orgId: string, invId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: InvestigationUpdate) =>
      unwrapCase(
        await api.PATCH("/api/v1/orgs/{org_id}/investigations/{investigation_id}", {
          params: { path: { org_id: orgId, investigation_id: invId } },
          body,
        }),
      ),
    onSuccess: async (updated: Investigation) => {
      queryClient.setQueryData(caseKeys.investigation(orgId, invId), updated);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "investigations"] }),
        queryClient.invalidateQueries({ queryKey: caseKeys.statusEvents(orgId, invId) }),
        queryClient.invalidateQueries({ queryKey: caseKeys.timeline(orgId, invId) }),
      ]);
    },
    onError: async () => {
      // Stale data (e.g. 409): reload the case.
      await queryClient.invalidateQueries({ queryKey: caseKeys.investigation(orgId, invId), exact: true });
    },
  });
}

export function useStatusEvents(orgId: string, invId: string) {
  return useInfiniteQuery({
    queryKey: caseKeys.statusEvents(orgId, invId),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/status-events", {
          params: {
            path: { org_id: orgId, investigation_id: invId },
            query: { limit: 50, ...(pageParam ? { cursor: pageParam } : {}) },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor,
  });
}

export function useEvidenceSharePolicy(orgId: string, evidenceId: string) {
  return useQuery({
    queryKey: caseKeys.evidencePolicy(orgId, evidenceId),
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/evidence/{evidence_id}/share-policy", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
        }),
      ),
  });
}

export function usePutEvidenceSharePolicy(orgId: string, evidenceId: string, investigationId?: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { ai_excluded: boolean; ti_excluded: boolean }) =>
      unwrapCase(
        await api.PUT("/api/v1/orgs/{org_id}/evidence/{evidence_id}/share-policy", {
          params: { path: { org_id: orgId, evidence_id: evidenceId } },
          body,
        }),
      ),
    onSuccess: async (out) => {
      queryClient.setQueryData(caseKeys.evidencePolicy(orgId, evidenceId), out);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence", evidenceId], exact: true }),
        queryClient.invalidateQueries({ queryKey: ["org", orgId, "evidence-list"] }),
        ...(investigationId
          ? [queryClient.invalidateQueries({ queryKey: caseKeys.investigation(orgId, investigationId), exact: true })]
          : []),
      ]);
    },
  });
}

/** Evidence of a case (offset paging), with the share-policy flags of each row. */
export function useCaseEvidence(orgId: string, invId: string, offset: number, limit: number) {
  return useQuery({
    queryKey: ["org", orgId, "evidence-list", invId, "with-policy", offset, limit],
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/evidence", {
          params: { path: { org_id: orgId, investigation_id: invId }, query: { limit, offset } },
        }),
      ),
    placeholderData: keepPreviousData,
  });
}

/** Job id → module (pcap / malware) of the case's analyses, for deep links. */
export function useJobRoutes(orgId: string, investigationId: string): ReadonlyMap<string, JobRoute> {
  const analyses = useInvestigationAnalyses(orgId, investigationId);
  return useMemo(
    () =>
      new Map<string, JobRoute>(
        (analyses.data?.items ?? []).map((job) => [job.id, ANALYZER_ROUTES[job.analyzer]]),
      ),
    [analyses.data],
  );
}

/** Display names of the org's members by user id (for tombstones and history). */
export function useMemberNames(orgId: string) {
  return useQuery({
    queryKey: caseKeys.members(orgId),
    queryFn: async () => {
      const page = unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/members", { params: { path: { org_id: orgId }, query: { limit: 100 } } }),
      );
      return new Map(page.items.map((m) => [m.user_id, m.display_name]));
    },
    staleTime: 5 * 60_000,
  });
}

// ---------------------------------------------------------------------------------------------
// Notes

export function useNotes(orgId: string, invId: string, includeDeleted: boolean) {
  return useInfiniteQuery({
    queryKey: [...caseKeys.notes(orgId, invId), { includeDeleted }],
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/notes", {
          params: {
            path: { org_id: orgId, investigation_id: invId },
            query: { include_deleted: includeDeleted, limit: 50, ...(pageParam ? { cursor: pageParam } : {}) },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor,
  });
}

export function useNote(orgId: string, noteId: string | null) {
  return useQuery({
    queryKey: caseKeys.note(orgId, noteId ?? ""),
    enabled: noteId !== null,
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/notes/{note_id}", {
          params: { path: { org_id: orgId, note_id: noteId ?? "" } },
        }),
      ),
  });
}

function useNoteInvalidation(orgId: string, invId: string) {
  const queryClient = useQueryClient();
  return async (noteId?: string) => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: caseKeys.notes(orgId, invId) }),
      queryClient.invalidateQueries({ queryKey: caseKeys.timeline(orgId, invId) }),
      ...(noteId ? [queryClient.invalidateQueries({ queryKey: caseKeys.note(orgId, noteId) })] : []),
    ]);
  };
}

export function useCreateNote(orgId: string, invId: string) {
  const invalidate = useNoteInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async (body: NoteCreate) =>
      unwrapCase(
        await api.POST("/api/v1/orgs/{org_id}/investigations/{investigation_id}/notes", {
          params: { path: { org_id: orgId, investigation_id: invId } },
          body,
        }),
      ),
    onSuccess: async () => invalidate(),
  });
}

export function useUpdateNote(orgId: string, invId: string) {
  const invalidate = useNoteInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async ({ noteId, body }: { noteId: string; body: NoteUpdate }) =>
      unwrapCase(
        await api.PUT("/api/v1/orgs/{org_id}/notes/{note_id}", {
          params: { path: { org_id: orgId, note_id: noteId } },
          body,
        }),
      ),
    onSuccess: async (note) => invalidate(note.id),
    // A stale edit (409) or a removed note: refresh the list and the detail.
    onError: async (_error, { noteId }) => invalidate(noteId),
  });
}

export function useDeleteNote(orgId: string, invId: string) {
  const invalidate = useNoteInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async (noteId: string) =>
      ensureCaseOk(
        await api.DELETE("/api/v1/orgs/{org_id}/notes/{note_id}", {
          params: { path: { org_id: orgId, note_id: noteId } },
        }),
      ),
    onSuccess: async (_out, noteId) => invalidate(noteId),
  });
}

// ---------------------------------------------------------------------------------------------
// Case IOCs and collections

export function useCaseIocs(orgId: string, invId: string, filters: { type?: string; q?: string; limit: number }) {
  return useInfiniteQuery({
    queryKey: [...caseKeys.caseIocs(orgId, invId), filters],
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/iocs", {
          params: {
            path: { org_id: orgId, investigation_id: invId },
            query: {
              limit: filters.limit,
              ...(filters.type ? { type: [filters.type] } : {}),
              ...(filters.q ? { q: filters.q } : {}),
              ...(pageParam ? { cursor: pageParam } : {}),
            },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor,
    placeholderData: keepPreviousData,
  });
}

export function useCollections(orgId: string, invId: string) {
  return useQuery({
    queryKey: caseKeys.collections(orgId, invId),
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/ioc-collections", {
          params: { path: { org_id: orgId, investigation_id: invId } },
        }),
      ),
  });
}

export function useCollection(orgId: string, collectionId: string | null) {
  return useQuery({
    queryKey: caseKeys.collection(orgId, collectionId ?? ""),
    enabled: collectionId !== null,
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/ioc-collections/{collection_id}", {
          params: { path: { org_id: orgId, collection_id: collectionId ?? "" } },
        }),
      ),
  });
}

export function useCollectionItems(
  orgId: string,
  collectionId: string,
  filters: { type?: string; q?: string; includeRemoved: boolean },
) {
  return useInfiniteQuery({
    queryKey: [...caseKeys.collection(orgId, collectionId), "items", filters],
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/ioc-collections/{collection_id}/items", {
          params: {
            path: { org_id: orgId, collection_id: collectionId },
            query: {
              include_removed: filters.includeRemoved,
              ...(filters.type ? { type: filters.type } : {}),
              ...(filters.q ? { q: filters.q } : {}),
              ...(pageParam ? { cursor: pageParam } : {}),
            },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor,
    placeholderData: keepPreviousData,
  });
}

function useCollectionInvalidation(orgId: string, invId: string) {
  const queryClient = useQueryClient();
  return async (collectionId?: string) => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: caseKeys.collections(orgId, invId) }),
      queryClient.invalidateQueries({ queryKey: caseKeys.caseIocs(orgId, invId) }),
      ...(collectionId ? [queryClient.invalidateQueries({ queryKey: caseKeys.collection(orgId, collectionId) })] : []),
    ]);
  };
}

export function useCreateCollection(orgId: string, invId: string) {
  const invalidate = useCollectionInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async (body: { name: string; description: string }) =>
      unwrapCase(
        await api.POST("/api/v1/orgs/{org_id}/investigations/{investigation_id}/ioc-collections", {
          params: { path: { org_id: orgId, investigation_id: invId } },
          body,
        }),
      ),
    onSuccess: async (created) => invalidate(created.id),
  });
}

export function useUpdateCollection(orgId: string, invId: string, collectionId: string) {
  const invalidate = useCollectionInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async (body: { name?: string; description?: string; archived?: boolean }) =>
      unwrapCase(
        await api.PATCH("/api/v1/orgs/{org_id}/ioc-collections/{collection_id}", {
          params: { path: { org_id: orgId, collection_id: collectionId } },
          body,
        }),
      ),
    onSuccess: async () => invalidate(collectionId),
  });
}

export function useAddItems(orgId: string, invId: string) {
  const invalidate = useCollectionInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async ({ collectionId, items }: { collectionId: string; items: (IocItemManual | { ioc_id: string })[] }) =>
      unwrapCase(
        await api.POST("/api/v1/orgs/{org_id}/ioc-collections/{collection_id}/items", {
          params: { path: { org_id: orgId, collection_id: collectionId } },
          body: { items },
        }),
      ),
    onSuccess: async (_out, { collectionId }) => invalidate(collectionId),
  });
}

export function useRemoveItem(orgId: string, invId: string, collectionId: string) {
  const invalidate = useCollectionInvalidation(orgId, invId);
  return useMutation({
    mutationFn: async (itemId: string) =>
      ensureCaseOk(
        await api.DELETE("/api/v1/orgs/{org_id}/ioc-collections/{collection_id}/items/{item_id}", {
          params: { path: { org_id: orgId, collection_id: collectionId, item_id: itemId } },
        }),
      ),
    onSuccess: async () => invalidate(collectionId),
  });
}

/** Downloads a collection export under the server's filename (no blob URL is kept). */
export function useExportCollection(orgId: string) {
  return useMutation({
    mutationFn: async ({
      collectionId,
      name,
      format,
      clearText,
      canWrite,
    }: {
      collectionId: string;
      name: string;
      format: ExportFormat;
      clearText: boolean;
      canWrite: boolean;
    }) =>
      saveDownload(
        await api.GET("/api/v1/orgs/{org_id}/ioc-collections/{collection_id}/export", {
          params: { path: { org_id: orgId, collection_id: collectionId }, query: exportQuery(format, clearText, canWrite) },
          parseAs: "blob",
        }),
        exportFallbackName(name, format),
      ),
  });
}

// ---------------------------------------------------------------------------------------------
// ATT&CK

export function useCaseAttack(orgId: string, invId: string) {
  return useQuery({
    queryKey: caseKeys.attack(orgId, invId),
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/attack", {
          params: { path: { org_id: orgId, investigation_id: invId } },
        }),
      ),
  });
}

export function useAttackSuggestions(orgId: string, invId: string) {
  return useQuery({
    queryKey: [...caseKeys.attack(orgId, invId), "suggestions"],
    queryFn: async () =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/attack/suggestions", {
          params: { path: { org_id: orgId, investigation_id: invId } },
        }),
      ),
  });
}

export function useCreateMapping(orgId: string, invId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: AttackMappingCreate) =>
      unwrapCase(
        await api.POST("/api/v1/orgs/{org_id}/investigations/{investigation_id}/attack", {
          params: { path: { org_id: orgId, investigation_id: invId } },
          body,
        }),
      ),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: caseKeys.attack(orgId, invId) }),
  });
}

export function useUpdateMapping(orgId: string, invId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ mappingId, body }: { mappingId: string; body: AttackMappingUpdate }) =>
      unwrapCase(
        await api.PATCH("/api/v1/orgs/{org_id}/attack-mappings/{mapping_id}", {
          params: { path: { org_id: orgId, mapping_id: mappingId } },
          body,
        }),
      ),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: caseKeys.attack(orgId, invId) }),
  });
}

// ---------------------------------------------------------------------------------------------
// Timeline

export function useCaseTimeline(orgId: string, invId: string, kinds: readonly RefKindName[]) {
  return useInfiniteQuery({
    queryKey: [...caseKeys.timeline(orgId, invId), { kinds }],
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      unwrapCase(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/timeline", {
          params: {
            path: { org_id: orgId, investigation_id: invId },
            query: {
              limit: 100,
              ...(kinds.length > 0 ? { kinds: [...kinds] } : {}),
              ...(pageParam ? { cursor: pageParam } : {}),
            },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor,
    placeholderData: keepPreviousData,
  });
}

export function useExportTimeline(orgId: string, invId: string) {
  return useMutation({
    mutationFn: async ({ format, kinds, caseRef }: { format: "csv" | "json"; kinds: readonly RefKindName[]; caseRef: string }) =>
      saveDownload(
        await api.GET("/api/v1/orgs/{org_id}/investigations/{investigation_id}/timeline/export", {
          params: {
            path: { org_id: orgId, investigation_id: invId },
            query: { format, ...(kinds.length > 0 ? { kinds: [...kinds] } : {}) },
          },
          parseAs: "blob",
        }),
        `${caseRef.replace(/[^A-Za-z0-9-]+/g, "_") || "case"}-timeline.${format}`,
      ),
  });
}
