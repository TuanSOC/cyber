import { ApiError } from "@/lib/api";

/**
 * Plain-language messages for API error codes the UI explains instead of showing the server
 * message (M7). Phases 8 and 9 use them; new codes are added here by the parent only.
 */
export const HTTP_ERROR_TEXT: Readonly<Record<string, string>> = {
  evidence_purged:
    "The evidence bytes were deleted by the retention policy. Its hashes and chain of custody are kept.",
  legal_hold_active: "A legal hold covers this data, so it cannot be changed or deleted.",
  policy_floor: "A retention period is below the minimum this platform allows.",
  retention_acknowledgement_required:
    "Enforcing retention deletes data. Confirm that you understand before turning it on.",
  search_query_invalid: "Search terms must be 2 to 256 characters long.",
};

/** The message for an error code, or null when the code has no specific text. */
export function httpErrorText(code: string): string | null {
  return Object.hasOwn(HTTP_ERROR_TEXT, code) ? HTTP_ERROR_TEXT[code] : null;
}

/** `httpErrorText` for an `ApiError`, else null. */
export function apiErrorText(error: unknown): string | null {
  return error instanceof ApiError ? httpErrorText(error.code) : null;
}
