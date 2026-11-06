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
  // M8: memory forensics.
  memory_image_too_large: "The memory image is larger than this platform accepts.",
  memory_image_empty: "An empty file cannot be analyzed as a memory image.",
  memory_sensitivity_restricted:
    "This evidence is a restricted memory image. An administrator must release it before AI or threat-intel use is allowed.",
  memory_sensitivity_released: "This memory evidence was already released.",
  acknowledgement_required: "Confirm that you understand what releasing this memory image allows.",
  insufficient_storage: "The platform does not have enough free space for this upload right now. Try again later.",
};

/** The message for an error code, or null when the code has no specific text. */
export function httpErrorText(code: string): string | null {
  return Object.hasOwn(HTTP_ERROR_TEXT, code) ? HTTP_ERROR_TEXT[code] : null;
}

/** `httpErrorText` for an `ApiError`, else null. */
export function apiErrorText(error: unknown): string | null {
  return error instanceof ApiError ? httpErrorText(error.code) : null;
}
