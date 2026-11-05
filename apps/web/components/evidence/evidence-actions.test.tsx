import { describe, expect, it } from "vitest";

import { actionErrorText } from "@/components/evidence/evidence-actions";
import { ApiError } from "@/lib/api";
import { HTTP_ERROR_TEXT } from "@/lib/http-errors";

describe("evidence action error text", () => {
  it("explains a 410 evidence_purged instead of the raw server message", () => {
    const text = actionErrorText(new ApiError(410, "evidence_purged", "gone"));
    expect(text).toBe(HTTP_ERROR_TEXT.evidence_purged);
    expect(text).not.toBe("gone");
  });

  it("falls back to the server message for other API errors", () => {
    expect(actionErrorText(new ApiError(404, "not_found", "Evidence not found"))).toBe("Evidence not found");
  });

  it("uses the generic message for non-API errors", () => {
    expect(actionErrorText(new Error("boom"))).toBe("Something went wrong. Please try again.");
  });
});
