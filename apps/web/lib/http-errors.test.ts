import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import { apiErrorText, httpErrorText } from "@/lib/http-errors";

describe("http error texts (M7)", () => {
  it("explains the M7 error codes", () => {
    for (const code of [
      "evidence_purged",
      "legal_hold_active",
      "policy_floor",
      "retention_acknowledgement_required",
      "search_query_invalid",
    ]) {
      expect(httpErrorText(code)).toBeTruthy();
    }
  });

  it("returns null for other codes and prototype keys", () => {
    expect(httpErrorText("not_found")).toBeNull();
    expect(httpErrorText("toString")).toBeNull();
    expect(httpErrorText("__proto__")).toBeNull();
  });

  it("reads the code of an ApiError only", () => {
    expect(apiErrorText(new ApiError(410, "evidence_purged", "gone"))).toContain("retention");
    expect(apiErrorText(new Error("evidence_purged"))).toBeNull();
  });
});
