import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  type AiProvider,
  type AiProviderSaved,
  addEntries,
  aiErrorMessage,
  aiKeyErrorMessage,
  aiProviderState,
  aiVerifyErrorText,
  canEnable,
  disclosedCategories,
  fieldErrors,
  formatCostMicros,
  hasErrorCode,
  modelOptionLabel,
  needsPaidTierAck,
  needsPrivacyAck,
  needsTermsAck,
  normalizeCidr,
  normalizeSuffix,
  parseBudget,
  unavailableText,
  usableAiProviders,
  usedPercent,
  visibleAiProviders,
} from "@/lib/ai-settings";
import { ApiError } from "@/lib/api";
import { aiSettingsKeys, storeAiKey } from "@/lib/use-ai-settings";

const SENTINEL = "sk-SENTINEL-0123456789abcdef";

function aiProvider(over: Partial<AiProvider> = {}): AiProvider {
  return {
    name: "anthropic",
    label: "Anthropic Claude",
    models: [
      {
        id: "claude-sonnet-5",
        label: "Claude Sonnet 5",
        price: { input: 2, output: 10, cache_read: 0.2, cache_write: 2.5 },
        verified: true,
      },
      {
        id: "claude-opus-5-5",
        label: "Claude Opus 5.5",
        price: { input: 4, output: 20, cache_read: 0.2, cache_write: 5 },
        verified: false,
      },
    ],
    default_model: "claude-sonnet-5",
    price_version: "2026-11-01",
    tos_note: "Your organization is bound by its own Anthropic Commercial Terms and Usage Policy.",
    privacy_note: "Running an analysis sends evidence excerpts to Anthropic.",
    available: true,
    unavailable_reason: null,
    platform_key: false,
    requires_paid_tier_ack: false,
    configured: true,
    enabled: true,
    model: null,
    key_last4: "wxyz",
    verify_status: "valid",
    verified_at: "2026-11-05T10:00:00Z",
    last_error_code: null,
    terms_ack_at: "2026-11-05T09:00:00Z",
    paid_tier_ack_at: null,
    default_limits: { per_minute: 20 },
    ceilings: { per_minute: 200 },
    limits: null,
    ...over,
  };
}

describe("providers", () => {
  it("shows the mock only when available", () => {
    const items = [aiProvider(), aiProvider({ name: "mock", available: false, unavailable_reason: "prod_mock" })];
    expect(visibleAiProviders(items).map((p) => p.name)).toEqual(["anthropic"]);
    expect(visibleAiProviders([aiProvider({ name: "mock" })]).map((p) => p.name)).toEqual(["mock"]);
  });

  it("usable providers need enabled, a key (own or platform) and availability", () => {
    const items = [
      aiProvider(),
      aiProvider({ name: "gemini", enabled: false }),
      aiProvider({ name: "mock", configured: false, platform_key: true }),
      aiProvider({ name: "gemini", available: false }),
    ];
    expect(usableAiProviders(items).map((p) => p.name)).toEqual(["anthropic", "mock"]);
  });

  it("acknowledgements: terms on first enable, paid tier only for gemini", () => {
    expect(needsTermsAck(aiProvider({ terms_ack_at: null }))).toBe(true);
    expect(needsTermsAck(aiProvider())).toBe(false);
    expect(needsPaidTierAck(aiProvider())).toBe(false);
    expect(needsPaidTierAck(aiProvider({ name: "gemini", requires_paid_tier_ack: true }))).toBe(true);
    expect(
      needsPaidTierAck(aiProvider({ requires_paid_tier_ack: true, paid_tier_ack_at: "2026-11-05T09:00:00Z" })),
    ).toBe(false);
  });

  it("state and enable rules", () => {
    expect(aiProviderState(aiProvider({ configured: false, verify_status: null }))).toBe("not_configured");
    expect(aiProviderState(aiProvider({ configured: false, platform_key: true, verify_status: null }))).toBe(
      "unverified",
    );
    expect(canEnable(aiProvider({ configured: false }))).toBe(false);
    expect(canEnable(aiProvider({ configured: false, platform_key: true }))).toBe(true);
    expect(canEnable(aiProvider({ available: false }))).toBe(false);
  });

  it("explains gemini billing and marks unverified models", () => {
    expect(unavailableText("gemini_billing_required")).toMatch(/training and human review/);
    expect(unavailableText("gemini_billing_required")).toContain("GEMINI_BILLING_ENABLED");
    const [sonnet, opus] = aiProvider().models;
    expect(modelOptionLabel(sonnet)).toBe("Claude Sonnet 5 · $2 / $10 per MTok (in / out)");
    expect(modelOptionLabel(opus)).toMatch(/· unverified$/);
    expect(aiVerifyErrorText("auth_failed")).toBe("The provider rejected the key.");
    expect(aiVerifyErrorText("weird")).toBe("Check failed (weird).");
    expect(aiVerifyErrorText(null)).toBeNull();
  });
});

describe("privacy", () => {
  const current = {
    ai_enabled: true,
    pseudonymize_internal: true,
    include_strings: false,
    include_ti: true,
    include_case_text: false,
  };

  it("re-acknowledgement only when the disclosure widens (RT22)", () => {
    expect(needsPrivacyAck({ ...current, ai_enabled: false }, { ai_enabled: true })).toBe(true);
    expect(needsPrivacyAck(current, { include_strings: true })).toBe(true);
    expect(needsPrivacyAck(current, { include_case_text: true })).toBe(true);
    expect(needsPrivacyAck(current, { pseudonymize_internal: false })).toBe(true);
    expect(needsPrivacyAck(current, { include_ti: false })).toBe(false);
    expect(needsPrivacyAck(current, { include_ti: true })).toBe(false);
    expect(needsPrivacyAck(current, { ai_enabled: false })).toBe(false);
    expect(needsPrivacyAck(current, { daily_token_budget: 5 })).toBe(false);
    expect(needsPrivacyAck({ ...current, include_strings: true }, { include_strings: true })).toBe(false);
  });

  it("lists the categories that leave under the next settings", () => {
    expect(disclosedCategories(current)).toContain("threat intelligence summaries");
    expect(disclosedCategories(current)).not.toContain("the case title and description");
    const wide = disclosedCategories({ ...current, include_case_text: true, include_strings: true, include_ti: false });
    expect(wide).toContain("the case title and description");
    expect(wide).toContain("decoded strings from files");
    expect(wide).not.toContain("threat intelligence summaries");
  });
});

describe("list validators", () => {
  it("CIDRs", () => {
    expect(normalizeCidr("10.0.0.0/8")).toEqual({ value: "10.0.0.0/8" });
    expect(normalizeCidr(" 192.168.1.10 ")).toEqual({ value: "192.168.1.10/32" });
    expect(normalizeCidr("2001:DB8::/32")).toEqual({ value: "2001:db8::/32" });
    expect(normalizeCidr("fd00::1")).toEqual({ value: "fd00::1/128" });
    for (const bad of ["10.0.0.0/33", "256.1.1.1/8", "010.0.0.1/8", "10.0.0/8", "corp", "::g/64", "1.2.3.4/8/9", ""]) {
      expect(normalizeCidr(bad)).toHaveProperty("error");
    }
  });

  it("domain suffixes", () => {
    expect(normalizeSuffix(".Corp.Example.org")).toEqual({ value: "corp.example.org" });
    expect(normalizeSuffix("internal")).toEqual({ value: "internal" });
    expect(normalizeSuffix("bücher.example")).toEqual({ value: "xn--bcher-kva.example" });
    for (const bad of ["a..b", "-bad.example", "10.0.0.1", "host.123", "has space.org", "", "x".repeat(64) + ".org"]) {
      expect(normalizeSuffix(bad)).toHaveProperty("error");
    }
  });

  it("adds pasted entries, deduplicates and reports errors", () => {
    const out = addEntries(["10.0.0.0/8"], "10.0.0.0/8, 172.16.0.0/12\nnope", normalizeCidr);
    expect(out.list).toEqual(["10.0.0.0/8", "172.16.0.0/12"]);
    expect(out.errors).toEqual(['"nope" is not a valid CIDR']);
    const full = Array.from({ length: 50 }, (_, i) => `s${i}.example`);
    expect(addEntries(full, "one.more", normalizeSuffix).errors).toEqual(["At most 50 entries."]);
  });
});

describe("budgets and usage", () => {
  it("parses token counts within the ceiling", () => {
    expect(parseBudget("1,000,000", 20_000_000)).toEqual({ value: 1_000_000, error: null });
    expect(parseBudget("1_000", 20_000)).toEqual({ value: 1000, error: null });
    expect(parseBudget("", 10).error).toBeTruthy();
    expect(parseBudget("1.5", 10).error).toBe("Whole tokens only.");
    expect(parseBudget("0", 10).error).toBe("At least 1 token.");
    expect(parseBudget("200001", 200_000).error).toBe("At most 200,000 (the operator ceiling).");
  });

  it("formats cost estimates and budget share", () => {
    expect(formatCostMicros(0)).toBe("≈ $0");
    expect(formatCostMicros(12_300)).toBe("≈ $0.0123");
    expect(formatCostMicros(2_500_000)).toBe("≈ $2.50");
    expect(usedPercent(250, 1000)).toBe(25);
    expect(usedPercent(5000, 1000)).toBe(100);
  });
});

describe("errors", () => {
  it("maps stable codes and 403", () => {
    for (const code of [
      "terms_not_acknowledged",
      "paid_tier_not_acknowledged",
      "privacy_not_acknowledged",
      "model_not_allowed",
      "provider_unavailable",
      "budget_above_ceiling",
    ]) {
      const text = aiErrorMessage(new ApiError(422, code, "server text"));
      expect(text).not.toBe("server text");
    }
    expect(aiErrorMessage(new ApiError(403, "forbidden", "Forbidden"))).toMatch(/owners and admins/);
    expect(hasErrorCode(new ApiError(422, "budget_above_ceiling", "x"), "budget_above_ceiling")).toBe(true);
    expect(hasErrorCode(new Error("x"), "budget_above_ceiling")).toBe(false);
  });

  it("never shows server validation text for the key form", () => {
    const error = new ApiError(422, "validation_error", `bad ${SENTINEL}`, [{ loc: ["body", "api_key"], msg: SENTINEL }]);
    expect(aiKeyErrorMessage(error)).not.toContain(SENTINEL);
  });

  it("extracts per-field validation messages", () => {
    const error = new ApiError(422, "validation_error", "Request validation failed", [
      { loc: ["body", "internal_cidrs"], msg: "Value error, internal_cidrs[1] is not a valid CIDR", type: "value_error" },
      { loc: ["body", "internal_suffixes"], msg: "Value error, internal_suffixes[0] is not a valid domain suffix" },
    ]);
    expect(fieldErrors(error, "internal_cidrs")).toEqual(["internal_cidrs[1] is not a valid CIDR"]);
    expect(fieldErrors(error, "internal_suffixes")).toHaveLength(1);
    expect(fieldErrors(new Error("x"), "internal_cidrs")).toEqual([]);
  });
});

describe("storeAiKey", () => {
  afterEach(() => vi.restoreAllMocks());

  function saved(): AiProviderSaved {
    return { ...aiProvider({ verify_status: "unverified" }), verify_queued: true };
  }

  function scan(client: QueryClient): string {
    return JSON.stringify([
      client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]),
      client.getMutationCache().getAll().map((m) => m.state),
    ]);
  }

  it("sends the key once, clears the input and keeps it out of every cache and log", async () => {
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const client = new QueryClient();
    client.setQueryData(aiSettingsKeys.providers("o1"), { items: [aiProvider()], total: 1, platform_ai_enabled: true });
    const input = { value: SENTINEL };
    const put = vi.fn(async () => ({ data: saved(), response: new Response(null, { status: 200 }) }));

    const out = await storeAiKey({ orgId: "o1", provider: "anthropic", input, queryClient: client, put });

    expect(put).toHaveBeenCalledTimes(1);
    expect(put).toHaveBeenCalledWith({ orgId: "o1", provider: "anthropic", apiKey: SENTINEL });
    expect(out).toEqual({ verifyQueued: true });
    expect(input.value).toBe("");
    expect(scan(client)).not.toContain(SENTINEL);
    expect(JSON.stringify([log.mock.calls, warn.mock.calls])).not.toContain(SENTINEL);
  });

  it("clears the input when the request fails, and throws the typed error", async () => {
    const client = new QueryClient();
    const input = { value: SENTINEL };
    const put = vi.fn(async () => ({
      error: { error: { code: "invalid_api_key", message: "The key must be 8-256 printable ASCII characters" } },
      response: new Response(null, { status: 422 }),
    }));
    await expect(storeAiKey({ orgId: "o1", provider: "anthropic", input, queryClient: client, put })).rejects.toThrow(
      ApiError,
    );
    expect(input.value).toBe("");
    expect(scan(client)).not.toContain(SENTINEL);
  });

  it("clears the input on a network error", async () => {
    const client = new QueryClient();
    const input = { value: SENTINEL };
    const put = vi.fn(async () => {
      throw new TypeError("network");
    });
    await expect(storeAiKey({ orgId: "o1", provider: "anthropic", input, queryClient: client, put })).rejects.toThrow(
      "network",
    );
    expect(input.value).toBe("");
  });
});
