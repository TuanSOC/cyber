import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AiOrgSettingsPanel, BudgetsForm } from "@/components/ai-settings/ai-org-settings-card";
import { AiPrivacyAckForm } from "@/components/ai-settings/ai-privacy-ack";
import { AiKeyForm, AiProviderCard } from "@/components/ai-settings/ai-provider-card";
import { AiTermsAckForm } from "@/components/ai-settings/ai-terms-ack";
import { AiUsageView } from "@/components/ai-settings/ai-usage";
import type { AiProvider, AiSettings, AiUsage } from "@/lib/ai-settings";

const SENTINEL = "sk-SENTINEL-0123456789abcdef";

function render(node: ReactElement): string {
  const client = new QueryClient();
  return renderToStaticMarkup(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function provider(over: Partial<AiProvider> = {}): AiProvider {
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

function gemini(over: Partial<AiProvider> = {}): AiProvider {
  return provider({
    name: "gemini",
    label: "Google Gemini",
    models: [
      {
        id: "gemini-3.8-flash",
        label: "Gemini 3.8 Flash",
        price: { input: 1.5, output: 7.5, cache_read: 0.375, cache_write: 1.5 },
        verified: false,
      },
    ],
    default_model: "gemini-3.8-flash",
    requires_paid_tier_ack: true,
    ...over,
  });
}

function settings(over: Partial<AiSettings> = {}): AiSettings {
  return {
    ai_enabled: false,
    platform_ai_enabled: true,
    privacy_ack_at: null,
    privacy_ack_by: null,
    default_provider: null,
    pseudonymize_internal: true,
    internal_cidrs: ["10.20.0.0/16"],
    internal_suffixes: ["corp.example.org"],
    include_strings: false,
    include_ti: true,
    include_case_text: false,
    daily_token_budget: 1_000_000,
    run_token_cap: 100_000,
    incident_token_cap: 600_000,
    ceilings: { daily_token_budget: 20_000_000, run_token_cap: 200_000, incident_token_cap: 2_000_000 },
    privacy_notice: "When AI analysis is on, running an analysis sends evidence excerpts.",
    updated_at: "2026-11-05T09:00:00Z",
    ...over,
  };
}

const button = (html: string, testId: string) =>
  html.match(new RegExp(`<button[^>]*data-testid="${testId}"[^>]*>`))?.[0] ?? "";
const isDisabled = (tag: string) => /\sdisabled(=""|\s|>)/.test(tag);

describe("AiProviderCard", () => {
  it("shows the key only as configured · ••••last4 and never renders a key value", () => {
    // Even if a response ever carried a key field, the card must not render it.
    const leaky = { ...provider(), api_key: SENTINEL } as AiProvider;
    const html = render(<AiProviderCard orgId="o1" provider={leaky} canManage />);
    expect(html).toContain("configured · ••••wxyz");
    expect(html).not.toContain(SENTINEL);
    expect(html).toContain("Replace key");
    expect(html).toContain("Remove key");
    expect(html).toContain("Verify");
  });

  it("uses a write-only, empty password input with autocomplete off", () => {
    const html = render(<AiProviderCard orgId="o1" provider={provider()} canManage />);
    const input = html.match(/<input[^>]*id="ai-key-anthropic"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('type="password"');
    expect(input).toMatch(/autocomplete="off"/i);
    expect(input).not.toMatch(/value="[^"]+"/);
  });

  it("does not pre-fill the key field of an unconfigured provider", () => {
    const html = render(
      <AiKeyForm orgId="o1" provider={{ name: "anthropic", configured: false }} onSaved={() => undefined} />,
    );
    const input = html.match(/<input[^>]*id="ai-key-anthropic"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('type="password"');
    expect(input).not.toMatch(/value="[^"]+"/);
    expect(html).toContain("Save key");
  });

  it("is read-only without integrations.manage", () => {
    const html = render(<AiProviderCard orgId="o1" provider={provider()} canManage={false} />);
    expect(html).not.toMatch(/<input/);
    expect(html).not.toMatch(/<button/);
    expect(html).not.toContain("Replace key");
    expect(html).toContain("configured · ••••wxyz");
    expect(html).toContain("Claude Sonnet 5");
  });

  it("shows the request limit with its maximum; admins may set their own", () => {
    const readOnly = render(<AiProviderCard orgId="o1" provider={provider()} canManage={false} />);
    expect(readOnly).toContain("20 / minute");
    expect(readOnly).toContain("(maximum 200)");
    expect(readOnly).not.toContain("Requests per minute");
    const own = render(
      <AiProviderCard orgId="o1" provider={provider({ limits: { per_minute: 5 } })} canManage />,
    );
    expect(own).toContain("5 / minute");
    expect(own).toContain("own limit");
    const input = own.match(/<input[^>]*id="ai-limit-anthropic"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('value="5"');
    expect(own).toContain("Save limit");
  });

  it("shows the model with prices and marks unverified ids", () => {
    const html = render(<AiProviderCard orgId="o1" provider={provider({ model: "claude-opus-5-5" })} canManage={false} />);
    expect(html).toContain("Claude Opus 5.5 · $4 / $20 per MTok (in / out) · unverified");
  });

  it("maps the last error code and shows the platform dev key badge", () => {
    const html = render(
      <AiProviderCard
        orgId="o1"
        provider={provider({
          configured: false,
          key_last4: null,
          platform_key: true,
          verify_status: "invalid",
          last_error_code: "auth_failed",
        })}
        canManage={false}
      />,
    );
    expect(html).toContain("Platform dev key in use");
    expect(html).toContain("invalid · auth_failed");
    expect(html).toContain("The provider rejected the key.");
  });

  it("Gemini without billing: prominent explanation and no controls, even for admins", () => {
    const html = render(
      <AiProviderCard
        orgId="o1"
        provider={gemini({
          available: false,
          unavailable_reason: "gemini_billing_required",
          configured: false,
          enabled: false,
          key_last4: null,
          verify_status: null,
          terms_ack_at: null,
        })}
        canManage
      />,
    );
    expect(html).toMatch(/training and human review/);
    expect(html).toContain("GEMINI_BILLING_ENABLED");
    expect(html).toContain('role="alert"');
    expect(html).not.toMatch(/<input/);
    expect(html).not.toMatch(/<button/);
    expect(html).toContain("not attested yet");
  });
});

describe("AiTermsAckForm", () => {
  const base = { onAckChange: () => undefined, onConfirm: () => undefined, onCancel: () => undefined, pending: false };

  it("blocks enabling until the terms are acknowledged", () => {
    const p = provider({ terms_ack_at: null, enabled: false });
    const off = render(<AiTermsAckForm {...base} provider={p} ack={{ terms: false, paidTier: false }} />);
    expect(isDisabled(button(off, "ai-ack-enable"))).toBe(true);
    expect(off).toContain(p.tos_note);
    expect(off).toContain('rel="noopener noreferrer"');
    expect(off).not.toContain("paid tier");
    const on = render(<AiTermsAckForm {...base} provider={p} ack={{ terms: true, paidTier: false }} />);
    expect(isDisabled(button(on, "ai-ack-enable"))).toBe(false);
  });

  it("Gemini also needs the paid-tier attestation (RT5)", () => {
    const p = gemini({ terms_ack_at: null, enabled: false });
    const termsOnly = render(<AiTermsAckForm {...base} provider={p} ack={{ terms: true, paidTier: false }} />);
    expect(termsOnly).toContain("This key belongs to a Google Cloud project with billing enabled (paid tier)");
    expect(isDisabled(button(termsOnly, "ai-ack-enable"))).toBe(true);
    const both = render(<AiTermsAckForm {...base} provider={p} ack={{ terms: true, paidTier: true }} />);
    expect(isDisabled(button(both, "ai-ack-enable"))).toBe(false);
  });

  it("asks only for what is still missing", () => {
    const p = gemini({ terms_ack_at: "2026-11-05T09:00:00Z", enabled: false });
    const html = render(<AiTermsAckForm {...base} provider={p} ack={{ terms: false, paidTier: false }} />);
    expect(html).not.toContain('id="ai-ack-terms-gemini"');
    expect(html).toContain('id="ai-ack-paid-gemini"');
    expect(isDisabled(button(html, "ai-ack-enable"))).toBe(true);
  });
});

describe("AiPrivacyAckForm", () => {
  const props = {
    notice: "When AI analysis is on, running an analysis sends evidence excerpts.",
    onCheckedChange: () => undefined,
    onConfirm: () => undefined,
    onCancel: () => undefined,
    pending: false,
    confirmLabel: "Acknowledge and turn on",
  };
  const next = { pseudonymize_internal: true, include_strings: false, include_ti: true, include_case_text: false };

  it("blocks enabling until the privacy notice is acknowledged", () => {
    const off = render(<AiPrivacyAckForm {...props} next={next} checked={false} />);
    expect(isDisabled(button(off, "ai-privacy-confirm"))).toBe(true);
    expect(off).toContain("IP addresses");
    expect(off).toContain("URLs (query values replaced)");
    expect(off).toContain("threat intelligence summaries");
    expect(off).not.toContain("the case title and description");
    expect(off).toContain(props.notice);
    const on = render(<AiPrivacyAckForm {...props} next={next} checked />);
    expect(isDisabled(button(on, "ai-privacy-confirm"))).toBe(false);
  });

  it("states the widened disclosure", () => {
    const html = render(
      <AiPrivacyAckForm
        {...props}
        next={{ ...next, pseudonymize_internal: false, include_case_text: true }}
        checked={false}
      />,
    );
    expect(html).toContain("the case title and description");
    expect(html).toContain("Pseudonymization is off");
  });
});

describe("AiOrgSettingsPanel", () => {
  it("is read-only for analysts and viewers", () => {
    const html = render(
      <AiOrgSettingsPanel
        orgId="o1"
        settings={settings({ ai_enabled: true, privacy_ack_at: "2026-11-05T09:00:00Z" })}
        canManage={false}
        providers={[provider()]}
      />,
    );
    expect(html).not.toMatch(/<input/);
    expect(html).not.toMatch(/<button/);
    expect(html).toContain("On: analysts can run AI analyses.");
    expect(html).toContain("Privacy notice acknowledged on");
    expect(html).toContain("10.20.0.0/16");
    expect(html).toContain("corp.example.org");
    expect(html).toContain("1,000,000 tokens");
    expect(html).toContain("(maximum 20,000,000)");
  });

  it("is off by default with the defaults for an admin; no refusal-fallback toggle", () => {
    const html = render(<AiOrgSettingsPanel orgId="o1" settings={settings()} canManage providers={[provider()]} />);
    expect(html).toContain("Off: no evidence is sent to any AI provider.");
    expect(html).toContain("Turn on AI analysis…");
    const checkbox = (key: string) => html.match(new RegExp(`<input[^>]*id="ai-${key}"[^>]*>`))?.[0] ?? "";
    expect(checkbox("pseudonymize_internal")).toMatch(/checked/);
    expect(checkbox("include_ti")).toMatch(/checked/);
    expect(checkbox("include_strings")).not.toMatch(/checked/);
    expect(checkbox("include_case_text")).not.toMatch(/checked/);
    expect(html).not.toMatch(/fallback/i);
    expect(html).toContain("The privacy notice has not been acknowledged yet.");
  });

  it("cannot turn AI on when the deployment has it off", () => {
    const html = render(
      <AiOrgSettingsPanel orgId="o1" settings={settings({ platform_ai_enabled: false })} canManage providers={[]} />,
    );
    const turnOn = html.match(/<button[^>]*>Turn on AI analysis…<\/button>/)?.[0] ?? "";
    expect(isDisabled(turnOn)).toBe(true);
  });
});

describe("BudgetsForm", () => {
  it("shows the ceilings and blocks a budget above them", () => {
    const html = render(<BudgetsForm orgId="o1" settings={settings({ run_token_cap: 300_000 })} />);
    expect(html).toContain("maximum 200,000");
    expect(html).toContain("At most 200,000 (the operator ceiling).");
    const save = html.match(/<button[^>]*type="submit"[^>]*>/)?.[0] ?? "";
    expect(isDisabled(save)).toBe(true);
  });
});

describe("AiUsageView", () => {
  it("shows today's tokens and estimated cost per provider vs the budget", () => {
    const usage: AiUsage = {
      day: "2026-11-05",
      total_tokens: 250_000,
      cost_micros: 1_234_000,
      daily_token_budget: 1_000_000,
      remaining_tokens: 750_000,
      run_token_cap: 100_000,
      incident_token_cap: 600_000,
      ceilings: { daily_token_budget: 20_000_000, run_token_cap: 200_000, incident_token_cap: 2_000_000 },
      providers: [
        {
          provider: "anthropic",
          runs: 3,
          cost_micros: 1_234_000,
          usage: {
            input_tokens: 200_000,
            output_tokens: 50_000,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            total_tokens: 250_000,
          },
        },
      ],
    };
    const html = render(<AiUsageView usage={usage} providers={[provider()]} />);
    expect(html).toContain("250,000");
    expect(html).toContain("1,000,000");
    expect(html).toContain("750,000 left");
    expect(html).toContain("Anthropic Claude");
    expect(html).toContain("≈ $1.23");
    expect(html).toContain('aria-valuenow="25"');
  });
});
