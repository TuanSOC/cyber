import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { IntegrationCard, KeyForm } from "@/components/ti/integration-card";
import { TermsAckForm } from "@/components/ti/terms-ack";
import type { Integration } from "@/lib/ti";

const SENTINEL = "SENTINEL-KEY-0123456789abcd";

function render(node: ReactElement): string {
  const client = new QueryClient();
  return renderToStaticMarkup(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function integration(over: Partial<Integration> = {}): Integration {
  return {
    name: "virustotal",
    label: "VirusTotal",
    supported_types: ["ipv4", "domain", "sha256"],
    tos_note: "The VirusTotal public API must not be used in commercial products.",
    privacy_note: "Every enabled lookup tells VirusTotal which indicators your organization is investigating.",
    needs_base_url: false,
    default_limits: { per_minute: 4, per_day: 500 },
    ceilings: { per_minute: 4, per_day: 500 },
    available: true,
    configured: true,
    enabled: true,
    key_last4: "abcd",
    verify_status: "valid",
    verified_at: "2026-11-05T10:00:00Z",
    last_error_code: null,
    terms_ack_at: "2026-11-05T09:00:00Z",
    base_url: null,
    limits: null,
    ...over,
  };
}

describe("IntegrationCard", () => {
  it("shows the key only as ••••last4 and never renders a key value", () => {
    // Even if a response ever carried a key field, the card must not render it.
    const leaky = { ...integration(), api_key: SENTINEL } as Integration;
    const html = render(<IntegrationCard orgId="o1" integration={leaky} canManage />);
    expect(html).toContain("••••abcd");
    expect(html).not.toContain(SENTINEL);
    expect(html).toContain("terms acknowledged on");
  });

  it("uses a write-only, empty password input with autocomplete off", () => {
    const html = render(<IntegrationCard orgId="o1" integration={integration()} canManage />);
    const input = html.match(/<input[^>]*id="key-virustotal"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('type="password"');
    expect(input).toMatch(/autocomplete="off"/i);
    expect(input).not.toMatch(/value="[^"]+"/);
    expect(html).toContain("Replace key");
    expect(html).toContain("Remove key");
    expect(html).toContain("Verify");
  });

  it("is read-only without integrations.manage", () => {
    const html = render(<IntegrationCard orgId="o1" integration={integration()} canManage={false} />);
    expect(html).not.toMatch(/<input/);
    expect(html).not.toMatch(/<button/);
    expect(html).not.toContain("Replace key");
    expect(html).toContain("••••abcd");
  });

  it("shows invalid · misp_url_not_public for a MISP host that is not public", () => {
    const html = render(
      <IntegrationCard
        orgId="o1"
        integration={integration({
          name: "misp",
          label: "MISP",
          needs_base_url: true,
          base_url: "https://misp.example.org",
          verify_status: "invalid",
          last_error_code: "misp_url_not_public",
        })}
        canManage
      />,
    );
    expect(html).toContain("invalid · misp_url_not_public");
    expect(html).toContain('id="url-misp"');
  });

  it("does not pre-fill the key field of an unconfigured provider", () => {
    const html = render(
      <KeyForm
        orgId="o1"
        integration={{ name: "otx", configured: false, needs_base_url: false, base_url: null, verified_at: null }}
        onSaved={() => undefined}
      />,
    );
    const input = html.match(/<input[^>]*id="key-otx"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('type="password"');
    expect(input).toMatch(/autocomplete="off"/i);
    expect(input).not.toMatch(/value="[^"]+"/);
    expect(html).toContain("Save key");
  });
});

describe("TermsAckForm", () => {
  const props = {
    integration: integration({ terms_ack_at: null, enabled: false }),
    onCheckedChange: () => undefined,
    onConfirm: () => undefined,
    onCancel: () => undefined,
    pending: false,
  };

  it("blocks enabling until the acknowledgement is ticked", () => {
    const html = render(<TermsAckForm {...props} checked={false} />);
    const button = html.match(/<button[^>]*data-testid="ack-enable"[^>]*>/)?.[0] ?? "";
    expect(button).toMatch(/\sdisabled(=""|\s|>)/);
    expect(html).toContain(props.integration.tos_note);
    expect(html).toContain('rel="noopener noreferrer"');
  });

  it("allows enabling once ticked", () => {
    const html = render(<TermsAckForm {...props} checked />);
    const button = html.match(/<button[^>]*data-testid="ack-enable"[^>]*>/)?.[0] ?? "";
    expect(button).not.toMatch(/\sdisabled(=""|\s|>)/);
  });
});
