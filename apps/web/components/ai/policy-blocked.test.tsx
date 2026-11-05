import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { aiErrorMessage } from "@/components/ai/context-preview-dialog";
import { PolicyBlocked } from "@/components/ai/policy-blocked";
import { ApiError, unwrap } from "@/lib/api";
import { PolicyApiError } from "@/lib/case";
import { tiErrorMessage } from "@/lib/ti";

const ORG = "11111111-1111-4111-8111-111111111111";
const INV = "22222222-2222-4222-8222-222222222222";

function render(node: ReactElement): string {
  return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);
}

describe("PolicyBlocked", () => {
  it("renders nothing for other errors", () => {
    expect(render(<PolicyBlocked orgId={ORG} error={new ApiError(409, "ai_busy", "busy")} investigationId={INV} />)).toBe("");
    expect(render(<PolicyBlocked orgId={ORG} error={new Error("x")} investigationId={INV} />)).toBe("");
  });

  it("shows the reason and links to the case share-policy card", () => {
    const error = new PolicyApiError(new ApiError(409, "policy_blocked", "blocked"), "tlp_red");
    const html = render(<PolicyBlocked orgId={ORG} error={error} investigationId={INV} what="This AI analysis" />);
    expect(html).toContain("This AI analysis is blocked by the share policy.");
    expect(html).toContain("TLP:RED");
    expect(html).toContain(`href="/o/${ORG}/investigations/${INV}#share-policy"`);
  });

  it("names the reason of an error from the shared unwrap (AI / TI wrappers)", () => {
    let error: unknown;
    try {
      unwrap({
        data: undefined,
        error: { error: { code: "policy_blocked", message: "blocked", reason: "evidence_ti_excluded" } },
        response: new Response(null, { status: 409 }),
      });
    } catch (e) {
      error = e;
    }
    const html = render(<PolicyBlocked orgId={ORG} error={error} investigationId={INV} what="This threat-intel enrichment" />);
    expect(html).toContain("An evidence item of this scope is marked");
    expect(aiErrorMessage(error)).toContain("An evidence item of this scope");
    expect(tiErrorMessage(error)).toContain("An evidence item of this scope");
    expect(tiErrorMessage(new ApiError(409, "policy_blocked", "x"))).toContain("does not allow sending these indicators");
  });

  it("falls back to a generic reason without one", () => {
    const html = render(<PolicyBlocked orgId={ORG} error={new ApiError(409, "policy_blocked", "x")} />);
    expect(html).toContain("does not allow this");
    expect(html).not.toContain("href=");
  });

  it("works from a known policy reason without an error", () => {
    const html = render(<PolicyBlocked orgId={ORG} reason="case_ai_excluded" investigationId={INV} />);
    expect(html).toContain("do not send to AI");
  });
});
