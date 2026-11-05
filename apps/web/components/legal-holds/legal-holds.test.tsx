import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { LegalHoldBadge } from "@/components/investigations/legal-hold-badge";
import { CaseHoldCardView } from "@/components/legal-holds/case-hold-card";
import { releaseNotice } from "@/components/legal-holds/hold-actions";
import { HoldList } from "@/components/legal-holds/hold-list";
import type { LegalHold } from "@/lib/legal-holds";
import { formatDay } from "@/lib/retention";

const ORG = "11111111-1111-4111-8111-111111111111";
const INV = "22222222-2222-4222-8222-222222222222";
const NOW = Date.parse("2026-11-06T12:00:00Z");

function render(node: ReactElement): string {
  return renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);
}

function hold(over: Partial<LegalHold> = {}): LegalHold {
  return {
    id: "h1",
    scope: "investigation",
    investigation_id: INV,
    case_ref: "CASE-00012",
    reason: "Litigation notice",
    placed_by: "u1",
    placed_by_name: "Alice",
    placed_at: "2026-11-01T12:00:00Z",
    released_by: null,
    released_at: null,
    release_reason: null,
    protects_until: null,
    active: true,
    s3_sync: "pending",
    s3_synced_at: null,
    ...over,
  };
}

const view = (canManage: boolean, holds: LegalHold[], legalHold = holds.length > 0) =>
  render(
    <CaseHoldCardView
      orgId={ORG}
      investigationId={INV}
      legalHold={legalHold}
      holds={holds}
      now={NOW}
      canManage={canManage}
      delayDays={7}
    />,
  );

describe("legal hold badge", () => {
  it("shows only on held cases", () => {
    expect(render(<LegalHoldBadge legalHold={false} />)).toBe("");
    expect(render(<LegalHoldBadge legalHold />)).toContain("Legal hold");
  });
});

describe("case hold card (role gating)", () => {
  it("offers place to org.update only", () => {
    expect(view(true, [], false)).toContain("Place hold");
    expect(view(false, [], false)).not.toContain("Place hold");
    expect(view(false, [], false)).toContain("No legal hold covers this case.");
  });

  it("offers release to org.update only, and no second place while a hold is active", () => {
    const admin = view(true, [hold()]);
    expect(admin).toContain("Release");
    expect(admin).not.toContain("Place hold");
    const viewer = view(false, [hold()]);
    expect(viewer).not.toContain("Release");
    expect(viewer).toContain("Litigation notice");
  });

  it("shows the object-store hold as pending until the worker syncs it", () => {
    expect(view(false, [hold()])).toContain("Object-store hold: pending");
    expect(view(false, [hold({ s3_synced_at: "2026-11-06T12:01:00Z", s3_sync: "synced" })])).toContain(
      "Object-store hold: synced",
    );
  });

  it("mentions an org-wide hold", () => {
    expect(view(false, [hold({ id: "o1", scope: "org", investigation_id: null, case_ref: null })])).toContain(
      "An organization-wide hold also covers this case.",
    );
  });
});

describe("hold list", () => {
  it("shows a released hold as still protecting until the delay passed", () => {
    const released = hold({
      released_at: "2026-11-05T12:00:00Z",
      released_by: "u2",
      release_reason: "Case settled",
      protects_until: "2026-11-12T12:00:00Z",
      active: false,
    });
    const html = render(<HoldList orgId={ORG} holds={[released]} now={NOW} canManage delayDays={7} />);
    expect(html).toContain("Released (still protecting)");
    expect(html).toContain(`protects until ${formatDay("2026-11-12T12:00:00Z")}`);
    expect(html).toContain("Case settled");
    // Released once: no second release.
    expect(html).not.toContain(" Release</button>");
  });

  it("renders hostile reasons and names as text", () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(1)</script>';
    const html = render(
      <HoldList orgId={ORG} holds={[hold({ reason: hostile, placed_by_name: hostile, case_ref: hostile })]} now={NOW} canManage={false} delayDays={7} />,
    );
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
  });

  it("names the protection delay before a release is confirmed (RT1)", () => {
    const until = new Date("2026-11-13T12:00:00Z");
    const text = releaseNotice(until, 7);
    expect(text).toContain("7 more days");
    expect(text).toContain(formatDay(until));
  });
});
