import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { CaseTlpCard } from "@/components/investigations/case-tlp-card";
import { SharePolicyCard, ShareToggles } from "@/components/investigations/share-policy-card";
import { StatusEventList } from "@/components/investigations/status-history";

const noop = () => undefined;

function inputs(html: string): string[] {
  return [...html.matchAll(/<input[^>]*>/g)].map((m) => m[0]);
}

describe("share-policy toggles (role matrix)", () => {
  const flags = { ai_excluded: true, ti_excluded: false };

  it("viewer: every toggle disabled", () => {
    const html = renderToStaticMarkup(<ShareToggles flags={flags} tlpRed={false} canTurnOn={false} canTurnOff={false} onChange={noop} />);
    expect(inputs(html).every((i) => i.includes('disabled=""'))).toBe(true);
    expect(html).toContain("integrations.manage");
  });

  it("analyst: can turn the TI flag on, cannot turn the AI flag off (reason shown)", () => {
    const html = renderToStaticMarkup(<ShareToggles flags={flags} tlpRed={false} canTurnOn canTurnOff={false} onChange={noop} />);
    const [ai, ti] = inputs(html);
    expect(ai).toContain('disabled=""');
    expect(ai).toContain('checked=""');
    expect(ti).not.toContain('disabled=""');
    expect(html).toContain("Only an admin (integrations.manage) can turn an exclusion off.");
  });

  it("admin: both toggles enabled", () => {
    const html = renderToStaticMarkup(<ShareToggles flags={flags} tlpRed={false} canTurnOn canTurnOff onChange={noop} />);
    expect(inputs(html).some((i) => i.includes('disabled=""'))).toBe(false);
  });

  it("TLP:RED forces both on with an explanation", () => {
    const html = renderToStaticMarkup(
      <ShareToggles flags={{ ai_excluded: false, ti_excluded: false }} tlpRed canTurnOn canTurnOff onChange={noop} />,
    );
    const both = inputs(html);
    expect(both).toHaveLength(2);
    expect(both.every((i) => i.includes('checked=""') && i.includes('disabled=""'))).toBe(true);
    expect(html).toContain("Forced on by TLP:RED");
  });

  it("the card is the share-policy anchor and shows the computed reasons", () => {
    const html = renderToStaticMarkup(
      <SharePolicyCard
        flags={{ ai_excluded: false, ti_excluded: true }}
        policy={{ ai_blocked: false, ti_blocked: true, reasons: ["case_ti_excluded"] }}
        tlpRed={false}
        canTurnOn
        canTurnOff
        readOnly={false}
        pending={false}
        onChange={noop}
      />,
    );
    expect(html).toContain('id="share-policy"');
    expect(html).toContain("Nothing from this case is sent to threat-intel providers.");
  });
});

describe("TLP card", () => {
  it("always shows the label text next to the colour", () => {
    const html = renderToStaticMarkup(<CaseTlpCard tlp="amber" canWrite={false} canDowngrade={false} pending={false} onSave={noop} />);
    expect(html).toContain("TLP:AMBER");
    expect(html).toContain("Your role cannot change the TLP");
  });

  it("disables less restrictive labels without org.update", () => {
    const html = renderToStaticMarkup(<CaseTlpCard tlp="amber" canWrite canDowngrade={false} pending={false} onSave={noop} />);
    expect(html).toMatch(/<option value="green" disabled="">/);
    expect(html).toMatch(/<option value="red">/);
    const admin = renderToStaticMarkup(<CaseTlpCard tlp="amber" canWrite canDowngrade pending={false} onSave={noop} />);
    expect(admin).toMatch(/<option value="green">/);
  });
});

describe("status history", () => {
  it("renders reasons as text", () => {
    const html = renderToStaticMarkup(
      <StatusEventList
        events={[
          {
            id: "e1",
            actor_id: "u1",
            actor_name: "Alice",
            from_status: "in_progress",
            to_status: "closed",
            occurred_at: "2026-11-05T10:00:00Z",
            reason: `contained <img src=x onerror=alert(1)> ‮ok`,
          },
        ]}
      />,
    );
    expect(html).toContain("In progress → Closed");
    expect(html).not.toContain("<img");
    expect(html).toContain("⟨U+202E⟩");
  });
});
