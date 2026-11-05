import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ActiveCounts, OpsMetricsTable, RecentFailures, WindowSelector } from "@/components/ops/ops-metrics";
import type { OrgOpsMetrics, RecentFailure } from "@/lib/ops-metrics";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "44444444-4444-4444-8444-444444444444";

const metrics: OrgOpsMetrics = {
  window: "24h",
  generated_at: "2026-11-06T12:00:00Z",
  active: { pcap: 2, report: 1 },
  items: [
    {
      kind: "pcap",
      subkind: "full",
      total: 40,
      succeeded: 35,
      failed: 5,
      failure_ratio: 0.125,
      parse_success_ratio: 0.9459,
      queue_p50_ms: 850,
      queue_p95_ms: 4200,
      run_p50_ms: 42_000,
      run_p95_ms: 185_000,
      error_classes: { parse: 2, infra: 3 },
    },
    {
      kind: "ai",
      subkind: null,
      total: 0,
      succeeded: 0,
      failed: 0,
      failure_ratio: null,
      parse_success_ratio: null,
      queue_p50_ms: null,
      queue_p95_ms: null,
      run_p50_ms: null,
      run_p95_ms: null,
      error_classes: {},
    },
  ],
};

describe("operations page", () => {
  it("renders the numbers as plain text", () => {
    const html = renderToStaticMarkup(<OpsMetricsTable metrics={metrics} />);
    expect(html).toContain("PCAP analysis · full");
    expect(html).toContain("12.5 %");
    expect(html).toContain("94.6 %");
    expect(html).toContain("42 s / 3 min 05 s");
    expect(html).toContain("850 ms / 4.2 s");
    expect(html).toContain("infra 3, parse 2");
    expect(html).toContain("AI analyst");
    expect(html).not.toContain("<svg");
  });

  it("orders analyzers before AI", () => {
    const html = renderToStaticMarkup(<OpsMetricsTable metrics={metrics} />);
    expect(html.indexOf("PCAP analysis")).toBeLessThan(html.indexOf("AI analyst"));
  });

  it("shows active counts and the window selector", () => {
    expect(renderToStaticMarkup(<ActiveCounts active={metrics.active} />)).toContain("Queued or running now:</span> 3");
    const selector = renderToStaticMarkup(<WindowSelector value="7d" onChange={() => undefined} />);
    expect(selector).toContain("Last 24 hours");
    expect(selector).toMatch(/aria-pressed="true"[^>]*>Last 7 days/);
  });

  it("lists recent failures with their class and a deep link", () => {
    const failure: RecentFailure = {
      job_id: JOB,
      kind: "pcap",
      subkind: null,
      error_code: "unparseable_capture",
      error_class: "parse",
      finished_at: "2026-11-06T11:00:00Z",
      investigation_id: ORG,
      evidence_id: ORG,
      href: `/pcap/${JOB}`,
    };
    const html = renderToStaticMarkup(<RecentFailures orgId={ORG} failures={[failure]} />);
    expect(html).toContain(`href="/o/${ORG}/pcap/${JOB}"`);
    expect(html).toContain("unparseable_capture");
    expect(html).toContain(">parse<");
    expect(renderToStaticMarkup(<RecentFailures orgId={ORG} failures={[]} />)).toContain("No failed analyses.");
  });
});
