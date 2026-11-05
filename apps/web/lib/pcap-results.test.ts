import { describe, expect, it } from "vitest";

import {
  REF_TABS,
  alertSeverity,
  citedQuery,
  parseRowRef,
  attributeText,
  detailList,
  detailText,
  endpointText,
  engineErrorText,
  findingCount,
  flowLinkFor,
  formatCount,
  formatPercent,
  parseIpFilter,
  parseOverview,
  parsePortFilter,
  parseTab,
  protocolTree,
  recordFields,
  searchTerm,
  truncationText,
  withParams,
} from "./pcap-results";

describe("engine errors and truncation", () => {
  it.each([
    ["capture_cut_short", /cut short/],
    ["zeek_cut_short", /Zeek stopped/],
    ["tshark_failed", /protocol hierarchy is missing/],
    ["tshark_timeout", /did not finish in time/],
    ["suricata_failed", /alerts .* missing/],
    ["suricata_timeout", /did not finish in time/],
    ["suricata_skipped", /skipped/],
  ])("%s has human text", (code, text) => {
    expect(engineErrorText(code)).toMatch(text);
  });

  it("shows unknown codes verbatim and ignores prototype keys", () => {
    expect(engineErrorText("brand_new")).toBe("An analysis engine reported a problem (brand_new).");
    expect(engineErrorText("constructor")).toBe("An analysis engine reported a problem (constructor).");
  });

  it("describes capped kinds", () => {
    expect(truncationText("flows")).toBe("Results are partial: flows (only the largest flows were kept) capped.");
    expect(truncationText("iocs")).toBe("Results are partial: IOCs capped.");
    expect(truncationText("odd_key")).toBe("Results are partial: odd_key capped.");
    expect(truncationText("toString")).toBe("Results are partial: toString capped.");
  });
});

const SUMMARY = {
  schema_version: "pcap.v1",
  capture_format: "pcapng",
  tool_versions: { zeek: "8.0.10", rules_sha256: "ab".repeat(32), bad: { x: 1 } },
  engine_errors: ["suricata_timeout", 7, ""],
  truncated: { flows: true, dns: false, iocs: true, weird: "yes" },
  capture: {
    packets: 1200,
    bytes: 987654,
    first_ts: "2026-11-04T10:00:00Z",
    last_ts: "2026-11-04T10:05:00Z",
    duration_s: 300.5,
    link_type: "Ethernet",
    protocol_hierarchy: [
      { path: "eth", frames: 1200, bytes: 987654 },
      { path: "eth:ip", frames: 1100, bytes: 900000 },
      { path: "eth:ip:udp", frames: 100, bytes: 10000 },
      { path: "eth:ip:tcp", frames: 1000, bytes: 890000 },
      { path: "eth:ip:tcp:tls", frames: 50, bytes: 60000 },
      { path: "bad", frames: "many", bytes: 1 },
    ],
    top_sources: [{ ip: "10.0.0.5", bytes: 10, packets: 2, flows: 1 }, { bytes: 3 }],
    top_destinations: "nope",
    top_ports: [{ port: 443, proto: "tcp", flows: 9, bytes: 99 }],
  },
  engine_counts: { flows: 999999, findings: 999 },
  counts: { flows: 40, findings: 3, alerts: 0, dns: 12 },
};

describe("parseOverview", () => {
  const o = parseOverview(SUMMARY);

  it("extracts capture facts", () => {
    expect(o.capture).toEqual({
      packets: 1200,
      bytes: 987654,
      firstTs: "2026-11-04T10:00:00Z",
      lastTs: "2026-11-04T10:05:00Z",
      durationS: 300.5,
      linkType: "Ethernet",
    });
    expect(o.captureFormat).toBe("pcapng");
    expect(o.schemaVersion).toBe("pcap.v1");
  });

  it("keeps only well-formed rows", () => {
    expect(o.hierarchy.map((p) => p.path)).toEqual(["eth", "eth:ip", "eth:ip:udp", "eth:ip:tcp", "eth:ip:tcp:tls"]);
    expect(o.topSources).toEqual([{ ip: "10.0.0.5", bytes: 10, packets: 2, flows: 1 }]);
    expect(o.topDestinations).toEqual([]);
    expect(o.topPorts).toEqual([{ port: 443, proto: "tcp", flows: 9, bytes: 99 }]);
    expect(o.engineErrors).toEqual(["suricata_timeout"]);
    expect(o.truncated).toEqual(["flows", "iocs"]);
    expect(o.toolVersions).toEqual([
      ["zeek", "8.0.10"],
      ["rules_sha256", "ab".repeat(32)],
    ]);
  });

  it("counts stored rows from summary.counts, never the analyzer's engine_counts", () => {
    expect(o.counts).toEqual([
      { key: "findings", label: "Findings", stored: 3 },
      { key: "alerts", label: "Alerts", stored: 0 },
      { key: "flows", label: "Flows", stored: 40 },
      { key: "dns", label: "DNS records", stored: 12 },
    ]);
  });

  it("survives an empty or malformed summary", () => {
    const empty = parseOverview(null);
    expect(empty.capture).toBeNull();
    expect(empty.hierarchy).toEqual([]);
    expect(empty.counts).toEqual([]);
    expect(parseOverview({ capture: [], counts: "x", truncated: [] }).truncated).toEqual([]);
  });

  it("reads the finding count", () => {
    expect(findingCount(SUMMARY)).toBe(3);
    expect(findingCount({})).toBeNull();
    expect(findingCount({ counts: { findings: "3" } })).toBeNull();
  });
});

describe("protocolTree", () => {
  it("builds an indented depth-first list sorted by bytes", () => {
    const tree = protocolTree(parseOverview(SUMMARY).hierarchy);
    expect(tree.map((n) => [n.label, n.depth])).toEqual([
      ["eth", 0],
      ["ip", 1],
      ["tcp", 2],
      ["tls", 3],
      ["udp", 2],
    ]);
    expect(tree[0].share).toBe(1);
    expect(tree[4].share).toBeCloseTo(10000 / 987654);
  });

  it("attaches orphans to the nearest ancestor and drops duplicates", () => {
    const tree = protocolTree([
      { path: "eth", frames: 2, bytes: 100 },
      { path: "eth:ip:tcp", frames: 1, bytes: 50 },
      { path: "eth:ip:tcp", frames: 9, bytes: 999 },
      { path: "sll:ip", frames: 1, bytes: 0 },
    ]);
    expect(tree.map((n) => [n.path, n.depth, n.share])).toEqual([
      ["eth", 0, 1],
      ["eth:ip:tcp", 1, 0.5],
      ["sll:ip", 0, 0],
    ]);
    expect(protocolTree([])).toEqual([]);
  });
});

describe("record details", () => {
  it("formats DNS details", () => {
    expect(
      recordFields("dns", { query: "example.test", qtype: "A", rcode: "NOERROR", answers: ["1.2.3.4", 5], ttls: [] }),
    ).toEqual([
      { key: "query", label: "Query", value: "example.test" },
      { key: "qtype", label: "Type", value: "A" },
      { key: "rcode", label: "Response code", value: "NOERROR" },
      { key: "answers", label: "Answers", value: "1.2.3.4, 5" },
    ]);
  });

  it("formats HTTP details and keeps hostile text as plain strings", () => {
    const fields = recordFields("http", {
      method: "GET",
      host: "evil.test",
      uri: "javascript:alert(1)",
      status_code: 200,
      user_agent: "<script>x</script>",
      resp_mime_types: ["application/x-dosexec"],
      response_body_len: 2048,
      referrer: null,
    });
    expect(Object.fromEntries(fields.map((f) => [f.key, f.value]))).toEqual({
      method: "GET",
      host: "evil.test",
      uri: "javascript:alert(1)",
      status_code: "200",
      user_agent: "<script>x</script>",
      resp_mime_types: "application/x-dosexec",
      response_body_len: "2,048 B",
    });
  });

  it("formats TLS details with flags, dates and fingerprints", () => {
    const fields = recordFields("tls", {
      version: "TLSv10",
      server_name: "a.test",
      established: true,
      ja3: "abc",
      cert_not_after: "2020-01-01T00:00:00Z",
      self_signed: false,
      validation_status: "self signed certificate",
    });
    expect(fields).toEqual([
      { key: "version", label: "Version", value: "TLSv10" },
      { key: "server_name", label: "Server name (SNI)", value: "a.test" },
      { key: "established", label: "Established", value: "yes" },
      { key: "ja3", label: "JA3", value: "abc", format: "mono" },
      { key: "cert_not_after", label: "Valid until", value: "2020-01-01T00:00:00Z", format: "date" },
      { key: "validation_status", label: "Validation", value: "self signed certificate" },
      { key: "self_signed", label: "Self-signed", value: "no" },
    ]);
  });

  it("tolerates malformed details", () => {
    expect(recordFields("dns", null)).toEqual([]);
    expect(recordFields("tls", ["x"])).toEqual([]);
    expect(detailText({ a: { b: 1 } }, "a")).toBeNull();
    expect(detailText({ a: "" }, "a")).toBeNull();
    expect(detailList({ a: "x" }, "a")).toEqual([]);
  });
});

describe("formatting", () => {
  it.each([
    ["10.0.0.1", 443, "10.0.0.1:443"],
    ["2001:db8::1", 53, "[2001:db8::1]:53"],
    ["10.0.0.1", null, "10.0.0.1"],
    [null, 80, "?:80"],
  ] as const)("endpointText(%s, %s) = %s", (ip, port, expected) => {
    expect(endpointText(ip, port)).toBe(expected);
  });

  it("formats attributes, counts and percentages", () => {
    expect(attributeText("x")).toBe("x");
    expect(attributeText(0.123456)).toBe("0.123");
    expect(attributeText(12000)).toBe("12,000");
    expect(attributeText(true)).toBe("yes");
    expect(attributeText(null)).toBe("—");
    expect(attributeText({ a: 1 })).toBe('{"a":1}');
    expect(formatCount(1234567)).toBe("1,234,567");
    expect(formatCount(null)).toBe("—");
    expect(formatPercent(0.873)).toBe("87%");
    expect(formatPercent(1.5)).toBe("100%");
  });

  it("maps Suricata severities", () => {
    expect([1, 2, 3, 4].map(alertSeverity)).toEqual(["high", "medium", "low", "info"]);
  });
});

describe("filters and URL state", () => {
  it("validates IP filters", () => {
    expect(parseIpFilter("")).toEqual({ invalid: false });
    expect(parseIpFilter(" 10.0.0.1 ")).toEqual({ ip: "10.0.0.1", invalid: false });
    expect(parseIpFilter("2001:db8::1")).toEqual({ ip: "2001:db8::1", invalid: false });
    expect(parseIpFilter("10.0.0")).toEqual({ invalid: true });
    expect(parseIpFilter("256.1.1.1")).toEqual({ invalid: true });
    expect(parseIpFilter("example.test")).toEqual({ invalid: true });
  });

  it("validates port filters", () => {
    expect(parsePortFilter("")).toEqual({ invalid: false });
    expect(parsePortFilter("443")).toEqual({ port: 443, invalid: false });
    expect(parsePortFilter("0")).toEqual({ port: 0, invalid: false });
    expect(parsePortFilter("65536")).toEqual({ invalid: true });
    expect(parsePortFilter("-1")).toEqual({ invalid: true });
    expect(parsePortFilter("8e2")).toEqual({ invalid: true });
  });

  it("normalizes search terms", () => {
    expect(searchTerm("  ")).toBeUndefined();
    expect(searchTerm(" a\0b ")).toBe("ab");
    expect(searchTerm("x".repeat(300))).toHaveLength(200);
  });

  it("parses tabs and updates query strings", () => {
    expect(parseTab("flows")).toBe("flows");
    expect(parseTab("nope")).toBe("overview");
    expect(parseTab(null)).toBe("overview");
    expect(withParams("tab=findings&x=1", { tab: "flows", ip: "10.0.0.1", port: 443, x: undefined })).toBe(
      "?tab=flows&ip=10.0.0.1&port=443",
    );
    expect(withParams("tab=flows", { tab: undefined })).toBe("");
    expect(withParams("", { ref: "C a&b" })).toBe("?ref=C+a%26b");
  });

  it("links a row to its flow", () => {
    const e = { src_ip: "10.0.0.5", src_port: 51000, dst_ip: "203.0.113.9", dst_port: 443 };
    expect(flowLinkFor(e, "CabC1", true)).toEqual({ ip: "10.0.0.5", port: 51000, ref: "CabC1" });
    expect(flowLinkFor(e, "CabC2", false)).toEqual({ ip: "10.0.0.5", port: 443, ref: "CabC2" });
    expect(flowLinkFor({ src_ip: null, src_port: null, dst_ip: "203.0.113.9", dst_port: null }, null, true)).toEqual({
      ip: "203.0.113.9",
      port: undefined,
      ref: undefined,
    });
  });
});

describe("cited rows (ref)", () => {
  const ROW = "33333333-3333-4333-8333-333333333333";

  it("accepts only row ids and never forwards anything else", () => {
    expect(parseRowRef(ROW)).toEqual({ ref: ROW, invalid: false });
    expect(parseRowRef(ROW.toUpperCase())).toEqual({ ref: ROW, invalid: false });
    expect(parseRowRef(null)).toEqual({ invalid: false });
    expect(parseRowRef("CUid1")).toEqual({ invalid: true });
    expect(parseRowRef("javascript:alert(1)")).toEqual({ invalid: true });
  });

  it("queries just the cited row, ignoring the other filters and the page", () => {
    expect(citedQuery(ROW, { severity: "high" }, { limit: 25, offset: 50 })).toEqual({ ref: ROW, limit: 25, offset: 0 });
    expect(citedQuery(undefined, { severity: "high" }, { limit: 25, offset: 50 })).toEqual({
      severity: "high",
      limit: 25,
      offset: 50,
    });
  });

  it("reads ref on every citable PCAP tab; Flows keeps its uid highlight", () => {
    for (const tab of ["findings", "alerts", "dns", "http", "tls", "iocs", "timeline"]) {
      expect(REF_TABS.has(tab)).toBe(true);
      expect(parseTab(tab)).toBe(tab);
    }
    expect(REF_TABS.has("flows")).toBe(false);
    expect(parseTab("ai")).toBe("ai");
  });
});
