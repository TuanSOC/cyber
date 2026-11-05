import { describe, expect, it } from "vitest";

import {
  addSummary,
  checkManualIoc,
  defang,
  exportFallbackName,
  exportQuery,
  iocDisplay,
  itemOutcomeText,
  manualTypeFor,
  refangInput,
  selectionToItems,
} from "@/lib/ioc-collections";

describe("defang", () => {
  it("defangs URLs, domains, IPs and emails; leaves hashes", () => {
    expect(defang("https://evil.example.org/a?b=c", "url")).toBe("hxxps[:]//evil[.]example[.]org/a?b=c");
    expect(defang("http://1.2.3.4/", "url")).toBe("hxxp[:]//1[.]2[.]3[.]4/");
    expect(defang("evil.example", "domain")).toBe("evil[.]example");
    expect(defang("10.0.0.5", "ip")).toBe("10[.]0[.]0[.]5");
    expect(defang("2001:db8::1", "ipv6")).toBe("2001[:]db8[:][:]1");
    expect(defang("a.b@example.com", "email")).toBe("a[.]b[@]example[.]com");
    expect(defang("44d88612fea8a8f36de82e1278abb02f", "md5")).toBe("44d88612fea8a8f36de82e1278abb02f");
    expect(defang("javascript:alert(1)", "url")).toBe("javascript:alert(1)");
  });

  it("reveals only on request", () => {
    expect(iocDisplay("evil.example", "domain", false)).toBe("evil[.]example");
    expect(iocDisplay("evil.example", "domain", true)).toBe("evil.example");
  });
});

describe("manual add", () => {
  it("refangs input and checks shapes", () => {
    expect(refangInput(" hxxps[:]//evil[.]example/x ")).toBe("https://evil.example/x");
    expect(checkManualIoc("domain", "evil[.]example")).toBeNull();
    expect(checkManualIoc("ipv4", "300.1.1.1")).not.toBeNull();
    expect(checkManualIoc("ipv4", "8.8.8.8")).toBeNull();
    expect(checkManualIoc("ipv6", "2001:db8::1")).toBeNull();
    expect(checkManualIoc("ipv6", "1.2.3.4")).not.toBeNull();
    expect(checkManualIoc("sha256", "abc")).not.toBeNull();
    expect(checkManualIoc("url", "javascript:alert(1)")).not.toBeNull();
    expect(checkManualIoc("email", "a b@c.d")).not.toBeNull();
    expect(checkManualIoc("domain", "")).toBe("Enter a value.");
  });

  it("maps job IOC types and selections", () => {
    expect(manualTypeFor("ip", "10.0.0.1")).toBe("ipv4");
    expect(manualTypeFor("ip", "fe80::1")).toBe("ipv6");
    expect(manualTypeFor("file_sha256", "x")).toBe("sha256");
    expect(manualTypeFor("ja3", "x")).toBeNull();
    const { items, skipped } = selectionToItems([
      { ioc_type: "domain", value: "a.example" },
      { ioc_type: "registry_key", value: "HKLM\\x" },
    ]);
    expect(items).toEqual([{ type: "domain", value: "a.example" }]);
    expect(skipped).toBe(1);
  });

  it("describes per-item outcomes", () => {
    expect(itemOutcomeText({ outcome: "added", reason: null })).toBe("added");
    expect(itemOutcomeText({ outcome: "duplicate", reason: null })).toBe("already in the collection");
    expect(itemOutcomeText({ outcome: "invalid", reason: "invalid_ioc" })).toBe("invalid: not a valid indicator");
    expect(itemOutcomeText({ outcome: "invalid", reason: "x" })).toBe("invalid: x");
    expect(addSummary({ added: 2, duplicates: 1, invalid: 0 })).toBe("2 added, 1 already present, 0 invalid");
  });
});

describe("exports", () => {
  it("only evidence.write holders get clear text", () => {
    expect(exportQuery("csv", true, false)).toEqual({ format: "csv", defang: true });
    expect(exportQuery("csv", true, true)).toEqual({ format: "csv", defang: false });
    expect(exportQuery("stix21", false, true)).toEqual({ format: "stix21", defang: true });
  });

  it("has a safe fallback filename", () => {
    expect(exportFallbackName("../C2 hosts", "stix21")).toBe("C2_hosts.stix.json");
    expect(exportFallbackName("", "csv")).toBe("collection.csv");
  });
});
