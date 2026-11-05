import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AddResultList, ExportNotice, IocValue } from "@/components/ioc-collections/ioc-parts";

describe("IOC values", () => {
  it("are defanged text by default and never links", () => {
    const html = renderToStaticMarkup(<IocValue value="https://evil.example/<img src=x>" type="url" reveal={false} />);
    expect(html).toContain("hxxps[:]//evil[.]example/");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("href=");
  });

  it("reveal shows the clear value, still as text", () => {
    const html = renderToStaticMarkup(<IocValue value="javascript:alert(1)" type="url" reveal />);
    expect(html).toContain("javascript:alert(1)");
    expect(html).not.toContain("href=");
  });
});

describe("add results", () => {
  it("lists added / duplicate / invalid per submitted item", () => {
    const html = renderToStaticMarkup(
      <AddResultList
        submitted={[
          { type: "domain", value: "a.example" },
          { type: "domain", value: "a.example" },
          { type: "ipv4", value: "999.1.1.1" },
        ]}
        result={{
          added: 1,
          duplicates: 1,
          invalid: 1,
          results: [
            { index: 0, item_id: "i1", outcome: "added", reason: null },
            { index: 1, item_id: "i1", outcome: "duplicate", reason: null },
            { index: 2, item_id: null, outcome: "invalid", reason: "invalid_ioc" },
          ],
        }}
      />,
    );
    expect(html).toContain("1 added, 1 already present, 1 invalid");
    expect(html).toContain("a[.]example");
    expect(html).toContain("already in the collection");
    expect(html).toContain("invalid: not a valid indicator");
  });
});

describe("export notice", () => {
  it("shows the TLP label and that exports are not redacted (RT8)", () => {
    const html = renderToStaticMarkup(<ExportNotice tlp="amber_strict" />);
    expect(html).toContain("TLP:AMBER+STRICT");
    expect(html).toContain("not redacted");
  });
});
