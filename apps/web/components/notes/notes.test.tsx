import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { NoteBody, NoteMeta, NoteTombstone, RefChips, VersionList } from "@/components/notes/note-parts";
import type { JobRoute } from "@/lib/ai";
import type { Note } from "@/lib/notes";

const ORG = "11111111-1111-4111-8111-111111111111";
const JOB = "22222222-2222-4222-8222-222222222222";
const ROW = "33333333-3333-4333-8333-333333333333";
const routes = new Map<string, JobRoute>([[JOB, "pcap"]]);

const HOSTILE = [
  `<img src=x onerror="alert(1)">`,
  `<script>alert(2)</script>`,
  `[click](javascript:alert(3)) javascript:alert(4) https://evil.example/x`,
  `**bold** _md_ <a href="https://evil.example">a</a>`,
  `abc‮txt.exe​`,
].join("\n");

function note(over: Partial<Note> = {}): Note {
  return {
    id: ROW,
    investigation_id: JOB,
    author_id: "u1",
    author_name: `<b>Mallory</b>`,
    created_by: "u1",
    created_by_name: "Mallory",
    body: HOSTILE,
    created_at: "2026-11-05T10:00:00Z",
    updated_at: "2026-11-05T11:00:00Z",
    deleted: false,
    deleted_at: null,
    deleted_by: null,
    edited: true,
    include_in_reports: false,
    pinned: true,
    refs: [],
    version: 2,
    ...over,
  };
}

/** Every element of the markup, by tag name. */
function tags(html: string): string[] {
  return [...html.matchAll(/<([a-z][a-z0-9-]*)\b/gi)].map((m) => m[1].toLowerCase());
}

describe("note text renders as inert text", () => {
  it("produces no element, link or attribute from the body", () => {
    const html = renderToStaticMarkup(<NoteBody body={HOSTILE} />);
    expect(tags(html)).toEqual(["p"]);
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script");
    expect(html).not.toMatch(/<a[\s>]/);
    expect(html).not.toMatch(/\shref="/);
    expect(html).not.toMatch(/\sonerror="/);
    expect(html).not.toContain("<strong");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(html).toContain("javascript:alert(4)");
  });

  it("makes bidi and zero-width characters visible", () => {
    const html = renderToStaticMarkup(<NoteBody body={HOSTILE} />);
    expect(html).toContain("⟨U+202E⟩");
    expect(html).toContain("⟨U+200B⟩");
    expect(html).not.toContain("‮");
  });

  it("escapes author names and keeps the version history as text", () => {
    const meta = renderToStaticMarkup(<NoteMeta note={note()} />);
    expect(meta).toContain("&lt;b&gt;Mallory&lt;/b&gt;");
    expect(meta).toContain("edited (v2)");
    expect(meta).toContain("Pinned");
    const history = renderToStaticMarkup(
      <VersionList
        orgId={ORG}
        routes={routes}
        versions={[
          { version: 1, author_id: "u1", author_name: "Mallory", body: "first <img src=x>", created_at: "2026-11-05T10:00:00Z", refs: [] },
          { version: 2, author_id: "u1", author_name: "Mallory", body: HOSTILE, created_at: "2026-11-05T11:00:00Z", refs: [] },
        ]}
      />,
    );
    expect(history).not.toContain("<img");
    expect(history.indexOf("v2")).toBeLessThan(history.indexOf("v1"));
  });

  it("shows only a tombstone for a deleted note", () => {
    const html = renderToStaticMarkup(
      <NoteTombstone
        note={note({ deleted: true, body: null, deleted_by: "u2", deleted_at: "2026-11-05T12:00:00Z" })}
        names={new Map([["u2", "Bob"]])}
      />,
    );
    expect(html).toContain("Deleted by Bob at");
    expect(html).not.toContain("onerror");
  });
});

describe("ref chips", () => {
  it("links known refs internally and never links unknown ones", () => {
    const html = renderToStaticMarkup(
      <RefChips
        orgId={ORG}
        routes={routes}
        refs={[
          { kind: "finding", ref_id: ROW, job_id: JOB },
          { kind: "alert", ref_id: ROW, job_id: "44444444-4444-4444-8444-444444444444" },
        ]}
      />,
    );
    expect(html).toContain(`href="/o/${ORG}/pcap/${JOB}?tab=findings&amp;ref=${ROW}"`);
    expect((html.match(/href=/g) ?? []).length).toBe(1);
    expect(html).toContain("Alert · 33333333");
  });
});
