import { describe, expect, it } from "vitest";

import {
  codeLines,
  codeStats,
  escapedText,
  isHomoglyphIdentifier,
  plainTokens,
  tokenize,
  visibleParts,
} from "@/lib/c-tokenizer";

const join = (text: string) =>
  tokenize(text)
    .map((t) => t.text)
    .join("");

const SAMPLE = [
  "#include <windows.h>",
  "int inject_remote(ulong pid,void *payload,size_t len)",
  "{",
  "  // a \"comment\" with 'quotes'",
  '  pvVar1 = VirtualAllocEx(hProcess,(LPVOID)0x0,len,0x3000,0x40);',
  "  puts(L\"wide \\\" quote\");",
  "  c = '\\'';",
  "  /* block */ x = 1.5e+3 + u8\"utf\";",
  "  return 0;",
  "}",
].join("\n");

function kinds(text: string) {
  return tokenize(text).filter((t) => t.kind !== "whitespace");
}

describe("c tokenizer", () => {
  it("classifies keywords, types, literals, comments, numbers and preprocessor lines", () => {
    const tokens = kinds(SAMPLE);
    const find = (text: string) => tokens.find((t) => t.text === text)?.kind;
    expect(find("#include <windows.h>")).toBe("preprocessor");
    expect(find("int")).toBe("type");
    expect(find("return")).toBe("keyword");
    expect(find("VirtualAllocEx")).toBe("identifier");
    expect(find("0x3000")).toBe("number");
    expect(find("1.5e+3")).toBe("number");
    expect(find('L"wide \\" quote"')).toBe("string");
    expect(find("'\\''")).toBe("char");
    expect(find("/* block */")).toBe("comment");
    expect(find('// a "comment" with \'quotes\'')).toBe("comment");
    expect(find('u8"utf"')).toBe("string");
    expect(join(SAMPLE)).toBe(SAMPLE);
  });

  it("is lossless on edge cases and unterminated literals", () => {
    for (const text of ["", '"', "'", "\\", '"abc', '"abc\nnext"', "/*", "/* never", "//", "#", "  #define X \\\n 1", "L", 'u8"', "‮", "a\u0000b", "😀x"]) {
      expect(join(text)).toBe(text);
    }
    const open = tokenize('puts("open\nreturn;');
    expect(open.find((t) => t.kind === "string")?.text).toBe('"open');
    expect(open.find((t) => t.text === "return")?.kind).toBe("keyword");
  });

  it("is lossless on random input", () => {
    let seed = 1010;
    const rand = () => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed / 2 ** 31;
    };
    const alphabet = 'ab_ 0x9"\'\\/*\n\t;{}()#L8uU‮а😀';
    for (let n = 0; n < 500; n += 1) {
      const chars = Array.from(alphabet);
      const text = Array.from({ length: Math.floor(rand() * 200) }, () => chars[Math.floor(rand() * chars.length)]).join("");
      expect(join(text)).toBe(text);
    }
  });

  it.each(['"', "\\", "/*", "'", '"\\', "//\n", "#\n", "a", "‮"])("scans 1 MiB of %j in linear time", (unit) => {
    const text = unit.repeat(Math.floor(1_048_576 / unit.length));
    const started = performance.now();
    const tokens = tokenize(text);
    const elapsed = performance.now() - started;
    expect(tokens.reduce((n, t) => n + t.text.length, 0)).toBe(text.length);
    expect(elapsed).toBeLessThan(5_000); // a quadratic scanner would take hours
  });

  it("shows hidden and direction-changing characters as escapes (Trojan Source)", () => {
    const code = 'if (isAdmin) { /* ‮ } ⁦if (isAdmin)⁩ ⁦ begin admins only */';
    const parts = visibleParts(code);
    expect(parts.filter((p) => p.hidden).map((p) => p.text)).toEqual(["⟨U+202E⟩", "⟨U+2066⟩", "⟨U+2069⟩", "⟨U+2066⟩"]);
    expect(escapedText(code)).not.toMatch(/[‪-‮⁦-⁩]/);
    expect(escapedText("a​b﻿c\u0007d\tE")).toBe("a⟨U+200B⟩b⟨U+FEFF⟩c⟨U+0007⟩d\tE");
    expect(escapedText("tag\u{e0041}")).toBe("tag⟨U+E0041⟩");
    expect(codeStats(tokenize(code)).hidden).toBe(4);
  });

  it("flags identifiers with non-ASCII letters (homoglyphs)", () => {
    const tokens = tokenize("void раyload_init(void) { int сount = 0; int count = 1; }");
    const flagged = tokens.filter(isHomoglyphIdentifier).map((t) => t.text);
    expect(flagged).toEqual(["раyload_init", "сount"]);
    expect(codeStats(tokens).homoglyphs).toBe(2);
  });

  it("splits tokens into lines, cutting multi-line comments", () => {
    const lines = codeLines(tokenize("a /* one\ntwo */ b\r\nc"));
    expect(lines.map((line) => line.map((t) => t.text).join(""))).toEqual(["a /* one", "two */ b", "c"]);
    expect(lines[1][0].kind).toBe("comment");
  });

  it("keeps disassembly plain and lossless", () => {
    const text = "mov  eax, 0x40\ncall qword ptr [rip + 0x1234]";
    expect(
      plainTokens(text)
        .map((t) => t.text)
        .join(""),
    ).toBe(text);
    expect(new Set(plainTokens(text).map((t) => t.kind))).toEqual(new Set(["identifier", "whitespace"]));
  });
});
