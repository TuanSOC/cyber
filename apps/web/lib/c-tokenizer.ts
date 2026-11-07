/**
 * A hand-written, linear-time tokenizer for decompiled C (M10 phase 10; the API's
 * `ai/context/c_literals.py` is its Python twin, reduced to literals and identifiers).
 *
 * Decompiled code is attacker-influenced text: identifiers come from export / symbol names,
 * literals carry whatever the binary stores. The code viewer renders the tokens as React text
 * nodes inside `<span>`s (never HTML); this module only classifies characters:
 *
 * - one pass over the input, no regular expression with backtracking (`String.prototype`
 *   searches only for a fixed terminator), so 1 MiB of `"`, `\` or `/*` costs one pass;
 * - lossless: concatenating the token texts gives the input back exactly;
 * - an unterminated string / char literal ends before the line break; an unterminated block
 *   comment runs to the end; a preprocessor line runs to the end of its (continued) line.
 *
 * Invisible and control characters ("Trojan Source": bidi embeddings / overrides / isolates,
 * zero-width characters, tag characters, C0 / C1 controls except tab) are split out by
 * `visibleParts` into `hidden` parts the viewer shows as `⟨U+202E⟩` escapes; identifiers with
 * non-ASCII characters (homoglyphs such as a Cyrillic `а`) are flagged by `isHomoglyphIdentifier`.
 */

export type TokenKind =
  | "keyword"
  | "type"
  | "identifier"
  | "number"
  | "string"
  | "char"
  | "comment"
  | "preprocessor"
  | "punctuation"
  | "whitespace"
  | "invalid";

export type Token = { kind: TokenKind; text: string };

const KEYWORDS = new Set([
  "auto",
  "break",
  "case",
  "const",
  "continue",
  "default",
  "do",
  "else",
  "enum",
  "extern",
  "for",
  "goto",
  "if",
  "inline",
  "register",
  "restrict",
  "return",
  "sizeof",
  "static",
  "struct",
  "switch",
  "typedef",
  "union",
  "volatile",
  "while",
  "true",
  "false",
  "NULL",
]);

// C and Ghidra type names (`undefined4`, `ulonglong`, `LPVOID` stay identifiers unless listed).
const TYPES = new Set([
  "void",
  "char",
  "short",
  "int",
  "long",
  "float",
  "double",
  "signed",
  "unsigned",
  "bool",
  "_Bool",
  "byte",
  "uchar",
  "ushort",
  "uint",
  "ulong",
  "longlong",
  "ulonglong",
  "undefined",
  "undefined1",
  "undefined2",
  "undefined4",
  "undefined8",
  "size_t",
  "code",
  "wchar_t",
  "int8_t",
  "int16_t",
  "int32_t",
  "int64_t",
  "uint8_t",
  "uint16_t",
  "uint32_t",
  "uint64_t",
]);

const PUNCTUATION = new Set("{}()[];,.:?~!%^&*-+=|<>/\\#@`".split(""));
const LITERAL_PREFIXES = new Set(["L", "u", "U", "u8"]);

function isDigit(cp: number): boolean {
  return cp >= 0x30 && cp <= 0x39;
}

function isAsciiLetter(cp: number): boolean {
  return (cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a);
}

/** Letters of any script start an identifier (homoglyph names must stay identifiers). */
function isIdentStart(ch: string): boolean {
  const cp = ch.codePointAt(0) ?? 0;
  if (isAsciiLetter(cp) || ch === "_" || ch === "$") return true;
  return cp > 0x7f && !isHidden(cp) && LETTER.test(ch);
}

// One code point at a time (anchored, no repetition): a constant-time test.
const LETTER = /^[\p{L}\p{Nl}]$/u;

function isIdentPart(ch: string): boolean {
  const cp = ch.codePointAt(0) ?? 0;
  return isIdentStart(ch) || isDigit(cp);
}

function isSpace(cp: number): boolean {
  return cp === 0x20 || cp === 0x09 || cp === 0x0a || cp === 0x0d || cp === 0x0b || cp === 0x0c;
}

/**
 * Characters the viewer never renders as-is: C0 controls except tab and line feed, DEL, C1
 * controls, bidi marks / embeddings / overrides / isolates (U+061C, U+200E-200F,
 * U+202A-202E, U+2066-2069), zero-width characters (U+200B-200D, U+2060-2064, U+FEFF), the
 * soft hyphen and tag characters (U+E0000-E007F).
 */
export function isHidden(cp: number): boolean {
  if (cp === 0x09 || cp === 0x0a) return false;
  if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) return true;
  if (cp === 0xad || cp === 0x061c || cp === 0xfeff) return true;
  if (cp >= 0x200b && cp <= 0x200f) return true;
  if (cp >= 0x202a && cp <= 0x202e) return true;
  if (cp >= 0x2060 && cp <= 0x2064) return true;
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  return cp >= 0xe0000 && cp <= 0xe007f;
}

/** The visible escape of a hidden character: `⟨U+202E⟩`. */
export function escapeCodePoint(cp: number): string {
  return `⟨U+${cp.toString(16).toUpperCase().padStart(4, "0")}⟩`;
}

/** The end (exclusive) of a string / char literal whose opening quote is at `quoteAt`. */
function literalEnd(text: string, quoteAt: number): number {
  const quote = text[quoteAt];
  const n = text.length;
  let j = quoteAt + 1;
  while (j < n) {
    const ch = text[j];
    if (ch === "\\") {
      j += 2; // an escape; a backslash-newline continuation keeps the literal open
      continue;
    }
    if (ch === quote) return j + 1;
    if (ch === "\n") return j;
    j += 1;
  }
  return n;
}

/** The end of a preprocessor line (backslash-newline continues it). */
function lineEnd(text: string, from: number): number {
  const n = text.length;
  let j = from;
  while (j < n) {
    if (text[j] === "\\" && text[j + 1] === "\n") {
      j += 2;
      continue;
    }
    if (text[j] === "\n") return j;
    j += 1;
  }
  return n;
}

function atLineStart(text: string, i: number): boolean {
  let k = i - 1;
  while (k >= 0 && (text[k] === " " || text[k] === "\t")) k -= 1;
  return k < 0 || text[k] === "\n";
}

/** Tokens of `text` in order; `tokens.map(t => t.text).join("") === text`. */
export function tokenize(text: string): Token[] {
  const out: Token[] = [];
  const n = text.length;
  let i = 0;
  const push = (kind: TokenKind, end: number) => {
    out.push({ kind, text: text.slice(i, end) });
    i = end;
  };
  while (i < n) {
    const ch = text[i];
    const cp = text.charCodeAt(i);
    const next = text[i + 1];
    if (isSpace(cp)) {
      let j = i + 1;
      while (j < n && isSpace(text.charCodeAt(j))) j += 1;
      push("whitespace", j);
    } else if (ch === "/" && next === "/") {
      const end = text.indexOf("\n", i + 2);
      push("comment", end < 0 ? n : end);
    } else if (ch === "/" && next === "*") {
      const close = text.indexOf("*/", i + 2);
      push("comment", close < 0 ? n : close + 2);
    } else if (ch === '"' || ch === "'") {
      push(ch === '"' ? "string" : "char", literalEnd(text, i));
    } else if (ch === "#" && atLineStart(text, i)) {
      push("preprocessor", lineEnd(text, i));
    } else if (isDigit(cp)) {
      let j = i + 1;
      while (j < n) {
        const c = text[j];
        const code = text.charCodeAt(j);
        if (isDigit(code) || isAsciiLetter(code) || c === "_" || c === ".") j += 1;
        else if ((c === "+" || c === "-") && "eEpP".includes(text[j - 1] ?? "_") && text[i + 1] !== "x") j += 1;
        else break;
      }
      push("number", j);
    } else if (isIdentStart(ch)) {
      let j = i + ch.length;
      while (j < n) {
        const c = String.fromCodePoint(text.codePointAt(j) ?? 0);
        if (!isIdentPart(c)) break;
        j += c.length;
      }
      const word = text.slice(i, j);
      if ((text[j] === '"' || text[j] === "'") && LITERAL_PREFIXES.has(word)) {
        push(text[j] === '"' ? "string" : "char", literalEnd(text, j));
      } else {
        push(KEYWORDS.has(word) ? "keyword" : TYPES.has(word) ? "type" : "identifier", j);
      }
    } else if (PUNCTUATION.has(ch)) {
      push("punctuation", i + 1);
    } else {
      // Anything else (hidden characters, symbols, a lone surrogate): one code point each.
      const width = String.fromCodePoint(text.codePointAt(i) ?? 0).length;
      push("invalid", i + Math.max(1, width));
    }
  }
  return out;
}

/** True for an identifier holding a non-ASCII character (a possible homoglyph, RT17). */
export function isHomoglyphIdentifier(token: Token): boolean {
  if (token.kind !== "identifier" && token.kind !== "keyword" && token.kind !== "type") return false;
  for (let k = 0; k < token.text.length; k += 1) if (token.text.charCodeAt(k) > 0x7f) return true;
  return false;
}

export type VisiblePart = { hidden: false; text: string } | { hidden: true; text: string; codePoint: number };

/** `text` split into plain runs and hidden characters (each shown as its escape). */
export function visibleParts(text: string): VisiblePart[] {
  const parts: VisiblePart[] = [];
  let start = 0;
  let k = 0;
  while (k < text.length) {
    const cp = text.codePointAt(k) ?? 0;
    const width = cp > 0xffff ? 2 : 1;
    if (isHidden(cp)) {
      if (k > start) parts.push({ hidden: false, text: text.slice(start, k) });
      parts.push({ hidden: true, text: escapeCodePoint(cp), codePoint: cp });
      start = k + width;
    }
    k += width;
  }
  if (start < text.length) parts.push({ hidden: false, text: text.slice(start) });
  return parts;
}

/** The text with every hidden character replaced by its escape ("Copy" copies this). */
export function escapedText(text: string): string {
  return visibleParts(text)
    .map((part) => part.text)
    .join("");
}

export type CodeLine = Token[];

/**
 * Tokens split into lines (a token spanning line breaks, such as a block comment, is cut into
 * one token per line). Line feeds are dropped: the viewer renders one row per line.
 */
export function codeLines(tokens: readonly Token[]): CodeLine[] {
  const lines: CodeLine[] = [[]];
  for (const token of tokens) {
    let rest = token.text;
    let breakAt = rest.indexOf("\n");
    while (breakAt >= 0) {
      const head = rest.slice(0, breakAt).replace(/\r$/, "");
      if (head) lines[lines.length - 1].push({ kind: token.kind, text: head });
      lines.push([]);
      rest = rest.slice(breakAt + 1);
      breakAt = rest.indexOf("\n");
    }
    if (rest) lines[lines.length - 1].push({ kind: token.kind, text: rest });
  }
  return lines;
}

export type CodeStats = { hidden: number; homoglyphs: number };

/** What the viewer's banner counts: hidden characters and non-ASCII identifiers. */
export function codeStats(tokens: readonly Token[]): CodeStats {
  let hidden = 0;
  let homoglyphs = 0;
  for (const token of tokens) {
    if (isHomoglyphIdentifier(token)) homoglyphs += 1;
    for (let k = 0; k < token.text.length; k += 1) {
      const cp = token.text.codePointAt(k) ?? 0;
      if (cp > 0xffff) k += 1;
      if (isHidden(cp)) hidden += 1;
    }
  }
  return { hidden, homoglyphs };
}

/** Plain (non-C) tokens for disassembly: one whitespace / text token per run, still lossless. */
export function plainTokens(text: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < text.length) {
    const space = isSpace(text.charCodeAt(i));
    let j = i + 1;
    while (j < text.length && isSpace(text.charCodeAt(j)) === space) j += 1;
    out.push({ kind: space ? "whitespace" : "identifier", text: text.slice(i, j) });
    i = j;
  }
  return out;
}
