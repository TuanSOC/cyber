"""Snapshot -> Markdown (CommonMark + GFM tables), with our own escaper.

Nothing from the snapshot can become Markdown or HTML syntax:

- text: every ASCII punctuation character is backslash-escaped (`md_text`), so no emphasis,
  link, image, autolink, raw HTML, entity (`&#x202E;` stays literal text), heading, quote,
  list (`-`, `+`, `*`, `1.`), setext underline (`=`) or table pipe can start; leading
  spaces and tabs become no-break spaces (no indented code block);
- evidence values (IOC values, hashes, paths, citation fields) are code spans whose fence is
  one backtick longer than the longest backtick run in the value (`md_code`);
- table cells: `|` is escaped and a newline becomes ` ⏎ `, so a value cannot end its row
  (RT19);
- `vis` first: bidi, zero-width, control and tag characters become `⟨U+XXXX⟩` (RT24).

The only links are the `[C12](#c12)` citation anchors (the appendix headings are `C12`, so
GFM's heading ids resolve them); platform paths appear as code text. A TLP line opens and
closes the document.
"""

import re
from collections.abc import Iterable, Sequence
from datetime import datetime

from cyberlab_jobs.report import ReportSnapshot

from report_worker import render_html, text
from report_worker.text import vis

ASCII_PUNCTUATION = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
NEWLINE_MARK = " ⏎ "
NBSP = " "
_BACKTICKS = re.compile(r"`+")
_LEADING_WS = re.compile(r"^[ \t]+")


def _escape(value: str) -> str:
    return "".join("\\" + ch if ch in ASCII_PUNCTUATION else ch for ch in value)


def _line(value: str) -> str:
    """One line of text: indentation kept as no-break spaces, punctuation escaped."""
    match = _LEADING_WS.match(value)
    lead = ""
    if match:
        lead = match.group(0).replace("\t", "    ").replace(" ", NBSP)
        value = value[match.end() :]
    return lead + _escape(value)


def md_text(value: str | None) -> str:
    """Inline text on one line (newlines shown as ` ⏎ `)."""
    if value is None or value == "":
        return text.EMPTY
    return _line(vis(value).replace("\r", "").replace("\n", NEWLINE_MARK))


def md_cell(value: str | None) -> str:
    """Text inside a table cell (`|` is already escaped by `md_text`)."""
    return md_text(value)


def md_code(value: str | None, *, cell: bool = False) -> str:
    """A code span: literal text whatever it contains; one line; `|` escaped in cells."""
    if value is None or value == "":
        return text.EMPTY
    shown = vis(value).replace("\n", NEWLINE_MARK)
    if cell:
        shown = shown.replace("|", "\\|")
    longest = max((len(run) for run in _BACKTICKS.findall(shown)), default=0)
    fence = "`" * (longest + 1)
    # One space of padding on both sides is stripped by CommonMark: the content stays
    # exact even when it starts or ends with a backtick.
    return f"{fence} {shown} {fence}"


def md_paragraphs(value: str) -> str:
    """Analyst prose: paragraphs kept, line breaks as hard breaks, everything escaped."""
    if not value.strip():
        return text.EMPTY
    paragraphs = [p for p in re.split(r"\n[ \t]*\n", vis(value).replace("\r", "")) if p.strip()]
    return "\n\n".join("  \n".join(_line(line) for line in p.split("\n")) for p in paragraphs)


def cite(n: int) -> str:
    return f"[\\[C{int(n)}\\]](#c{int(n)})"


def cites(numbers: Iterable[int]) -> str:
    return "".join(cite(n) for n in numbers)


def maybe_cite(n: int | None) -> str:
    return "" if n is None else " " + cite(n)


def table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    """A GFM table; every cell is already escaped by the caller."""
    lines = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join("---" for _ in header) + "|",
    ]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _shown(items: int, total: int) -> str:
    if total > items:
        return f"_Showing {items:,} of {total:,}\\._\n\n".replace(",", NBSP)
    return ""


def _ts(value: datetime | None) -> str:
    return _escape(text.ts(value))


def _tlp_line(s: ReportSnapshot, sha256: str) -> str:
    footer = text.case_footer(s.case.case_ref, s.report.version, sha256)
    return f"**{_escape(text.tlp_label(s.report.tlp))}** · {_escape(footer)}"


def render(s: ReportSnapshot, *, sha256: str) -> str:
    out: list[str] = [_tlp_line(s, sha256), ""]
    out += [f"# {md_text(s.report.title)}", ""]
    out += [
        f"_{_escape(text.tlp_definition(s.report.tlp))}_",
        "",
        table(
            ["Field", "Value"],
            [
                ["Case", f"{_escape(s.case.case_ref)}: {md_cell(s.case.title)}"],
                ["Report version", str(s.report.version)],
                ["Finalized", _ts(s.report.finalized_at)],
                ["Snapshot sha256", md_code(sha256, cell=True)],
                ["Profile", _escape(s.report.profile.value)],
                ["Distribution", md_cell(s.report.distribution)],
                ["Prepared by", md_cell(s.report.generated_by)],
            ],
        ),
        "",
    ]
    if s.report.change_note:
        out += ["## Change note", "", md_paragraphs(s.report.change_note), ""]
    out += ["## Document control", ""]
    control = [
        [
            f"v{d.version}",
            _ts(d.finalized_at),
            md_code(d.snapshot_sha256_short, cell=True),
            md_cell(d.change_note),
        ]
        for d in s.report.document_control
    ]
    control.append(
        [
            f"v{s.report.version} (this)",
            _ts(s.report.finalized_at),
            md_code(text.short_sha(sha256), cell=True),
            md_cell(s.report.change_note),
        ]
    )
    out += [table(["Version", "Finalized", "sha256", "Change note"], control), ""]

    for name, title in render_html.ANALYST_SECTIONS:
        body = getattr(s.sections, name)
        if body:
            out += [f"## {title}", "", md_paragraphs(body), ""]

    out += _case(s)
    out += _data_sections(s)
    out += [
        "## Integrity",
        "",
        "This document is a rendition of the signed snapshot "
        f"{md_code(sha256)} \\({_escape(s.schema_version)}\\)\\. The snapshot, its manifest "
        "and the detached Ed25519 signature are the record of truth\\.",
        "",
        _tlp_line(s, sha256),
        "",
    ]
    return "\n".join(out)


def _case(s: ReportSnapshot) -> list[str]:
    c = s.case
    out = [
        "## Case",
        "",
        table(
            ["Field", "Value"],
            [
                ["Reference", _escape(c.case_ref)],
                ["Title", md_cell(c.title)],
                ["Status", md_cell(c.status)],
                ["Severity", md_cell(c.severity)],
                ["Case TLP", _escape(text.tlp_label(c.tlp))],
                ["Opened", _ts(c.created_at)],
            ],
        ),
        "",
    ]
    if c.description:
        out += ["### Description", "", md_paragraphs(c.description), ""]
    if c.status_history:
        out += [
            "### Status history",
            "",
            _shown(len(c.status_history), c.status_history_total)
            + table(
                ["When", "From", "To", "By", "Reason"],
                [
                    [
                        _ts(e.occurred_at),
                        md_cell(e.from_status),
                        md_cell(e.to_status),
                        md_cell(e.actor),
                        md_cell(e.reason),
                    ]
                    for e in c.status_history
                ],
            ),
            "",
        ]
    return out


def _section(title: str, items: int, total: int, body: str) -> list[str]:
    return [f"## {title}", "", _shown(items, total) + body, ""]


def _data_sections(s: ReportSnapshot) -> list[str]:
    out: list[str] = []
    if s.evidence.items:
        rows = [
            [
                md_cell(e.filename) + maybe_cite(e.cite_no),
                f"{e.size_bytes}",
                md_code(e.sha256, cell=True),
                _ts(e.uploaded_at),
                md_cell(e.uploaded_by),
            ]
            for e in s.evidence.items
        ]
        out += _section(
            "Evidence",
            len(s.evidence.items),
            s.evidence.total,
            table(["File", "Size \\(bytes\\)", "sha256", "Uploaded", "By"], rows),
        )
    if s.custody.items:
        rows = [
            [
                _ts(c.occurred_at),
                md_cell(c.action),
                md_cell(c.actor),
                md_code(str(c.evidence_id), cell=True),
                md_code(c.ip, cell=True),
            ]
            for c in s.custody.items
        ]
        out += _section(
            "Chain of custody",
            len(s.custody.items),
            s.custody.total,
            table(["When", "Action", "Actor", "Evidence", "Client"], rows),
        )
    if s.jobs.items:
        rows = [
            [
                md_code(str(j.job_id), cell=True) + maybe_cite(j.cite_no),
                md_cell(j.analyzer),
                md_cell(j.status),
                _ts(j.finished_at),
                md_code(
                    ", ".join(f"{k} {v}" for k, v in sorted(j.tool_versions.items())), cell=True
                ),
            ]
            for j in s.jobs.items
        ]
        out += _section(
            "Analysis jobs",
            len(s.jobs.items),
            s.jobs.total,
            table(["Job", "Analyzer", "Status", "Finished", "Tool versions"], rows),
        )
    omitted = render_html.omissions_line(s)
    if s.findings.items or omitted is not None:
        rows = [
            [
                md_cell(f.severity),
                md_cell(f.title) + maybe_cite(f.cite_no),
                md_cell(f.description),
                md_cell(f.category),
                md_cell(", ".join(f.attack_ids)),
            ]
            for f in s.findings.items
        ]
        body = (
            table(["Severity", "Finding", "Description", "Category", "ATT&CK"], rows)
            if rows
            else ""
        )
        if omitted is not None:
            # M8 (RT10): a fixed sentence around one integer, escaped like any text.
            body = (body + "\n\n" if body else "") + f"_{md_text(omitted)}_"
        out += _section("Findings", len(s.findings.items), s.findings.total, body)
    if s.alerts.items:
        rows = [
            [
                md_cell(a.severity),
                md_cell(a.signature) + maybe_cite(a.cite_no),
                _ts(a.ts),
                md_code(a.src, cell=True),
                md_code(a.dst, cell=True),
                str(a.count),
            ]
            for a in s.alerts.items
        ]
        out += _section(
            "Alerts",
            len(s.alerts.items),
            s.alerts.total,
            table(["Severity", "Signature", "When", "Source", "Destination", "Count"], rows),
        )
    if s.iocs.items:
        rows = [
            [
                md_cell(i.ioc_type),
                md_code(i.value, cell=True) + maybe_cite(i.cite_no),
                str(i.count_jobs),
                _ts(i.first_seen),
                _ts(i.last_seen),
                md_cell(", ".join(i.collections)),
            ]
            for i in s.iocs.items
        ]
        out += _section(
            "Indicators of compromise",
            len(s.iocs.items),
            s.iocs.total,
            table(["Type", "Value", "Jobs", "First seen", "Last seen", "Collections"], rows),
        )
    if s.ti.items:
        values = {i.ioc_key: i.value for i in s.iocs.items}
        rows = [
            [
                md_code(values.get(t.ioc_key, t.ioc_key), cell=True) + maybe_cite(t.cite_no),
                md_cell(t.provider),
                md_cell(t.status + (", found" if t.found else "")),
                md_cell(t.score),
                md_cell(t.summary),
                _ts(t.fetched_at),
            ]
            for t in s.ti.items
        ]
        out += _section(
            "Threat intelligence",
            len(s.ti.items),
            s.ti.total,
            "_Answers attributed to their providers; third\\-party opinions, not verdicts of "
            "this platform\\._\n\n"
            + table(["Indicator", "Provider", "Result", "Score", "Summary", "Fetched"], rows),
        )
    if s.attack.items:
        rows = [
            [
                md_cell(a.technique_id),
                md_cell(a.name),
                md_cell(", ".join(a.tactics)),
                md_cell(a.status + (", revoked" if a.revoked else "")),
                md_cell(a.rationale) + (" " + cites(a.cite_nos) if a.cite_nos else ""),
            ]
            for a in s.attack.items
        ]
        out += _section(
            "MITRE ATT&CK mapping",
            len(s.attack.items),
            s.attack.total,
            table(["Technique", "Name", "Tactics", "Status", "Rationale"], rows),
        )
    if s.timeline.items:
        rows = [
            [
                _ts(t.ts),
                md_cell(t.kind),
                md_cell(t.title) + maybe_cite(t.cite_no),
                md_cell(t.severity),
            ]
            for t in s.timeline.items
        ]
        out += _section(
            "Timeline",
            len(s.timeline.items),
            s.timeline.total,
            table(["When \\(UTC\\)", "Kind", "Event", "Severity"], rows),
        )
    if s.notes.items:
        notes: list[str] = []
        for n in s.notes.items:
            notes += [
                f"### {md_text(n.author)}, {_ts(n.updated_at)} \\(version {n.version}\\)",
                "",
                md_paragraphs(n.body),
                "",
            ]
            if n.cite_nos:
                notes += [cites(n.cite_nos), ""]
        out += _section("Analyst notes", len(s.notes.items), s.notes.total, "\n".join(notes))
    if s.ai.items:
        out += _ai(s)
    if s.citations.items:
        out += _appendix(s)
    return out


def _ai(s: ReportSnapshot) -> list[str]:
    out = ["## AI\\-assisted analysis", "", _shown(len(s.ai.items), s.ai.total)]
    for run in s.ai.items:
        out += [
            f"### {md_text(run.task)}: {md_text(run.provider)} / {md_text(run.model)}",
            "",
            "> **AI\\-generated interpretation: observations to verify, not verdicts\\.**  ",
            f"> Model {md_text(run.model)}, prompt {md_text(run.prompt_version)}, "
            f"finished {_ts(run.finished_at)}\\.  ",
            f"> {md_text(run.disclaimer)}",
            "",
        ]
        if run.omitted_unsupported or run.omitted_flagged:
            out += [
                f"_Omitted: {run.omitted_unsupported} unsupported, "
                f"{run.omitted_flagged} flagged claim\\(s\\)\\._",
                "",
            ]
        for key, title in render_html.AI_GROUPS:
            claims = [c for c in run.claims if c.section == key]
            if not claims:
                continue
            out += [f"#### {title}", ""]
            for c in claims:
                prefix = "**Hypothesis:** " if c.status == "hypothesis" else ""
                flags = "".join(f" {md_code(flag)}" for flag in c.flags)
                conf = f" \\({md_text(c.confidence)}\\)" if c.confidence else ""
                out += [f"{prefix}{md_text(c.text)}{cites(c.cite_nos)}{conf}{flags}", ""]
    return out


def _appendix(s: ReportSnapshot) -> list[str]:
    out = [
        "## Citation appendix",
        "",
        _shown(len(s.citations.items), s.citations.total),
    ]
    if s.citations.dropped_out_of_scope:
        out += [
            f"_{s.citations.dropped_out_of_scope} cited row\\(s\\) were out of scope at "
            "snapshot time and are not shown\\._",
            "",
        ]
    for c in s.citations.items:
        rows = [
            ["kind", md_cell(c.kind)],
            ["table", md_cell(c.ref_table)],
            ["row", md_code(c.ref_id, cell=True)],
            ["job", md_code(str(c.job_id) if c.job_id else None, cell=True)],
            ["source", md_cell(c.source)],
            ["fields\\_sha256", md_code(c.fields_sha256, cell=True)],
        ]
        rows += [
            [md_cell(name), md_code(value, cell=True)] for name, value in sorted(c.fields.items())
        ]
        if c.path:
            rows.append(["path", md_code(c.path, cell=True)])
        out += [f"### C{c.cite_no}", "", table(["Field", "Value"], rows), ""]
    return out
