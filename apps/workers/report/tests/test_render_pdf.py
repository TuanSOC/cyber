"""The PDF: PDF/A-3a, the three attachments byte for byte, TLP in the header and footer of
every page, the page cap, byte-identical output, and the deny-all fetcher (RT16, RT17).

`pypdf` reads the PDFs here only (tests); the worker never parses a PDF.
"""

import hashlib
import io
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pypdf
import pytest
from cyberlab_jobs.report import TLP, ReportSnapshot, canonical_json
from weasyprint import CSS, HTML, Attachment

from report_worker import render_pdf, text
from report_worker.fetch import DenyAllFetcher, FetchBlocked

MANIFEST = b'{"kid":"dev-report-1","schema_version":"cyberlab.report.manifest.v1"}'
SIGNATURE = b'{"alg":"Ed25519","signature":"AAAA"}'


def inputs(snapshot: ReportSnapshot) -> render_pdf.PdfInputs:
    data = canonical_json(snapshot)
    return render_pdf.PdfInputs(
        snapshot=snapshot,
        snapshot_bytes=data,
        sha256=hashlib.sha256(data).hexdigest(),
        manifest_bytes=MANIFEST,
        signature_bytes=SIGNATURE,
        finalized_at=snapshot.report.finalized_at,
    )


@pytest.fixture(scope="module")
def golden_pdf() -> tuple[bytes, int, render_pdf.PdfInputs]:
    from tests.conftest import load_snapshot

    snapshot_inputs = inputs(load_snapshot("golden_snapshot.json"))
    data, pages = render_pdf.render(snapshot_inputs)
    return data, pages, snapshot_inputs


def test_the_pdf_is_pdf_a_3a(golden_pdf: tuple[bytes, int, render_pdf.PdfInputs]) -> None:
    data, pages, _ = golden_pdf
    assert data.startswith(b"%PDF-")
    reader = pypdf.PdfReader(io.BytesIO(data))
    assert len(reader.pages) == pages
    root: Any = reader.trailer["/Root"]
    meta: Any = reader.metadata
    xmp = root["/Metadata"].get_object().get_data()
    assert b'pdfaid:part="3"' in xmp and b'pdfaid:conformance="A"' in xmp
    assert bool(root["/MarkInfo"]["/Marked"]) and "/StructTreeRoot" in root
    [intent] = root["/OutputIntents"]
    assert intent["/S"] == "/GTS_PDFA1" and "sRGB" in intent["/OutputConditionIdentifier"]
    assert root["/Lang"] == "en"
    assert meta is not None
    assert meta["/CreationDate"] == "D:20261106090000Z"
    assert meta["/ModDate"] == "D:20261106090000Z"


def test_the_attachments_are_the_inputs_byte_for_byte(
    golden_pdf: tuple[bytes, int, render_pdf.PdfInputs],
) -> None:
    data, _, snapshot_inputs = golden_pdf
    attachments = pypdf.PdfReader(io.BytesIO(data)).attachments
    assert {name: content for name, [content] in attachments.items()} == {
        "snapshot.json": snapshot_inputs.snapshot_bytes,
        "manifest.json": MANIFEST,
        "manifest.sig.json": SIGNATURE,
    }
    root: Any = pypdf.PdfReader(io.BytesIO(data)).trailer["/Root"]
    relationships = {
        str(spec.get_object()["/F"]): str(spec.get_object()["/AFRelationship"])
        for spec in root["/AF"]
    }
    assert relationships == {
        "snapshot.json": "/Source",
        "manifest.json": "/Source",
        "manifest.sig.json": "/Source",
    }


def test_the_tlp_is_in_the_header_and_footer_of_every_page(
    golden_pdf: tuple[bytes, int, render_pdf.PdfInputs],
) -> None:
    data, pages, snapshot_inputs = golden_pdf
    footer = text.case_footer("CASE-00012", 2, snapshot_inputs.sha256)
    reader = pypdf.PdfReader(io.BytesIO(data))
    assert pages >= 3
    for number, page in enumerate(reader.pages, start=1):
        content = page.extract_text()
        assert content.count("TLP:AMBER") >= 2, number  # @top-right and @bottom-right
        assert footer in content, number
        assert f"Page {number} of {pages}" in content


@pytest.mark.parametrize("tlp", list(TLP))
def test_every_tlp_label_reaches_the_margins(golden: ReportSnapshot, tlp: TLP) -> None:
    snapshot = golden.model_copy(update={"report": golden.report.model_copy(update={"tlp": tlp})})
    data, _ = render_pdf.render(inputs(snapshot))
    last = pypdf.PdfReader(io.BytesIO(data)).pages[-1].extract_text()
    assert last.count(text.tlp_label(tlp)) >= 2


def test_rendering_twice_gives_identical_bytes(
    golden_pdf: tuple[bytes, int, render_pdf.PdfInputs],
) -> None:
    data, _, snapshot_inputs = golden_pdf
    again, _ = render_pdf.render(snapshot_inputs)
    assert again == data


def test_the_hostile_snapshot_renders_reproducibly(hostile: ReportSnapshot) -> None:
    first, pages = render_pdf.render(inputs(hostile))
    second, _ = render_pdf.render(inputs(hostile))
    assert first == second and pages > 1
    content = "".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(first)).pages)
    content = content.replace("\x00", "")  # pypdf's reading of some fallback-font runs
    assert "U+202E" in content and "‮" not in content
    assert "</style><script>alert(1)</script>" in content.replace("\n", "")


def test_the_page_cap_is_checked_before_writing(golden: ReportSnapshot) -> None:
    with pytest.raises(render_pdf.TooManyPages) as exc:
        render_pdf.render(inputs(golden), max_pages=2)
    assert exc.value.pages > 2


# --- the deny-all fetcher (RT16) -----------------------------------------------------------

URLS = [
    "http://attacker.example/x.png",
    "https://attacker.example/x.css",
    "data:text/css,body{color:red}",
    "data:image/png;base64,iVBORw0KGgo=",
    "file:///etc/passwd",
    "file:///app/assets/report.css",
    "file:///app/assets/fonts.conf",
    "ftp://attacker.example/x",
]


@pytest.mark.parametrize("url", URLS)
def test_the_fetcher_refuses_every_url(url: str) -> None:
    fetcher = DenyAllFetcher()
    with pytest.raises(FetchBlocked):
        fetcher.fetch(url)
    with pytest.raises(FetchBlocked):
        fetcher(url)
    with pytest.raises(FetchBlocked):
        fetcher.open(url)
    assert fetcher.attempts == 3
    with pytest.raises(FetchBlocked):
        fetcher.check()


def _documents(url: str) -> dict[str, str]:
    return {
        "img": f'<img src="{url}">',
        "link": f'<link rel="stylesheet" href="{url}"><p>x</p>',
        "style-import": f'<style>@import url("{url}");</style><p>x</p>',
        "style-background": f'<style>p {{ background: url("{url}") }}</style><p>x</p>',
        "font-face": (
            f'<style>@font-face {{ font-family: X; src: url("{url}") }} p {{ font-family: X }}'
            "</style><p>x</p>"
        ),
        "inline-style": f'<p style="background-image: url({url})">x</p>',
        "svg-image": f'<svg xmlns="http://www.w3.org/2000/svg"><image href="{url}"/></svg>',
        "object": f'<object data="{url}"></object>',
    }


@pytest.mark.parametrize("kind", list(_documents("x")))
@pytest.mark.parametrize("url", URLS[:6])
def test_every_resource_kind_goes_to_the_fetcher_and_fails_the_render(kind: str, url: str) -> None:
    fetcher = DenyAllFetcher()
    try:
        document = HTML(string=_documents(url)[kind], base_url=None, url_fetcher=fetcher)
        document.render(presentational_hints=False).write_pdf()
    except FetchBlocked:
        pass
    # Stopped at the first attempt, or the attempt was swallowed and `check` fails it.
    assert fetcher.attempts >= 1, kind
    with pytest.raises(FetchBlocked):
        fetcher.check()


def test_a_64_mib_data_uri_is_refused_without_decoding() -> None:
    payload = "A" * (64 * 1024 * 1024)
    fetcher = DenyAllFetcher()
    seen: list[int] = []
    original = fetcher.fetch

    def fetch(url: str, headers: object = None) -> None:
        seen.append(len(url))
        original(url)

    fetcher.fetch = fetch  # type: ignore[method-assign,assignment]
    with pytest.raises(FetchBlocked):
        HTML(
            string=f'<img src="data:image/png;base64,{payload}">',
            base_url=None,
            url_fetcher=fetcher,
        ).render()
    assert seen and seen[0] > len(payload)  # the URL itself, undecoded


def test_a_stylesheet_given_as_a_url_goes_through_the_fetcher() -> None:
    fetcher = DenyAllFetcher()
    with pytest.raises(FetchBlocked):
        CSS(url="file:///app/assets/report.css", url_fetcher=fetcher)
    attachment = Attachment(url="file:///etc/passwd", url_fetcher=fetcher)
    with pytest.raises(FetchBlocked):
        HTML(string="<p>x</p>", base_url=None, url_fetcher=fetcher).write_pdf(
            attachments=[attachment]
        )


def test_relative_urls_are_never_resolved_or_fetched(tmp_path: Path) -> None:
    secret = tmp_path / "secret.css"
    secret.write_text("p { color: red }")
    fetcher = DenyAllFetcher()
    html = (
        f'<link rel="stylesheet" href="{secret.name}"><img src="secret.png">'
        '<style>@import "secret.css";</style><p>x</p>'
    )
    HTML(string=html, base_url=None, url_fetcher=fetcher).render().write_pdf()
    assert fetcher.attempts == 0  # nothing to resolve against: dropped before any fetch


def test_the_template_output_makes_no_fetch(hostile: ReportSnapshot) -> None:
    calls: list[str] = []

    class Counting(DenyAllFetcher):
        def fetch(self, url: str, headers: object = None) -> None:  # type: ignore[override]
            calls.append(url)
            super().fetch(url)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(render_pdf, "DenyAllFetcher", Counting)
        render_pdf.render(inputs(hostile))
    assert calls == []


def test_the_constant_stylesheet_was_built_with_the_deny_all_fetcher() -> None:
    assert render_pdf.PDF_VARIANT == "pdf/a-3a"
    assert isinstance(render_pdf.REPORT_CSS, CSS)


def test_the_image_has_no_ghostscript() -> None:
    assert shutil.which("gs") is None and shutil.which("ghostscript") is None


def test_dates_come_from_finalized_at_only(golden: ReportSnapshot) -> None:
    later = golden.model_copy(
        update={
            "report": golden.report.model_copy(
                update={"finalized_at": datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)}
            )
        }
    )
    data, _ = render_pdf.render(inputs(later))
    meta: Any = pypdf.PdfReader(io.BytesIO(data)).metadata
    assert meta["/CreationDate"] == "D:20270102030405Z"
