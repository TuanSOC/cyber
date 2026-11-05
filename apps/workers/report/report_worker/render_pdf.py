"""Snapshot -> PDF/A-3a with WeasyPrint 70 (runs only inside the sandboxed subprocess).

Every option is a constant, never derived from data (RT16, RT17):

- `HTML(string=…, base_url=None, url_fetcher=DenyAllFetcher())` and the constant
  stylesheet `CSS(string=REPORT_CSS_TEXT, url_fetcher=DenyAllFetcher())`;
- `pdf_variant="pdf/a-3a"` (tagged, with the sRGB output intent that 69.0 renamed from
  `srgb` to `output_intent` and every PDF/A variant forces), `presentational_hints=False`,
  `custom_metadata=False`, compressed;
- `pdf_identifier` = the first 16 bytes of the snapshot sha256, and the document and
  attachment dates = `finalized_at` (WeasyPrint otherwise omits the document dates and
  stamps attachments with "now"): the same snapshot gives byte-identical output with the
  same image and `RENDERER_VERSION` (RT17);
- the attachments `snapshot.json`, `manifest.json` and `manifest.sig.json` are passed as
  bytes (relationship `Source`), never as file names, which would go through the fetcher.

The page count is checked after layout and before the PDF is written (`too_many_pages`).
"""

from dataclasses import dataclass
from datetime import datetime

from cyberlab_jobs.report import MAX_PAGES, ReportSnapshot
from weasyprint import CSS, HTML, Attachment

from report_worker import render_html
from report_worker.fetch import DenyAllFetcher

PDF_VARIANT = "pdf/a-3a"
REPORT_CSS = CSS(string=render_html.REPORT_CSS_TEXT, url_fetcher=DenyAllFetcher())


class TooManyPages(Exception):
    def __init__(self, pages: int) -> None:
        super().__init__(f"{pages} pages")
        self.pages = pages


@dataclass(frozen=True)
class PdfInputs:
    snapshot: ReportSnapshot
    snapshot_bytes: bytes
    sha256: str
    manifest_bytes: bytes
    signature_bytes: bytes
    finalized_at: datetime


def _attachments(inputs: PdfInputs, fetcher: DenyAllFetcher) -> list[Attachment]:
    def attachment(data: bytes, name: str, description: str) -> Attachment:
        return Attachment(
            string=data,
            base_url=None,
            url_fetcher=fetcher,
            name=name,
            description=description,
            created=inputs.finalized_at,
            modified=inputs.finalized_at,
            relationship="Source",
        )

    return [
        attachment(inputs.snapshot_bytes, "snapshot.json", "Signed report snapshot"),
        attachment(inputs.manifest_bytes, "manifest.json", "Signed manifest"),
        attachment(inputs.signature_bytes, "manifest.sig.json", "Ed25519 signature"),
    ]


def render(inputs: PdfInputs, *, max_pages: int = MAX_PAGES) -> tuple[bytes, int]:
    """(PDF bytes, page count). Raises `FetchBlocked`, `TooManyPages`."""
    fetcher = DenyAllFetcher()
    html = render_html.render(inputs.snapshot, sha256=inputs.sha256, mode="pdf")
    # The same constant options for layout and for the PDF writer (WeasyPrint applies the
    # PDF/A variant's defaults, tags and the output intent, in `write_pdf`).
    options = {
        "stylesheets": [REPORT_CSS],
        "presentational_hints": False,
        "pdf_variant": PDF_VARIANT,
        "pdf_identifier": bytes.fromhex(inputs.sha256)[:16],
        "attachments": _attachments(inputs, fetcher),
        "custom_metadata": False,
        "uncompressed_pdf": False,
    }
    document = HTML(string=html, base_url=None, url_fetcher=fetcher).render(**options)
    fetcher.check()
    pages = len(document.pages)
    if pages > max_pages:
        raise TooManyPages(pages)
    data: bytes = document.write_pdf(**options)
    fetcher.check()
    return data, pages
