"""The renderer's only URL fetcher: it refuses every URL (RT16).

WeasyPrint 70 sends every resource load through `URLFetcher.fetch`: `http(s):`, `file:`,
`data:` (urllib's DataHandler), `@import`, `@font-face url()`, `<img>`, `<link>`, SVG
references and attachments given as file names or URLs. Nothing is allowed here:

- the CSS is a trusted constant passed as `CSS(string=…)`;
- fonts come only from fontconfig (the bundled Noto set), never `@font-face url()`;
- the PDF attachments are passed as bytes;
- `base_url=None`, so a relative URL has nothing to resolve against and is dropped by
  WeasyPrint before any fetch.

`FetchBlocked` derives from `FatalURLFetchingError` (a `BaseException`), which WeasyPrint
does not swallow: the render stops at the first attempt. The fetcher also counts attempts,
so a block swallowed by a WeasyPrint `except BaseException` (SVG drawing) still fails the
render closed (`fetch_blocked`). The URL is never logged or echoed: it may carry data.
"""

from typing import Any, NoReturn

from weasyprint.urls import FatalURLFetchingError, URLFetcher


class FetchBlocked(FatalURLFetchingError):  # type: ignore[misc]
    """A resource fetch was attempted and refused (error code `fetch_blocked`)."""


class DenyAllFetcher(URLFetcher):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__(
            timeout=1, allowed_protocols=(), allow_redirects=False, fail_on_errors=True
        )
        self.attempts = 0

    def fetch(self, url: str, headers: Any = None) -> NoReturn:
        self.attempts += 1
        raise FetchBlocked("resource fetch blocked")

    def open(self, *args: Any, **kwargs: Any) -> NoReturn:
        """`urllib`'s entry point, unreachable through `fetch`: refused as well."""
        self.attempts += 1
        raise FetchBlocked("resource fetch blocked")

    def check(self) -> None:
        """After a render: any attempt, even one WeasyPrint swallowed, fails it."""
        if self.attempts:
            raise FetchBlocked("resource fetch blocked")
