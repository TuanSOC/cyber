"""Image openers (probe side): raw, split raw and EWF, all handed to TSK as *external* images.

TSK never opens a path itself (`TSK_IMG_TYPE_EXTERNAL`): with `TSK_IMG_TYPE_DETECT` it would
probe its own image back ends (EWF, VMDK, VHD, AFF where built in) on hostile bytes. Our
readers are the only code reading the segment files:
- `SegmentReader` (raw and split raw): the root-named segment files (`O_NOFOLLOW`, regular),
  concatenated with bounds-checked reads (a read past the end is short, never an error);
- `EwfReader`: `pyewf.handle().open(pyewf.glob(<input>/image.E01))`. libewf checks each
  segment's stored number against its position, so a reordered, foreign or missing segment,
  or a lying segment count, fails the open → `ImageError("unsupported_disk_format")` with the
  libewf exception class. `glob` is given root's fixed first-segment path, never a path from
  the image, and must return exactly root's segment files. A claimed media size above
  `max_media_bytes` is refused (reason `media_size`; RT6).

pytsk3 / pyewf are imported lazily so the pure parts stay testable on any host.
"""

import bisect
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

MAX_READ = 64 * 1024**2  # one TSK read request (TSK asks for clusters / runs, never GiBs)
DEFAULT_SECTOR = 512


class ImageError(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        # A snake_case word (root validates `reason` as one): `ewf_OSError` -> `ewf_oserror`.
        self.reason = "".join(c for c in reason.lower() if c.isalnum() or c == "_")[:64] or "x"


class Reader(Protocol):
    size: int
    sector_size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def close(self) -> None: ...


def _open_regular(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ImageError("unsupported_disk_format", "segment_not_regular")
    return fd


class SegmentReader:
    """One logical media over ordered segment files (one for raw)."""

    sector_size = DEFAULT_SECTOR

    def __init__(self, paths: Sequence[Path]) -> None:
        if not paths:
            raise ImageError("unsupported_disk_format", "no_segments")
        self._fds: list[int] = []
        self._starts: list[int] = []
        total = 0
        try:
            for path in paths:
                fd = _open_regular(path)
                self._fds.append(fd)
                self._starts.append(total)
                total += os.fstat(fd).st_size
        except BaseException:
            self.close()
            raise
        self.size = total

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, MAX_READ, self.size - offset)
        out = bytearray()
        while length > 0:
            # The last segment starting at or before `offset` (empty segments are skipped).
            i = bisect.bisect_right(self._starts, offset) - 1
            end = self._starts[i + 1] if i + 1 < len(self._starts) else self.size
            chunk = os.pread(self._fds[i], min(length, end - offset), offset - self._starts[i])
            if not chunk:
                break  # a segment shorter than at open: stop, never loop
            out += chunk
            offset += len(chunk)
            length -= len(chunk)
        return bytes(out)

    def close(self) -> None:
        for fd in self._fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds = []


class EwfReader:
    def __init__(self, first_segment: Path, expected: Sequence[Path], max_media: int) -> None:
        import pyewf  # noqa: PLC0415 - the probe's only libewf import

        try:
            found = [Path(p) for p in pyewf.glob(str(first_segment))]
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ImageError("unsupported_disk_format", f"ewf_{type(exc).__name__}") from exc
        if sorted(os.path.realpath(p) for p in found) != sorted(
            os.path.realpath(p) for p in expected
        ):
            raise ImageError("unsupported_disk_format", "ewf_segment_set")
        self._handle = pyewf.handle()
        try:
            self._handle.open([str(p) for p in expected])
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ImageError("unsupported_disk_format", f"ewf_{type(exc).__name__}") from exc
        self.size = int(self._handle.get_media_size())
        if not 0 < self.size <= max_media:
            self.close()
            raise ImageError("unsupported_disk_format", "media_size")
        try:
            sector = int(self._handle.get_bytes_per_sector())
        except (OSError, RuntimeError, AttributeError):
            sector = DEFAULT_SECTOR
        self.sector_size = sector if sector in (512, 1024, 2048, 4096) else DEFAULT_SECTOR

    @property
    def handle(self) -> Any:
        return self._handle

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, MAX_READ, self.size - offset)
        return bytes(self._handle.read_buffer_at_offset(length, offset))

    def close(self) -> None:
        try:
            self._handle.close()
        except (OSError, RuntimeError):
            pass


@dataclass
class OpenedImage:
    reader: Reader
    img: Any  # pytsk3.Img_Info over `reader`
    format: str
    extra: dict[str, Any] = field(default_factory=dict)

    def close(self) -> None:
        self.reader.close()


def tsk_image(reader: Reader) -> Any:
    """A pytsk3 `Img_Info` reading through `reader` (TSK_IMG_TYPE_EXTERNAL)."""
    import pytsk3  # noqa: PLC0415

    class _External(pytsk3.Img_Info):  # type: ignore[misc]
        def __init__(self, source: Reader) -> None:
            self._source = source
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self) -> None:
            self._source.close()

        def read(self, offset: int, size: int) -> bytes:
            return self._source.read(offset, size)

        def get_size(self) -> int:
            return self._source.size

    return _External(reader)


def open_image(spec: dict[str, Any]) -> OpenedImage:
    """`spec` (root-written): `format`, `paths` (absolute, root's fixed names), `max_media`."""
    fmt = spec["format"]
    paths = [Path(p) for p in spec["paths"]]
    max_media = int(spec["max_media"])
    if not paths or not all(p.is_absolute() for p in paths):
        raise ImageError("unsupported_disk_format", "paths")
    reader: Reader
    if fmt in ("raw", "split_raw"):
        reader = SegmentReader(paths)
        if reader.size > max_media:
            reader.close()
            raise ImageError("unsupported_disk_format", "media_size")
    elif fmt == "ewf":
        reader = EwfReader(paths[0], paths, max_media)
    else:
        raise ImageError("unsupported_disk_format", "format")
    try:
        img = tsk_image(reader)
    except BaseException:
        reader.close()
        raise
    return OpenedImage(reader=reader, img=img, format=fmt)


def tsk_int(value: Any) -> int:
    """pytsk3 enum / int → int (enum values support `int()`; some builds expose `.value`)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(getattr(value, "value", 0))


__all__ = [
    "EwfReader",
    "ImageError",
    "OpenedImage",
    "Reader",
    "SegmentReader",
    "open_image",
    "tsk_image",
    "tsk_int",
]
