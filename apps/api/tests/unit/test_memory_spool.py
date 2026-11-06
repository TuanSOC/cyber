"""The memory upload's spool reservation (review fix): a chunked body reserves the memory
limit, concurrent memory uploads in one process never take the same free space, and a
reservation is released when its upload ends, whatever happened."""

import shutil
from collections import namedtuple

import pytest

from app.core.config import get_settings
from app.modules.evidence import uploads
from app.modules.memory_analysis.errors import InsufficientStorage

GIB = 1024**3
Usage = namedtuple("Usage", "total used free")


@pytest.fixture
def free(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    value = [0]
    monkeypatch.setattr(shutil, "disk_usage", lambda _: Usage(0, 0, value[0]))
    monkeypatch.setattr(uploads, "_spool_reserved", 0)
    return value


def test_a_chunked_body_reserves_the_memory_limit() -> None:
    assert uploads.spool_reservation("memory", 0) == get_settings().memory_max_bytes
    assert uploads.spool_reservation("memory", 4096) == 4096


def test_concurrent_reservations_add_up(free: list[int]) -> None:
    free[0] = 3 * GIB + uploads.MEMORY_SPOOL_RESERVE_BYTES
    with uploads._reserve_spool("/spool", 2 * GIB):
        assert uploads._spool_reserved == 2 * GIB
        with pytest.raises(InsufficientStorage):  # 3 GiB free, 2 GiB promised: 1 GiB left
            with uploads._reserve_spool("/spool", 2 * GIB):
                pass
        with uploads._reserve_spool("/spool", GIB):
            assert uploads._spool_reserved == 3 * GIB
    assert uploads._spool_reserved == 0


def test_a_reservation_is_released_on_error(free: list[int]) -> None:
    free[0] = 2 * GIB + uploads.MEMORY_SPOOL_RESERVE_BYTES
    with pytest.raises(RuntimeError), uploads._reserve_spool("/spool", GIB):
        raise RuntimeError("upload failed")
    assert uploads._spool_reserved == 0
