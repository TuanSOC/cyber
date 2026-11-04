"""The synthetic sample set: deterministic, labelled, inert."""

import hashlib
from pathlib import Path

from samples import elf, pe
from samples.generate import TEST_MARKER, eicar, generate
from tests.conftest import CLAMAV_TEST_DB, SampleSet, in_container

REQUIRED = {"profile", "file_format", "findings", "signatures", "iocs", "capabilities", "benign"}


def test_eicar_is_assembled_at_runtime_and_matches_the_test_db() -> None:
    data = eicar()
    assert len(data) == 68
    digest = hashlib.md5(data).hexdigest()  # noqa: S324 - the EICAR hash signature format
    assert (CLAMAV_TEST_DB / "cyberlab-test.hdb").read_text().startswith(f"{digest}:68:")
    marker_hex = TEST_MARKER.encode().hex()
    assert marker_hex in (CLAMAV_TEST_DB / "cyberlab-test.ndb").read_text()


def test_no_sample_binary_is_committed() -> None:
    root = Path(__file__).parents[2]
    for path in [*root.glob("samples/**/*"), *root.glob("tests/**/*")]:
        if path.is_file():
            assert path.suffix in {
                ".py",
                ".pyc",
                ".c",
                ".json",
                ".yar",
                ".yml",
                ".hdb",
                ".ndb",
                ".md",
            }, path


def test_builders_produce_expected_magic() -> None:
    image = pe.build(pe.PeSpec(sections=[pe.Section(".text", b"\xc3", pe.TEXT)]))
    assert (
        image[:2] == b"MZ" and image[int.from_bytes(image[0x3C:0x40], "little") :][:4] == b"PE\0\0"
    )
    obj = elf.build(elf.ElfSpec())
    assert obj[:4] == b"\x7fELF" and obj[4] == 2


@in_container
def test_set_is_deterministic_and_labelled(sample_set: SampleSet, tmp_path: Path) -> None:
    again = generate(tmp_path / "again")
    assert set(again) == set(sample_set.paths)
    for name, path in sample_set.paths.items():
        assert path.read_bytes() == again[name].read_bytes(), name
        label = sample_set.labels[name]
        assert REQUIRED <= set(label), name
        assert label["profile"] in {"full", "av"}
    assert {"mingw_hello", "mingw_hello32", "mingw_injector"} <= set(sample_set.paths)
    assert all(p.stat().st_size < 1024**2 for p in sample_set.paths.values())
