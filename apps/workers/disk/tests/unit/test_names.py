"""Names and the mirrored-tree sanitizer (M9 phase 2, RT13 / RT31). Pure: runs anywhere."""

import pytest

from disk_worker.probe import names


def test_names_are_printable_single_line_and_flag_lossy_bytes() -> None:
    assert names.display_name(b"report.docx") == ("report.docx", False)
    assert names.display_name(b"a\nb\x00c\x7f") == (r"a\x0ab\x00c\x7f", False)
    shown, lossy = names.display_name(b"caf\xe9")
    assert lossy and shown == "caf�"
    # RTLO stays visible (detections flag it), it is not a control character.
    assert names.display_name("x‮txt.exe".encode())[0] == "x‮txt.exe"


def test_a_name_is_cut_to_1024_bytes_on_a_character_boundary() -> None:
    shown, _ = names.display_name(("é" * 600).encode())
    assert len(shown.encode()) <= 1024
    assert shown == "é" * 512


def test_long_paths_are_cut_on_a_utf8_boundary_and_flagged() -> None:
    deep = "/" + "/".join(["ä" * 127] * 64)  # 64 levels of 254-byte names (> 16 KB)
    path, cut = names.bounded_path(deep)
    assert cut and len(path.encode()) <= 4096
    path.encode("utf-8")  # still valid UTF-8
    assert names.bounded_path("/etc/passwd") == ("/etc/passwd", False)


def test_join_path() -> None:
    assert names.join_path("", "etc") == "/etc"
    assert names.join_path("/etc", "shadow") == "/etc/shadow"


@pytest.mark.parametrize("bad", ["..", ".", "...", ""])
def test_dot_and_empty_components_are_refused(bad: str) -> None:
    with pytest.raises(names.UnsafeName):
        names.sanitize_component(bad, False)


def test_path_separators_nul_and_rtlo_never_survive() -> None:
    for comp in ("a/b", "a\x00b", "x‮txt.exe", "a:b", 'a"b'):
        out = names.sanitize_component(comp, False)
        assert "/" not in out and "‮" not in out and ":" not in out
        assert names.is_safe_relative(out)
    # `..` inside a path is a component made only of dots: refused, whatever comes after.
    with pytest.raises(names.UnsafeName):
        names.sanitize_relative("/a/../etc/passwd", False)


def test_non_ascii_components_stay_distinct() -> None:
    jose = names.sanitize_component("José", False)
    jos_q = names.sanitize_component("Jos?", False)
    jos_u = names.sanitize_component("Jos_", False)
    assert len({jose, jos_q, jos_u}) == 3
    assert jose.startswith("Jos_") and len(jose) == len("Jos_") + 7
    assert jos_u == "Jos_"  # nothing replaced: unchanged


def test_300_byte_names_are_cut_to_255_with_a_hash() -> None:
    a = names.sanitize_component("a" * 300, False)
    b = names.sanitize_component("a" * 299 + "b", False)
    assert len(a.encode()) <= 255 and len(b.encode()) <= 255
    assert a != b


def test_canonical_case_only_on_case_insensitive_file_systems() -> None:
    parts = names.sanitize_relative("/WINDOWS/system32/CONFIG/system", True)
    assert parts == ["Windows", "System32", "config", "SYSTEM"]
    assert names.sanitize_relative("/Users/bob/ntuser.dat", True) == ["Users", "bob", "NTUSER.DAT"]
    assert names.sanitize_relative("/etc/Config", False) == ["etc", "Config"]


def test_case_collisions_get_a_suffix_that_keeps_the_extension() -> None:
    assert names.with_collision_suffix("SYSTEM", 2) == "SYSTEM_c2"
    assert names.with_collision_suffix("auth.log", 3) == "auth_c3.log"
    assert names.with_collision_suffix(".bashrc", 2) == ".bashrc_c2"


def test_root_rechecks_reported_targets() -> None:
    assert names.is_safe_relative("Windows/System32/config/SYSTEM")
    assert names.is_safe_relative("$Recycle.Bin/x")
    for bad in ("/etc/passwd", "a/../b", "a//b", "a/./b", "a/b\x00", "a/é", ""):
        assert not names.is_safe_relative(bad)
