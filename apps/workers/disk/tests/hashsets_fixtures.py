"""Synthetic hash-set inputs for the M9 phase 5 tests (never real NSRL data; nothing is ever
downloaded). `make_rdsv3` writes a SQLite file in the documented RDSv3 shape (a `FILE` table
with `sha256, sha1, md5, crc32, file_name, file_size, package_id`, the minimal set's
`DISTINCT_HASH` view and a `METADATA` table) filled with our own random digests."""

import hashlib
import random
import sqlite3
from pathlib import Path


def digests(seed: int, n: int) -> list[tuple[str, str, str]]:
    """n (sha256, sha1, md5) triples of random content, deterministic per seed."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        blob = rng.randbytes(24)
        out.append(
            (
                hashlib.sha256(blob).hexdigest(),
                hashlib.sha1(blob).hexdigest(),  # noqa: S324 - fixture digests
                hashlib.md5(blob).hexdigest(),  # noqa: S324 - fixture digests
            )
        )
    return out


def make_rdsv3(
    path: Path,
    rows: list[tuple[str, str, str]],
    *,
    distinct_view: bool = True,
    upper: bool = True,
    drop_columns: tuple[str, ...] = (),
    extra_rows: list[tuple[object, object, object]] = (),  # type: ignore[assignment]
) -> Path:
    columns = [
        ("sha256", "TEXT"),
        ("sha1", "TEXT"),
        ("md5", "TEXT"),
        ("crc32", "TEXT"),
        ("file_name", "TEXT"),
        ("file_size", "INTEGER"),
        ("package_id", "INTEGER"),
    ]
    columns = [c for c in columns if c[0] not in drop_columns]
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE METADATA (key TEXT, value TEXT)")
        conn.execute("INSERT INTO METADATA VALUES ('synthetic', 'cyberlab test fixture')")
        conn.execute(f"CREATE TABLE FILE ({', '.join(f'{n} {t}' for n, t in columns)})")
        names = [n for n, _ in columns]
        all_rows: list[tuple[object, object, object]] = [*rows, *extra_rows]
        for i, (sha256, sha1, md5) in enumerate(all_rows):
            values: dict[str, object] = {
                "sha256": sha256.upper() if upper and isinstance(sha256, str) else sha256,
                "sha1": sha1.upper() if upper and isinstance(sha1, str) else sha1,
                "md5": md5.upper() if upper and isinstance(md5, str) else md5,
                "crc32": "00000000",
                "file_name": f"synthetic_{i}.bin",
                "file_size": i,
                "package_id": i % 7,
            }
            conn.execute(
                f"INSERT INTO FILE ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})",
                [values[n] for n in names],
            )
        if distinct_view and {"sha256", "sha1", "md5"} <= set(names):
            conn.execute(
                "CREATE VIEW DISTINCT_HASH AS SELECT DISTINCT sha256, sha1, md5 FROM FILE"
            )
        conn.commit()
    finally:
        conn.close()
    return path


def make_list(path: Path, values: list[str], *, md5sum_style: bool = True) -> Path:
    lines = ["# synthetic hash list (cyberlab test fixture)", ""]
    for i, value in enumerate(values):
        lines.append(f"{value}  *file_{i}.exe" if md5sum_style and i % 2 else value)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
