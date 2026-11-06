"""Root-side normalizers of the probe output (M9 phase 2; phase 3 adds `events`).

- `reader`: bounded JSONL / status reads over an already safely opened file;
- `models`: the per-stage row models (pydantic, `extra="forbid"`, bounded);
- `records`: rows -> `DiskPartitionRecord` / `DiskFileRecord`, the per-inode name index for
  the never-collected check and the hard-link flags (RT7).

Every probe row is re-validated; a bad row is dropped and counted, and a stage with more than
1 % bad rows is marked `failed` (`BAD_ROW_RATIO`).
"""

BAD_ROW_RATIO = 0.01
