"""The committed Enterprise ATT&CK index: loaded once, validated at import, labels by T-id."""

from functools import lru_cache
from pathlib import Path

from app.modules.attack.schemas import (
    AttackIndexFile,
    AttackLabel,
    AttackMeta,
    AttackTactic,
)

# Bump together with the committed file (see scripts/build_attack_index.py).
INDEX_VERSION = "20.0"
DATA_DIR = Path(__file__).resolve().parent / "data"
INDEX_PATH = DATA_DIR / f"attack_enterprise_v{INDEX_VERSION}.json"
# Revocation chains in v20 are at most two hops; the cap only guards a corrupt file.
_MAX_REVOCATION_HOPS = 8


def load_index(path: Path) -> AttackIndexFile:
    return AttackIndexFile.model_validate_json(path.read_bytes())


@lru_cache(maxsize=1)
def get_index() -> AttackIndexFile:
    index = load_index(INDEX_PATH)
    if index.meta.version != INDEX_VERSION:
        raise ValueError(f"{INDEX_PATH.name} holds ATT&CK {index.meta.version}")
    return index


def meta() -> AttackMeta:
    m = get_index().meta
    return AttackMeta(version=m.version, attack_spec=m.attack_spec, built_at=m.built_at)


def label(tid: str, index: AttackIndexFile | None = None) -> AttackLabel | None:
    """Label one T-id; a revoked id resolves to its replacement, deprecated ones are flagged."""
    if index is None:
        index = get_index()
    entry = index.techniques.get(tid)
    if entry is None:
        return None
    resolved, revoked = tid, False
    for _ in range(_MAX_REVOCATION_HOPS):
        if entry.revoked_by is None:
            break
        revoked = True
        resolved = entry.revoked_by
        entry = index.techniques[resolved]
    parent = index.techniques.get(entry.parent) if entry.parent else None
    return AttackLabel(
        id=tid,
        technique_id=resolved,
        name=entry.name,
        tactics=[AttackTactic(shortname=s, name=index.tactics[s]) for s in entry.tactics],
        is_subtechnique=entry.is_subtechnique,
        parent=entry.parent,
        parent_name=parent.name if parent else None,
        deprecated=entry.deprecated,
        revoked=revoked,
        url=entry.url,
    )


# Validate the committed file at import, so a broken index fails startup rather than a request.
get_index()
