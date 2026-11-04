"""The committed ATT&CK index file format and the label models served to the UI."""

from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

TECHNIQUE_ID_PATTERN = r"^T\d{4}(?:\.\d{3})?$"
TechniqueId = Annotated[str, StringConstraints(pattern=TECHNIQUE_ID_PATTERN)]
TacticShortname = Annotated[str, StringConstraints(pattern=r"^[a-z]+(?:-[a-z]+)*$")]

MITRE_NOTICE = (
    "© The MITRE Corporation. This work is reproduced and distributed with the permission "
    "of The MITRE Corporation."
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- index file (written by app/modules/attack/build.py) -----------------------------------


class AttackIndexMeta(_Strict):
    version: Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}$")]
    source_url: str
    source_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    built_at: str
    attack_spec: str


class AttackTechniqueEntry(_Strict):
    name: Annotated[str, StringConstraints(min_length=1)]
    tactics: tuple[TacticShortname, ...]
    is_subtechnique: bool
    parent: TechniqueId | None
    deprecated: bool
    revoked_by: TechniqueId | None
    url: str


class AttackIndexFile(_Strict):
    meta: AttackIndexMeta
    techniques: dict[TechniqueId, AttackTechniqueEntry] = Field(min_length=1)
    tactics: dict[TacticShortname, str] = Field(min_length=1)

    @model_validator(mode="after")
    def _references_resolve(self) -> Self:
        for tid, entry in self.techniques.items():
            for ref in (entry.parent, entry.revoked_by):
                if ref is not None and ref not in self.techniques:
                    raise ValueError(f"{tid} references unknown technique {ref}")
            unknown = set(entry.tactics) - self.tactics.keys()
            if unknown:
                raise ValueError(f"{tid} references unknown tactics {sorted(unknown)}")
        return self


# --- API ------------------------------------------------------------------------------------


class AttackTactic(_Strict):
    shortname: str
    name: str


class AttackLabel(_Strict):
    """One requested id. `technique_id` differs from `id` when `id` was revoked and replaced."""

    id: str
    technique_id: str
    name: str
    tactics: list[AttackTactic]
    is_subtechnique: bool
    parent: str | None
    parent_name: str | None
    deprecated: bool
    revoked: bool
    url: str


class AttackMeta(_Strict):
    version: str
    attack_spec: str
    built_at: str
    notice: str = MITRE_NOTICE


class AttackTechniquesOut(_Strict):
    meta: AttackMeta
    techniques: list[AttackLabel]
    unknown: list[str]
