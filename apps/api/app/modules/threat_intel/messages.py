"""Broker message of the `ti.*` tasks (frozen in M4 phase 1).

Tasks take one keyword argument, `message` (a dict), like every other CyberLab task. The
message carries ids only: never IOC values, keys or provider data (RT11).
"""

import uuid

from pydantic import BaseModel, ConfigDict


class TiRunMessage(BaseModel):
    """`ti.enrich`: run one time slice of a run. The worker re-checks the org against
    `ti_run_index` before touching anything."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: uuid.UUID
    org_id: uuid.UUID


class TiVerifyMessage(BaseModel):
    """`ti.verify` (M4 phase 2, additive): check one provider key of one org. Published only
    by the API after an authorized integration change; the worker re-reads the config in a
    tenant session of that org and drops the message if there is no sealed key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    org_id: uuid.UUID
    provider: str


class TiResumeMessage(BaseModel):
    """`ti.resume` (sent by ingest-beat): no fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)
