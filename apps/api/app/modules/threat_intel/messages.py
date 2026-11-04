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
