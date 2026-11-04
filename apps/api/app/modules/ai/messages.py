"""Broker messages of the `ai.*` tasks (M5 phase 1, FROZEN).

Tasks take one keyword argument, `message` (a dict), like every other CyberLab task. Messages
carry ids only: never context, model output, keys or provider data.
"""

import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.modules.ai.contracts import AiProviderName


class AiRunMessage(BaseModel):
    """`ai.run`: make progress on one run (one provider call at most per message, RT2). The
    worker re-checks the org against `ai_run_index` before touching anything."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: uuid.UUID
    org_id: uuid.UUID


class AiVerifyMessage(BaseModel):
    """`ai.verify`: check one provider key of one org after a key save. The worker re-reads
    the config in a tenant session of that org and drops the message when the stored
    `key_version` differs (a newer key has its own message)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    org_id: uuid.UUID
    provider: AiProviderName
    key_version: int = Field(ge=0)


class AiResumeMessage(BaseModel):
    """`ai.resume` (sent by ingest-beat every 30 s): no fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)
