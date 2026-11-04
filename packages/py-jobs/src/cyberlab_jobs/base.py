from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    """Contract base: unknown fields are rejected, instances are immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)


Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
# secrets.token_urlsafe(32) -> 43 chars of [A-Za-z0-9_-]
Token = Annotated[str, Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
ErrorCode = Annotated[str, Field(pattern=r"^[a-z][a-z_]{0,63}$")]
ShortText = Annotated[str, Field(max_length=255)]
