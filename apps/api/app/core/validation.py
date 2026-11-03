from typing import Annotated

from pydantic import StringConstraints

# Human-readable names: trimmed, no control characters (NUL would also break Postgres text).
SafeName = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[^\x00-\x1f\x7f]+$")]
