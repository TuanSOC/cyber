from typing import Annotated

from pydantic import StringConstraints

# Control chars plus invisible format chars (zero-width, bidi overrides/isolates, BOM) that
# could spoof how a name is displayed. NUL would also break Postgres text.
_UNSAFE_NAME_CHARS = r"\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿"

# Human-readable names: trimmed, single line, no control/format characters.
SafeName = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=rf"^[^{_UNSAFE_NAME_CHARS}]+$")
]

# Free-text search/filter terms: never NUL (Postgres text cannot hold it).
SearchTerm = Annotated[
    str, StringConstraints(strip_whitespace=True, max_length=200, pattern=r"^[^\x00]*$")
]
