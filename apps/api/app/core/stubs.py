"""`501 not_implemented` for routes frozen ahead of their implementation (M6 phase 1).

Every M6 route exists from phase 1 with its final path, method, permission dependency and
request / response models (so the contracts and the IDOR enumerator see it); its body
raises `not_implemented()` until the owning phase lands.
"""

from app.core.errors import AppError


class NotImplementedYet(AppError):
    status_code = 501
    code = "not_implemented"
    message = "This feature is not implemented yet"


def not_implemented() -> NotImplementedYet:
    return NotImplementedYet()
