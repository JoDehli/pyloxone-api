"""Optional token persistence hook.

The library does not store tokens itself. An application passes an object
with two methods as ``token_store=`` to :class:`LoxoneConnection`:

- ``load() -> dict | None``: the dict saved last, or ``None``.
- ``save(token: dict | None) -> None``: called after every login and every
  refresh with the new token dict, and with ``None`` when the token is reset.

The dict has these keys: ``token``, ``valid_until``, ``hash_alg``,
``unsecure_password`` and ``binding`` (``url``, ``port``, ``user``). The
binding ties a stored token to the connection it was issued for, so a token
of another Miniserver or user is never offered.

File permissions and atomic writes belong to the application.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

from .const import TOKEN_MIN_REMAINING_SECONDS
from .loxone_token import LoxoneToken

_HASH_ALGS = ("SHA1", "SHA256")


class TokenStore(Protocol):
    """Application-side persistence for the Loxone token."""

    def load(self) -> Optional[dict[str, Any]]:
        """Return the token dict saved last, or ``None``."""
        ...

    def save(self, token: Optional[dict[str, Any]]) -> None:
        """Persist ``token``; ``None`` means the token was reset."""
        ...


def make_binding(url: str, port: int, user: str) -> dict[str, Any]:
    """The connection identity a token is bound to."""
    return {"url": url, "port": port, "user": user}


def token_from_store(data: Any, binding: dict[str, Any]) -> Optional[LoxoneToken]:
    """Turn stored data into a usable :class:`LoxoneToken`, or ``None``.

    ``None`` (no token) for anything that is not a complete, well-formed
    token bound to ``binding``, or that expires within
    ``TOKEN_MIN_REMAINING_SECONDS``.
    """
    if not isinstance(data, dict):
        return None
    token_str = data.get("token")
    valid_until = data.get("valid_until")
    hash_alg = data.get("hash_alg")
    unsecure = data.get("unsecure_password", False)

    if not isinstance(token_str, str) or not token_str:
        return None
    if isinstance(valid_until, bool) or not isinstance(valid_until, (int, float)):
        return None
    if valid_until <= 0:
        return None
    if hash_alg not in _HASH_ALGS:
        return None
    if not isinstance(unsecure, bool):
        return None

    stored_binding = data.get("binding")
    if stored_binding != binding:
        return None

    token = LoxoneToken(
        token=token_str,
        valid_until=valid_until,
        hash_alg=hash_alg,
        key="",
        unsecure_password=unsecure,
    )
    if token.seconds_to_expire() <= TOKEN_MIN_REMAINING_SECONDS:
        return None
    return token
