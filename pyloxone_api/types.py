"""Various types."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pyloxone_api.message import TextMessage

if TYPE_CHECKING:
    from pyloxone_api.tokens import LoxoneToken


class MiniserverProtocol(Protocol):
    """Protocol, used only for type checking the mixins.

    These attributes and methods must have the same types as those in the main
    Miniserver class"""

    _host: str
    _password: str
    _port: int
    _tls_check_hostname: bool
    if TYPE_CHECKING:
        _token: LoxoneToken
    _use_tls: bool
    _user: str
    _https_status: int

    async def _send_text_command(
        self, command: str = "", encrypted: bool = False
    ) -> TextMessage:
        ...
