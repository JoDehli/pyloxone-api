"""A websocket implementation with logging.

This class will log messages sent and received, at the DEBUG level.
"""
from __future__ import annotations

import logging
from typing import Any

from websockets.client import WebSocketClientProtocol

_LOGGER = logging.getLogger(__name__)


class Websocket(WebSocketClientProtocol):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    async def recv(self) -> str | bytes:
        result = await super().recv()
        _LOGGER.debug(f"Received: {result[:80]!r} ...")
        return result

    async def send(self, message: bytes | str) -> None:  # type: ignore[override]
        await super().send(message)
        _LOGGER.debug(f"Sent:{message}")
        return
