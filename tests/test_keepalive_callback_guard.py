"""Regression tests for the KEEPALIVE dispatch callback guard.

Background
----------
``_do_start_listening`` dispatches every bodyless KEEPALIVE frame through
an inner ``_run_callback`` helper. For body-carrying frames the dispatch
is guarded by ``if callback and ...`` (an external callback is optional),
but the KEEPALIVE path used to schedule ``_run_callback(Keepalive(""))``
unconditionally.

When ``callback is None`` — which is exactly how the internal bootstrap
listener in ``open()`` starts its session (``start_listening(callback=None)``)
— the first keepalive (~every 30 s) called ``None({...})`` and raised
``TypeError: 'NoneType' object is not callable``, caught and logged as
``Callback error: ...``. Harmless (the connection keeps running) but it
is log noise on every bootstrap that outlives one keepalive interval
(e.g. a slow structure-file download over a relay).

These tests pin the behaviour both ways:

* with ``callback=None`` a keepalive must NOT produce a "Callback error",
* with a real callback a keepalive must still be delivered (the guard
  must not silence legitimate keepalive callbacks).
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.message import MessageType

# Loxone binary header: struct ``<cBccI`` =
#   byte0 = 0x03 (binary frame marker)
#   byte1 = message type (KEEPALIVE == 6)
#   byte2 = info flags (bit7 = estimated); 0x00 = exact
#   byte3 = reserved
#   byte4..7 = payload length (little-endian) == 0 for a bodyless keepalive
KEEPALIVE_HEADER = bytes([0x03, int(MessageType.KEEPALIVE), 0x00, 0x00, 0, 0, 0, 0])


class _FrameFeedWebsocket:
    """Fake ``websockets.ClientConnection`` that yields a fixed list of
    frames once, then ends the iteration cleanly (peer closed, code 1000).

    ``state`` mimics the real ``state``/``state.CLOSED`` enum access the
    recv loop performs; it always reports OPEN so the loop processes the
    frames rather than bailing out on the "connection closed" check.
    """

    state = type(
        "S", (), {"CLOSED": "CLOSED", "name": "OPEN"}
    )()  # state == state.CLOSED -> False

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = list(frames)

    async def send(self, *args, **kwargs):
        return None

    async def close(self, *args, **kwargs):
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._frames:
            return self._frames.pop(0)
        raise StopAsyncIteration


def _make_conn() -> LoxoneConnection:
    return LoxoneConnection(
        host="192.0.2.1",
        username="user",
        password="password",
        port=8080,
    )


async def _drive_listener(conn: LoxoneConnection, callback, frames: list[bytes]):
    """Run one pass of the recv loop over ``frames`` and let any
    fire-and-forget dispatch tasks (keepalive callback) finish.

    The loop raises ``LoxoneConnectionClosedOk`` when the fake peer ends
    the iteration cleanly; that is expected control flow here.
    """
    from pyloxone_api.exceptions import LoxoneConnectionClosedOk

    ws = _FrameFeedWebsocket(frames)
    with pytest.raises(LoxoneConnectionClosedOk):
        await conn._do_start_listening(callback, ws)

    # The keepalive callback is dispatched via ``_spawn_task`` (tracked in
    # ``conn._tasks``); give those background tasks a turn to run so the
    # error (if any) is actually logged before we assert on it.
    pending = [t for t in conn._tasks if not t.done()]
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_keepalive_with_none_callback_logs_no_error(caplog):
    """callback=None + KEEPALIVE must not raise/​log a "Callback error".

    This is the bootstrap-listener case from ``open()``.
    """
    conn = _make_conn()
    with caplog.at_level(logging.ERROR, logger="pyloxone_api.connection"):
        await _drive_listener(conn, None, [KEEPALIVE_HEADER])

    assert "Callback error" not in caplog.text
    assert "NoneType" not in caplog.text


@pytest.mark.asyncio
async def test_keepalive_with_real_callback_is_delivered():
    """A real callback must still receive the keepalive liveness event,
    so the guard does not silence legitimate keepalive callbacks.
    """
    conn = _make_conn()
    received: list[dict] = []

    def callback(msg):
        received.append(msg)

    await _drive_listener(conn, callback, [KEEPALIVE_HEADER])

    assert received == [{"keep_alive": "received"}]
