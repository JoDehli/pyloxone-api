"""Close codes 4007 (update) and 4008 (no event slot) use the normal backoff.

A long fixed wait (300 s) was tried first. It made reconnects after a
Miniserver update slower than before, and its need was never measured. Until
the event-slot check (``hasEventSlots``) is in place, these codes use the same
backoff as any other session error: ``min(base * 2**(n-1), max_delay)`` with
±20 % jitter.
"""

from __future__ import annotations

import pytest
import websockets.exceptions
from websockets.frames import Close

from pyloxone_api import connection as conn_mod
from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.exceptions import LoxoneNoEventSlotsError


def _closed(code: int) -> websockets.exceptions.ConnectionClosed:
    return websockets.exceptions.ConnectionClosed(Close(code, ""), None)


@pytest.fixture
def conn():
    return LoxoneConnection(
        host="192.0.2.1", username="user", password="password", port=8080
    )


async def _run_with(conn, monkeypatch, errors) -> list[float]:
    remaining = list(errors)

    async def fake_start_listening(self, callback=None):
        if remaining:
            raise remaining.pop(0)
        conn._shutdown_event.set()
        return None

    async def fake_close(self):
        return None

    sleeps: list[float] = []
    original_sleep = conn_mod.asyncio.sleep

    async def record_sleep(delay):
        if delay:
            sleeps.append(delay)
        return await original_sleep(0)

    monkeypatch.setattr(LoxoneConnection, "start_listening", fake_start_listening)
    monkeypatch.setattr(LoxoneConnection, "close", fake_close)
    monkeypatch.setattr(conn_mod.asyncio, "sleep", record_sleep)

    await conn.run(base_delay=1.0, max_delay=60)
    return sleeps


class TestNormalBackoffForUpdateAndSlotCodes:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("code", [4007, 4008, 1006])
    async def test_close_code_uses_normal_backoff(self, conn, monkeypatch, code):
        sleeps = await _run_with(conn, monkeypatch, [_closed(code)])
        assert len(sleeps) == 1
        assert 0.8 <= sleeps[0] <= 1.2, sleeps[0]

    @pytest.mark.asyncio
    async def test_no_event_slots_uses_normal_backoff(self, conn, monkeypatch):
        sleeps = await _run_with(
            conn, monkeypatch, [LoxoneNoEventSlotsError("no slot")]
        )
        assert len(sleeps) == 1
        assert 0.8 <= sleeps[0] <= 1.2, sleeps[0]

    @pytest.mark.asyncio
    async def test_backoff_never_exceeds_one_minute(self, conn, monkeypatch):
        sleeps = await _run_with(conn, monkeypatch, [_closed(4007)] * 10)
        assert max(sleeps) <= 60 * 1.2, max(sleeps)
