"""Preflight over ``jdev/cfg/api`` and the ``local_only`` option (4.9).

Before the websocket opens, ``hasEventSlots`` from ``/jdev/cfg/api`` is read:

- ``hasEventSlots == False``: retryable ``LoxoneNoEventSlotsError`` with the
  long wait of 4.4 (the supervisor waits, it does not give up).
- Lookup fails or the value is unreadable: no verdict, connect as before.

``local`` from ``apiKey`` is checked as well. With ``local_only=True`` a
remote Miniserver is refused with a final ``LoxoneRemoteAccessDeniedError``
(not retried). With the default ``local_only=False`` nothing changes.
"""

from __future__ import annotations

import pytest

from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.const import CMD_GET_API_CONFIG
from pyloxone_api.exceptions import (
    LoxoneConnectionError,
    LoxoneException,
    LoxoneNoEventSlotsError,
    LoxoneRemoteAccessDeniedError,
)


def _ll(value: str) -> bytes:
    """An LL envelope as the Miniserver returns it for a cfg query."""
    return (
        '{"LL": {"control": "dev/cfg/api", "code": "200", "value": "'
        + value.replace('"', '\\"')
        + '"}}'
    ).encode()


def _conn(**kwargs) -> LoxoneConnection:
    return LoxoneConnection(
        host="192.0.2.1", username="user", password="pw", port=8080, **kwargs
    )


class _Fetch:
    """Stands in for ``_get_with_retry``: returns a body or raises."""

    def __init__(self, body: bytes | None = None, exc: Exception | None = None):
        self.body = body
        self.exc = exc
        self.calls: list[str] = []

    async def __call__(self, command, connector):
        self.calls.append(command)
        if self.exc is not None:
            raise self.exc
        return self.body, ""


class TestEventSlotsPreflight:
    @pytest.mark.asyncio
    async def test_no_event_slots_raises_retryable(self, monkeypatch):
        conn = _conn()
        fetch = _Fetch(_ll("{'version': '17.2.10.21', 'hasEventSlots': false}"))
        monkeypatch.setattr(conn, "_get_with_retry", fetch)

        with pytest.raises(LoxoneNoEventSlotsError) as info:
            await conn._check_event_slots(object())

        assert isinstance(info.value, LoxoneConnectionError)
        assert fetch.calls == [CMD_GET_API_CONFIG]

    @pytest.mark.asyncio
    async def test_event_slots_available_passes(self, monkeypatch):
        conn = _conn()
        monkeypatch.setattr(
            conn,
            "_get_with_retry",
            _Fetch(_ll("{'version': '17.2.10.21', 'hasEventSlots': true}")),
        )
        assert await conn._check_event_slots(object()) is None

    @pytest.mark.asyncio
    async def test_failed_lookup_is_no_verdict(self, monkeypatch):
        conn = _conn()
        monkeypatch.setattr(
            conn, "_get_with_retry", _Fetch(exc=OSError("unreachable"))
        )
        assert await conn._check_event_slots(object()) is None

    @pytest.mark.asyncio
    async def test_unreadable_value_is_no_verdict(self, monkeypatch):
        conn = _conn()
        monkeypatch.setattr(conn, "_get_with_retry", _Fetch(_ll("not json")))
        assert await conn._check_event_slots(object()) is None

    @pytest.mark.asyncio
    async def test_missing_field_is_no_verdict(self, monkeypatch):
        conn = _conn()
        monkeypatch.setattr(
            conn, "_get_with_retry", _Fetch(_ll("{'version': '17.2.10.21'}"))
        )
        assert await conn._check_event_slots(object()) is None


class TestLocalOnly:
    def test_default_allows_remote(self):
        conn = _conn()
        assert conn.local_only is False
        conn._check_local_only(local=False)  # no exception

    def test_local_only_refuses_remote(self):
        conn = _conn(local_only=True)
        with pytest.raises(LoxoneRemoteAccessDeniedError):
            conn._check_local_only(local=False)

    def test_local_only_allows_local(self):
        conn = _conn(local_only=True)
        conn._check_local_only(local=True)  # no exception

    def test_refusal_is_not_retryable(self):
        assert not issubclass(LoxoneRemoteAccessDeniedError, LoxoneConnectionError)
        assert issubclass(LoxoneRemoteAccessDeniedError, LoxoneException)
        assert not issubclass(
            LoxoneRemoteAccessDeniedError, LoxoneConnection.RETRYABLE_SESSION_ERRORS
        )
