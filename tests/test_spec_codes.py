"""Response and close codes from the spec "Communicating with the Miniserver"
(chapters "Error-Codes" and "Websocket Close Codes")."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from websockets.exceptions import ConnectionClosedError
from websockets.frames import Close

from pyloxone_api.connection import (
    LoxoneConnection,
    _close_reason,
    _raise_if_fatal_close,
)
from pyloxone_api.exceptions import LoxoneUnauthorisedError
from pyloxone_api.loxone_http_client import LoxoneAsyncHttpClient


@pytest.fixture
def conn():
    return LoxoneConnection("192.0.2.1", "user", "password", port=8080)


def _closed(code: int) -> ConnectionClosedError:
    return ConnectionClosedError(Close(code, ""), None)


class TestLLCodes:
    def test_423_user_disabled_is_final(self, conn):
        with pytest.raises(LoxoneUnauthorisedError, match="423"):
            conn._check_auth_response(SimpleNamespace(code=423), "getjwt")

    def test_4003_is_not_an_ll_code(self, conn):
        """4003 is a websocket close code (blocked user), handled by
        ``_raise_if_fatal_close``. As a response code it means nothing."""
        conn._check_auth_response(SimpleNamespace(code=4003), "getkey2")
        assert conn._auth_failure is None


class _Content:
    def __init__(self, body: bytes):
        self._body = body

    async def read(self) -> bytes:
        return self._body


@pytest.mark.asyncio
async def test_http_423_raises_unauthorised():
    response = SimpleNamespace(status=423, content=_Content(b"disabled"))
    with pytest.raises(LoxoneUnauthorisedError, match="disabled"):
        await LoxoneAsyncHttpClient._handle_error(response)


class TestCloseCodes:
    @pytest.mark.parametrize(
        ("code", "text"),
        [
            (4004, "a user was changed"),
            (4005, "the connected user was changed"),
            (4007, "update"),
            (4008, "event slot"),
        ],
    )
    def test_known_codes_have_a_reason(self, code, text):
        assert text in _close_reason(_closed(code))

    def test_unknown_code_has_no_reason(self):
        assert _close_reason(_closed(1006)) is None

    @pytest.mark.parametrize("code", [4004, 4005])
    def test_user_changed_is_retryable(self, code):
        """After 4004/4005 the reconnect logs in again. A changed password
        then ends in 401 from the login, which is final there."""
        _raise_if_fatal_close(_closed(code))  # must not raise


def test_901_max_connections_is_retryable():
    """901 (too many concurrent connections) is retried with the normal
    backoff: a connection slot can free up at any time."""
    from pyloxone_api.exceptions import LoxoneMaxNumOfConnectionsError

    assert issubclass(
        LoxoneMaxNumOfConnectionsError, LoxoneConnection.RETRYABLE_SESSION_ERRORS
    )
