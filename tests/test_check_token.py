"""``LoxoneConnection.check_token`` (``jdev/sys/checktoken``).

The cleartext token is sent through command encryption, on an authenticated
session only. Code 200 means valid (True). Any other reply, including 401 and
400, means False. Unlike the auth handlers, a 401 here must not escalate to
``LoxoneUnauthorisedError``: an invalid token is an answer, not a failure of
the session.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from pyloxone_api.connection import LoxoneConnection, is_auth_response
from pyloxone_api.exceptions import LoxoneTokenError
from pyloxone_api.message import TextMessage

TOKEN = "clear-token-value"


def _reply(code: int) -> TextMessage:
    payload = {
        "LL": {
            "control": "jdev/sys/checktoken/" + TOKEN + "/user",
            "code": str(code),
            "value": "",
        }
    }
    return TextMessage(json.dumps(payload))


@pytest.fixture
def conn():
    c = LoxoneConnection(host="192.0.2.1", username="user", password="pw", port=8080)
    c._token.token = TOKEN
    c._authenticated_event.set()
    sent: list[tuple[str, bool]] = []

    async def fake_send(command, encrypted=False, **_kwargs):
        sent.append((command, encrypted))

    c._send_text_command = fake_send
    c._sent = sent
    return c


async def _answer_when_waiting(conn, code: int) -> None:
    """Wait until ``check_token`` is waiting, then deliver a reply."""
    for _ in range(1000):
        if conn._checktoken_waiter is not None:
            break
        await asyncio.sleep(0)
    await conn._websocket_event(_reply(code))


class TestCheckToken:
    @pytest.mark.asyncio
    async def test_200_means_valid(self, conn):
        task = asyncio.create_task(conn.check_token(timeout=2))
        await _answer_when_waiting(conn, 200)
        assert await task is True

    @pytest.mark.asyncio
    async def test_401_means_invalid_and_does_not_escalate(self, conn):
        task = asyncio.create_task(conn.check_token(timeout=2))
        await _answer_when_waiting(conn, 401)
        assert await task is False
        assert conn._auth_failure is None

    @pytest.mark.asyncio
    async def test_400_means_invalid(self, conn):
        task = asyncio.create_task(conn.check_token(timeout=2))
        await _answer_when_waiting(conn, 400)
        assert await task is False

    @pytest.mark.asyncio
    async def test_timeout_means_invalid(self, conn):
        assert await conn.check_token(timeout=0.01) is False

    @pytest.mark.asyncio
    async def test_sends_cleartext_token_encrypted(self, conn):
        task = asyncio.create_task(conn.check_token(timeout=2))
        await _answer_when_waiting(conn, 200)
        await task
        assert len(conn._sent) == 1
        command, encrypted = conn._sent[0]
        assert encrypted is True
        assert command.startswith("jdev/sys/checktoken/" + TOKEN + "/")

    @pytest.mark.asyncio
    async def test_not_sent_before_authentication(self, conn):
        conn._authenticated_event.clear()
        with pytest.raises(LoxoneTokenError):
            await conn.check_token(timeout=0.01)
        assert conn._sent == []

    @pytest.mark.asyncio
    async def test_waiter_is_cleared_after_reply(self, conn):
        task = asyncio.create_task(conn.check_token(timeout=2))
        await _answer_when_waiting(conn, 200)
        await task
        assert conn._checktoken_waiter is None

    @pytest.mark.asyncio
    async def test_waiter_is_cleared_after_timeout(self, conn):
        await conn.check_token(timeout=0.01)
        assert conn._checktoken_waiter is None


class TestCheckTokenReplyIsNotCallbackData:
    def test_checktoken_reply_is_auth_response(self):
        assert is_auth_response(_reply(200)) is True
