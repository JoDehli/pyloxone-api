"""A rejected token on ``authwithtoken`` must trigger the password fallback.

The Miniserver answers 401 for a token it refuses, and 404 when the token is
unknown or was killed (Handover 8). Both mean "this token is no good". The
connection drops the token and reconnects, so the password login can run.

Any other code (for example 500) is not a token rejection and must not reset
the token.
"""

from __future__ import annotations

import json

import pytest

from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.message import MessageType, parse_message

TOKEN = "stored-token"


def _reply(code: int):
    return parse_message(
        json.dumps(
            {
                "LL": {
                    "control": "authwithtoken/hash/user",
                    "code": str(code),
                    "value": {"validUntil": 500000000},
                }
            }
        ),
        MessageType.TEXT,
    )


@pytest.fixture
def conn():
    c = LoxoneConnection(host="192.0.2.1", username="user", password="pw", port=8080)
    c._token.token = TOKEN
    c._token.valid_until = 500000000
    c._token.hash_alg = "SHA256"
    return c


class TestTokenRejected:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("code", [401, 404])
    async def test_rejection_drops_token_and_requests_reconnect(self, conn, code):
        await conn._websocket_event(_reply(code))

        assert conn._reconnect_event.is_set()
        assert conn._token.token == ""
        assert not conn._authenticated_event.is_set()

    @pytest.mark.asyncio
    async def test_other_error_keeps_token(self, conn):
        await conn._websocket_event(_reply(500))

        assert not conn._reconnect_event.is_set()
        assert conn._token.token == TOKEN

    @pytest.mark.asyncio
    async def test_success_still_authenticates(self, conn):
        await conn._websocket_event(_reply(200))

        assert conn._authenticated_event.is_set()
        assert conn._token.token == TOKEN
