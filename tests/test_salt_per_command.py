"""Salt update after every encrypted command (spec "Communicating with the
Miniserver", Setting up a connection: "Update the {salt} on your behalf, eg.
After every sent command. This prevents replay attacks")."""

from __future__ import annotations

import asyncio
import random
import urllib.parse
from types import SimpleNamespace

import pytest

from pyloxone_api.connection import LoxoneConnection


class _SlowWebsocket:
    """Records sends; each send yields a random number of times, so
    concurrent senders can overtake each other inside ``send``."""

    def __init__(self, seed: int = 7):
        self.sent: list[str] = []
        self.protocol = SimpleNamespace(state=SimpleNamespace(name="OPEN"))
        self._rnd = random.Random(seed)

    async def send(self, message):
        for _ in range(self._rnd.randint(0, 5)):
            await asyncio.sleep(0)
        self.sent.append(message)


@pytest.fixture
def conn():
    c = LoxoneConnection("192.0.2.1", "user", "password", port=8080)
    c._aes_key = bytes(range(32))
    c._iv = bytes(range(16))
    c._generate_salt()
    return c


def _plain(conn, wire: str) -> str:
    cipher = urllib.parse.unquote(wire[len("jdev/sys/enc/"):])
    return conn._decrypt(cipher).decode()


@pytest.mark.asyncio
async def test_every_command_after_the_first_rotates(conn):
    conn.connection = _SlowWebsocket()
    first_salt = conn._salt

    for i in range(3):
        await conn._send_text_command(f"jdev/sps/io/x/{i}", encrypted=True)

    plains = [_plain(conn, w) for w in conn.connection.sent]
    assert plains[0] == f"salt/{first_salt}/jdev/sps/io/x/0"
    for plain in plains[1:]:
        assert plain.startswith("nextSalt/")


@pytest.mark.asyncio
async def test_concurrent_sends_keep_the_salt_chain_on_the_wire(conn):
    """The Miniserver accepts ``nextSalt/{prev}/{next}`` only when ``prev`` is
    its current salt, so the wire order must follow the rotation order."""
    conn.connection = _SlowWebsocket()
    conn._new_salt_needed = lambda: True  # rotate on every command
    current = conn._salt

    await asyncio.gather(
        *(conn._send_text_command(f"jdev/sps/io/x/{i}", encrypted=True) for i in range(20))
    )

    for wire in conn.connection.sent:
        parts = _plain(conn, wire).split("/")
        if parts[0] == "salt":
            assert parts[1] == current
        else:
            assert parts[0] == "nextSalt"
            assert parts[1] == current, "salt chain broken on the wire"
            current = parts[2]


@pytest.mark.asyncio
async def test_failed_send_does_not_advance_the_salt(conn):
    """A command that never reached the Miniserver must not move our salt
    past the Miniserver's."""

    class _Failing(_SlowWebsocket):
        async def send(self, message):
            raise OSError("broken pipe")

    conn.connection = _Failing()
    conn._new_salt_needed = lambda: True
    before = conn._salt

    with pytest.raises(OSError):
        await conn._send_text_command("jdev/sps/io/x/1", encrypted=True)

    assert conn._salt == before
