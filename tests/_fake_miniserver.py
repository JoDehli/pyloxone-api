"""A scripted Miniserver behind a fake websocket, for offline session tests.

It answers the commands of a login (key exchange, getkey2, getjwt or
authwithtoken), ``data/LoxAPP3.json`` and ``enablebinstatusupdate`` the way
the spec "Communicating with the Miniserver" describes: every reply is an
8-byte header followed by the payload. Encrypted commands are decrypted with
the session key of the connection under test.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import struct
import urllib.parse
from types import SimpleNamespace

from pyloxone_api.loxone_token import LOXONE_EPOCH

STRUCTURE = {"lastModified": "2026-11-01 10:00:00", "controls": {"a": {"type": "Switch"}}}


def header(message_type: int, length: int) -> bytes:
    return struct.pack("<cBccI", b"\x03", message_type, b"\x00", b"\x00", length)


def ll(control: str, value, code: int = 200) -> bytes:
    return json.dumps({"LL": {"control": control, "value": value, "code": str(code)}}).encode()


class FakeMiniserver:
    """``websockets`` client stand-in. ``sent`` lists the decrypted commands."""

    def __init__(self, conn, structure=None, authwithtoken_code: int = 200, version="2026-11-01 10:00:00"):
        self.conn = conn
        self.structure = STRUCTURE if structure is None else structure
        self.authwithtoken_code = authwithtoken_code
        self.version = version
        self.sent: list[str] = []
        self.raw_sent: list[str] = []
        self._inbox: asyncio.Queue = asyncio.Queue()
        self.closed = False
        self.state = SimpleNamespace(CLOSED="CLOSED", OPEN="OPEN", name="OPEN")
        self.protocol = SimpleNamespace(state=SimpleNamespace(name="OPEN"))

    # websocket API -----------------------------------------------------
    def __aiter__(self):
        return self

    async def __anext__(self):
        frame = await self._inbox.get()
        if frame is None:
            raise StopAsyncIteration
        return frame

    async def close(self, *args, **kwargs):
        if not self.closed:
            self.closed = True
            self.protocol.state.name = "CLOSED"
            self.state.name = "CLOSED"
            self._inbox.put_nowait(None)

    async def send(self, message):
        self.raw_sent.append(message)
        command = self._plain(message)
        self.sent.append(command)
        self._answer(command)

    # Miniserver behaviour ----------------------------------------------
    def _plain(self, message: str) -> str:
        if not message.startswith("jdev/sys/enc/"):
            return message
        cipher = urllib.parse.unquote(message[len("jdev/sys/enc/"):])
        text = self.conn._decrypt(cipher).decode()
        parts = text.split("/")
        # salt/{s}/{cmd} or nextSalt/{old}/{new}/{cmd}
        return "/".join(parts[2:] if parts[0] == "salt" else parts[3:])

    def _reply(self, body: bytes, message_type: int = 0) -> None:
        self._inbox.put_nowait(header(message_type, len(body)))
        self._inbox.put_nowait(body)

    def _answer(self, command: str) -> None:
        if command.startswith("jdev/sys/keyexchange/"):
            self._reply(ll("jdev/sys/keyexchange/x", "ok"))
        elif command.startswith("jdev/sys/getkey2/"):
            self._reply(ll(command, {"key": "41424344", "salt": "0011", "hashAlg": "SHA256"}))
        elif command.startswith("jdev/sys/getjwt/"):
            valid = (datetime.datetime.now() - LOXONE_EPOCH).total_seconds() + 3_000_000
            self._reply(ll(command, {"token": "TOKEN", "validUntil": valid, "key": "41424344",
                                     "tokenRights": 4, "unsecurePass": False}))
        elif command.startswith("authwithtoken/"):
            self._reply(ll(command, {}, self.authwithtoken_code))
        elif command == "jdev/sps/LoxAPPversion3":
            self._reply(ll("dev/sps/LoxAPPversion3", self.version))
        elif command == "data/LoxAPP3.json":
            self._reply(json.dumps(self.structure).encode())
        elif command == "jdev/sps/enablebinstatusupdate":
            self._reply(ll("dev/sps/enablebinstatusupdate", "1"))
        elif command == "keepalive":
            self._inbox.put_nowait(header(6, 0))
