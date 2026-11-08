"""Live probe: what does ``killtoken`` do to a token? (Handover 4.7)

Skipped unless run with ``-m online`` and ``PYLOXONE_LIVE=1``.

Steps, all on a token that this test issues itself:

1. Log in with the password. The Miniserver issues a new token.
2. Send ``killtoken`` with that token.
3. Connect again and present the same token via ``authwithtoken``.

The test records which of three outcomes the device produced. It asserts
only that one of them occurred, because the open question is what the device
does, not what it should do:

- ``STILL_VALID``: authentication with the killed token succeeded.
- ``REJECTED``: the token was refused and the library fell back to the
  password, which issued a new token.
- ``NO_AUTH``: no authentication within 30 s (for example a silent refusal).

The credentials come from ``~/.config/rs-loxone/miniserver.env``. They are
never printed. The second login issues one more token on the device. This test
does not remove it, so clean up in the web UI if needed.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

ENV_FILE = Path.home() / ".config" / "rs-loxone" / "miniserver.env"
DEFAULT_PORT = 8080


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _host_and_port(value: str) -> tuple[str, int]:
    if ":" in value:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return value, DEFAULT_PORT


live = pytest.mark.skipif(
    os.environ.get("PYLOXONE_LIVE") != "1",
    reason="live device test: set PYLOXONE_LIVE=1 and run with -m online",
)


async def _stop(conn, listener) -> None:
    if listener is not None:
        listener.cancel()
        try:
            await listener
        except (asyncio.CancelledError, Exception):
            pass
    try:
        await conn.close()
    except Exception:
        pass


@pytest.mark.online
@live
@pytest.mark.asyncio
async def test_killtoken_effect_on_token():
    if not ENV_FILE.is_file():
        pytest.skip("credentials file not found")
    env = _read_env(ENV_FILE)
    missing = [k for k in ("LOX_HOST", "LOX_USER", "LOX_PASS") if not env.get(k)]
    if missing:
        pytest.skip(f"credentials file lacks {', '.join(missing)}")

    from pyloxone_api.connection import LoxoneConnection

    host, port = _host_and_port(env["LOX_HOST"])
    user, password = env["LOX_USER"], env["LOX_PASS"]

    # 1. Password login: the device issues a token for this test.
    first = LoxoneConnection(host, user, password, port=port)
    listener = None
    try:
        await first.open()
        listener = asyncio.create_task(first.start_listening())
        try:
            await asyncio.wait_for(first._authenticated_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pytest.fail("first login did not complete within 30 s")
        token_dict = first.get_token_dict()
        killed_token = token_dict["token"]
        assert killed_token, "login produced no token"
    finally:
        await _stop(first, listener)

    # 2. Kill that token from an authenticated session. kill_token() swallows
    #    send errors, so record the send to be sure the command really left.
    second_stage = LoxoneConnection(
        host,
        user,
        password,
        port=port,
        token={
            "token": killed_token,
            "valid_until": token_dict["valid_until"],
            "hash_alg": token_dict["hash_alg"],
            "unsecure_password": token_dict["unsecure_password"],
        },
    )
    listener = None
    try:
        await second_stage.open()
        listener = asyncio.create_task(second_stage.start_listening())
        try:
            await asyncio.wait_for(second_stage._authenticated_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pytest.fail("could not authenticate before killtoken")

        sent: list[str] = []
        original_send = second_stage._send_text_command

        async def recording_send(command="", encrypted=False):
            sent.append(command)
            return await original_send(command, encrypted=encrypted)

        second_stage._send_text_command = recording_send
        await second_stage.kill_token()
        assert any(c.startswith("jdev/sys/killtoken/") for c in sent), (
            "killtoken was not sent"
        )
        await asyncio.sleep(2)
    finally:
        await _stop(second_stage, listener)

    # 3. Present the same token again on a fresh connection. The raw reply
    #    codes of authwithtoken are recorded before the library reacts.
    third = LoxoneConnection(
        host,
        user,
        password,
        port=port,
        token={
            "token": killed_token,
            "valid_until": token_dict["valid_until"],
            "hash_alg": token_dict["hash_alg"],
            "unsecure_password": token_dict["unsecure_password"],
        },
    )
    codes: list[object] = []
    original_event = third._websocket_event

    async def recording_event(message):
        if "authwithtoken" in str(getattr(message, "message", "")):
            codes.append(getattr(message, "code", None))
        return await original_event(message)

    third._websocket_event = recording_event

    listener = None
    outcome = "NO_AUTH"
    try:
        await third.open()
        listener = asyncio.create_task(third.start_listening())
        auth_wait = asyncio.create_task(third._authenticated_event.wait())
        await asyncio.wait(
            {auth_wait, listener}, timeout=30, return_when=asyncio.FIRST_COMPLETED
        )
        auth_wait.cancel()
        if third._authenticated_event.is_set():
            outcome = (
                "STILL_VALID" if third._token.token == killed_token else "REJECTED"
            )
        elif listener.done():
            outcome = "REJECTED"
    finally:
        await _stop(third, listener)

    print(f"\nAUTHWITHTOKEN RAW CODES: {codes}")
    print(f"\nKILLTOKEN RESULT: {outcome}")
    assert outcome in {"STILL_VALID", "REJECTED", "NO_AUTH"}
