"""Live test against a real Miniserver: does it accept PKCS#7 when sending?

This is Handover 4.3, "Schritt 0". It is skipped unless both are true:

- the test is run with ``-m online``, and
- the environment variable ``PYLOXONE_LIVE=1`` is set.

The default run (``uv run pytest``) never touches a device.

Credentials come from ``~/.config/rs-loxone/miniserver.env`` (``LOX_HOST``,
``LOX_USER``, ``LOX_PASS``). Values are never printed, logged or written
anywhere. Assertion messages contain no host or user names.

The only command sent is ``checktoken``, a read-only query. It is encrypted
through ``jdev/sys/enc`` with PKCS#7 padding. Nothing is switched, and
``killtoken`` is not called. Logging in issues a token on the device, as the
library does on every connect.
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


@pytest.mark.online
@live
@pytest.mark.asyncio
async def test_device_accepts_pkcs7_when_sending():
    if not ENV_FILE.is_file():
        pytest.skip("credentials file not found")
    env = _read_env(ENV_FILE)
    missing = [k for k in ("LOX_HOST", "LOX_USER", "LOX_PASS") if not env.get(k)]
    if missing:
        pytest.skip(f"credentials file lacks {', '.join(missing)}")

    from pyloxone_api.connection import LoxoneConnection

    host, port = _host_and_port(env["LOX_HOST"])
    conn = LoxoneConnection(host, env["LOX_USER"], env["LOX_PASS"], port=port)
    listener: asyncio.Task | None = None
    try:
        await conn.open()
        listener = asyncio.create_task(conn.start_listening())

        try:
            await asyncio.wait_for(conn._authenticated_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pytest.fail("login did not complete within 30 s")

        # Encrypted, PKCS#7-padded, read-only. False means no valid answer
        # (rejected, dropped or timed out), which is what this test checks.
        accepted = await conn.check_token(timeout=15)
        assert accepted, (
            "encrypted command with PKCS#7 padding got no valid answer; "
            "see Handover 4.3 for the zero-byte fallback"
        )
    finally:
        if listener is not None:
            listener.cancel()
            try:
                await listener
            except (asyncio.CancelledError, Exception):
                pass
        await conn.close()
