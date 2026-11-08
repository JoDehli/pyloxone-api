"""Live test against a real Miniserver: does it accept PKCS#7 when sending?

This is Handover 4.3, "Schritt 0". It is skipped unless both are true:

- the test is run with ``-m online``, and
- the environment variable ``PYLOXONE_LIVE=1`` is set.

The default run (``uv run pytest``) never touches a device.

Credentials come from the environment (``PYLOXONE_TEST_HOST``,
``PYLOXONE_TEST_USER``, ``PYLOXONE_TEST_PASSWORD``) or from ``.env.live`` in the
project root (git-ignored, mode 0600). See ``tests/live_config.py``. Values are
never printed, logged or written anywhere. Assertion messages contain no host
or user names.

The only command sent is ``checktoken``, a read-only query. It is encrypted
through ``jdev/sys/enc`` with PKCS#7 padding. Nothing is switched, and
``killtoken`` is not called. Logging in issues a token on the device, as the
library does on every connect.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from live_config import host_and_port, load_live_settings




live = pytest.mark.skipif(
    os.environ.get("PYLOXONE_LIVE") != "1",
    reason="live device test: set PYLOXONE_LIVE=1 and run with -m online",
)


@pytest.mark.online
@live
@pytest.mark.asyncio
async def test_device_accepts_pkcs7_when_sending():
    env, problem = load_live_settings()
    if env is None:
        pytest.skip(problem)

    from pyloxone_api.connection import LoxoneConnection

    host, port = host_and_port(env["PYLOXONE_TEST_HOST"])
    conn = LoxoneConnection(
        host, env["PYLOXONE_TEST_USER"], env["PYLOXONE_TEST_PASSWORD"], port=port
    )
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
