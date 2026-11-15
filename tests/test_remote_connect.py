"""Remote Connect (spec V17.0): address of a Miniserver by its serial."""

from __future__ import annotations

import json

import aiohttp
import pytest

from pyloxone_api import connection as connection_module
from pyloxone_api import remote_connect
from pyloxone_api.connection import LoxoneBaseConnection, LoxoneConnection
from pyloxone_api.exceptions import (
    LoxoneConnectionError,
    LoxoneRemoteConnectDeniedError,
    LoxoneRemoteConnectError,
)
from pyloxone_api.remote_connect import (
    RemoteAddress,
    normalise_serial,
    parse_getip_response,
    remote_connect_serial,
    resolve_remote_address,
)

SERIAL = "504F94A23DB1"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("504F94A23DB1", SERIAL),
        ("50:4f:94:a2:3d:b1", SERIAL),
        ("50-4F-94-A2-3D-B1", SERIAL),
        ("504F94A23DB", None),
        ("504F94A23DBZ", None),
        (None, None),
    ],
)
def test_normalise_serial(value, expected):
    assert normalise_serial(value) == expected


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (f"connect.loxonecloud.com/{SERIAL}", SERIAL),
        (f"https://connect.loxonecloud.com/{SERIAL.lower()}/", SERIAL),
        (f"dns.loxonecloud.com/{SERIAL}", SERIAL),  # deprecated, still recognised
        ("connect.loxonecloud.com", None),
        (f"192.168.1.20/{SERIAL}", None),
        ("192.168.1.20", None),
    ],
)
def test_remote_connect_serial(host, expected):
    assert remote_connect_serial(host) == expected


# --- /getip replies ------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            {"url": "https://relay-7.example.loxonecloud.com:443/"},
            RemoteAddress("https", "relay-7.example.loxonecloud.com:443"),
        ),
        (
            {"url": "relay-7.example.loxonecloud.com:8443"},
            RemoteAddress("https", "relay-7.example.loxonecloud.com:8443"),
        ),
        (
            {
                "cmd": "getip",
                "Code": 200,
                "IP": "1.2.3.4:80",
                "IPHTTPS": "1-2-3-4.504F94A23DB1.dyndns.loxonecloud.com:443",
            },
            RemoteAddress("https", "1-2-3-4.504F94A23DB1.dyndns.loxonecloud.com:443"),
        ),
        (
            {"cmd": "getip", "Code": 200, "IP": "1.2.3.4:8080"},
            RemoteAddress("http", "1.2.3.4:8080"),
        ),
    ],
)
def test_getip_success(body, expected):
    assert parse_getip_response(200, json.dumps(body)) == expected


def test_getip_denied_for_third_party_apps():
    """The reply Loxone sends since November 2026 to clients other than
    the Loxone App / Loxone Config."""
    body = {
        "cmd": "getip",
        "Code": 418,
        "IP": "",
        "PortOpen": False,
        "DNS-Status": "registered",
        "Info": {
            "title": "Request not permitted",
            "message": "Access through Loxone Remote Connect is only possible with the Loxone App or Loxone Config.",
            "link": "",
        },
    }
    with pytest.raises(LoxoneRemoteConnectDeniedError) as err:
        parse_getip_response(418, json.dumps(body))
    assert err.value.code == 418
    assert "only possible with the Loxone App" in str(err.value)


def test_getip_403_new_endpoint():
    with pytest.raises(LoxoneRemoteConnectDeniedError) as err:
        parse_getip_response(403, b'{"error":"Request not permitted","status":"error"}')
    assert err.value.code == 403
    assert "Request not permitted" in str(err.value)


@pytest.mark.parametrize("status", [404, 500, 504])
def test_getip_transient_status(status):
    with pytest.raises(LoxoneRemoteConnectError) as err:
        parse_getip_response(status, b"")
    assert err.value.code == status


def test_getip_code_in_body_of_200():
    with pytest.raises(LoxoneRemoteConnectError) as err:
        parse_getip_response(200, json.dumps({"Code": 483, "IP": ""}))
    assert err.value.code == 483
    with pytest.raises(LoxoneRemoteConnectDeniedError) as err:
        parse_getip_response(200, json.dumps({"Code": 409, "IP": ""}))
    assert err.value.code == 409


def test_getip_200_without_address():
    with pytest.raises(LoxoneRemoteConnectError):
        parse_getip_response(200, b"{}")


def test_error_classes_drive_the_supervisor():
    # Transient: retried by run(); denied: final.
    assert issubclass(LoxoneRemoteConnectError, LoxoneConnectionError)
    assert (
        LoxoneRemoteConnectError in LoxoneConnection.RETRYABLE_SESSION_ERRORS
        or issubclass(
            LoxoneRemoteConnectError, LoxoneConnection.RETRYABLE_SESSION_ERRORS
        )
    )
    assert not issubclass(
        LoxoneRemoteConnectDeniedError, LoxoneConnection.RETRYABLE_SESSION_ERRORS
    )


# --- resolve_remote_address ----------------------------------------------------


async def test_resolve_uses_the_new_endpoint(monkeypatch):
    calls = []

    async def fake_fetch(session, url, timeout):
        calls.append(url)
        return 200, b'{"url": "https://relay.example:443"}'

    monkeypatch.setattr(remote_connect, "_fetch", fake_fetch)
    async with aiohttp.ClientSession() as session:
        address = await resolve_remote_address("50:4f:94:a2:3d:b1", session)
    assert address == RemoteAddress("https", "relay.example:443")
    assert calls == [f"https://connect.loxonecloud.com/getip?snr={SERIAL}"]


async def test_resolve_network_error_is_retryable(monkeypatch):
    async def failing_fetch(session, url, timeout):
        raise aiohttp.ClientConnectionError("no route")

    monkeypatch.setattr(remote_connect, "_fetch", failing_fetch)
    with pytest.raises(LoxoneRemoteConnectError):
        await resolve_remote_address(SERIAL)


async def test_resolve_rejects_invalid_serial():
    with pytest.raises(ValueError):
        await resolve_remote_address("not-a-serial")


# --- connection ----------------------------------------------------------------


def _conn(host: str, **kwargs) -> LoxoneBaseConnection:
    return LoxoneBaseConnection(
        host=host, username="user", password="password", **kwargs
    )


def test_connection_with_remote_connect_host():
    conn = _conn(f"connect.loxonecloud.com/{SERIAL}")
    assert conn.remote_serial == SERIAL
    assert conn.scheme == "https"
    # The default port 8080 must not leak into the cloud address.
    assert conn.url == f"connect.loxonecloud.com/{SERIAL}"
    assert conn._token_binding["url"] == f"connect.loxonecloud.com/{SERIAL}"


def test_deprecated_dns_host_uses_the_new_endpoint():
    conn = _conn(f"dns.loxonecloud.com/{SERIAL}")
    assert conn.url == f"connect.loxonecloud.com/{SERIAL}"


def test_local_connection_is_unchanged():
    conn = _conn("192.168.1.20", port=8080)
    assert conn.remote_serial is None
    assert (conn.scheme, conn.url) == ("http", "192.168.1.20:8080")


def test_local_only_rejects_remote_connect():
    with pytest.raises(ValueError):
        _conn(f"connect.loxonecloud.com/{SERIAL}", local_only=True)


class _StopAfterResolve(Exception):
    pass


async def test_open_resolves_before_the_bootstrap(monkeypatch):
    async def fake_resolve(serial, session, *, timeout):
        assert serial == SERIAL
        return RemoteAddress("https", "relay.example:443")

    seen = {}

    async def stop(self, url, connector, **kwargs):
        seen["base_url"] = connector.base_url
        raise _StopAfterResolve

    monkeypatch.setattr(connection_module, "resolve_remote_address", fake_resolve)
    monkeypatch.setattr(LoxoneConnection, "_get_with_retry", stop)
    conn = LoxoneConnection(
        host=f"connect.loxonecloud.com/{SERIAL}", username="user", password="password"
    )
    with pytest.raises(_StopAfterResolve):
        await conn.open(connect_websocket=False)
    assert (conn.scheme, conn.url) == ("https", "relay.example:443")
    assert seen["base_url"].startswith("https://relay.example:443")
    # The token stays bound to the stable Remote Connect identity.
    assert conn._token_binding["url"] == f"connect.loxonecloud.com/{SERIAL}"


async def test_open_propagates_denial(monkeypatch):
    async def denied(serial, session, *, timeout):
        raise LoxoneRemoteConnectDeniedError("Remote Connect refused (418)", code=418)

    monkeypatch.setattr(connection_module, "resolve_remote_address", denied)
    conn = LoxoneConnection(
        host=f"connect.loxonecloud.com/{SERIAL}", username="user", password="password"
    )
    with pytest.raises(LoxoneRemoteConnectDeniedError):
        await conn.open(connect_websocket=False)
