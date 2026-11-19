"""``httpsStatus`` from ``jdev/cfg/apiKey`` (spec "Using HTTPS/WSS"):
1 = TLS available, 2 = certificate present but expired."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

import pytest

from pyloxone_api.connection import CMD_GET_API_KEY, LoxoneConnection
from pyloxone_api.exceptions import LoxoneServiceUnAvailableError


def _conn(host="192.168.1.47", port=80, **kwargs) -> LoxoneConnection:
    return LoxoneConnection(host, "user", "pw", port=port, **kwargs)


def test_status_unknown_before_open():
    conn = _conn()
    assert conn.https_status is None
    assert conn.tls_hostname is None


@pytest.mark.parametrize(
    "raw, expected",
    [(1, 1), ("1", 1), (2, 2), (0, 0), ("x", None), (None, None)],
)
def test_status_is_read(raw, expected):
    conn = _conn()
    conn._apply_api_key_info({"snr": "50:4F:94:AA:BB:CC", "httpsStatus": raw})
    assert conn.https_status == expected


def test_tls_hostname_for_local_ipv4():
    conn = _conn()
    conn._apply_api_key_info({"snr": "50:4F:94:AA:BB:CC", "httpsStatus": 1})
    assert conn.tls_hostname == "192-168-1-47.504F94AABBCC.dyndns.loxonecloud.com"


def test_tls_hostname_for_ipv6():
    conn = _conn(host="[fd00::1]")
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 1})
    assert conn.tls_hostname == "fd00--1.504F94AABBCC.dyndns.loxonecloud.com"


def test_no_tls_hostname_for_a_scoped_ipv6_address():
    """``%`` from a scope ID is not valid in a DNS label."""
    conn = _conn(host="[fe80::1%eth0]")
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 1})
    assert conn.tls_hostname is None


@pytest.mark.parametrize(
    "serial",
    ["50:4F:94:AA:BB:CC", "50-4F-94-AA-BB-CC", " 504f94aabbcc\n"],
)
def test_tls_hostname_normalizes_the_serial(serial):
    conn = _conn()
    conn._apply_api_key_info({"snr": serial, "httpsStatus": 1})
    assert conn.tls_hostname == "192-168-1-47.504F94AABBCC.dyndns.loxonecloud.com"


def test_no_tls_hostname_without_tls():
    conn = _conn()
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 0})
    assert conn.tls_hostname is None


def test_no_tls_hostname_for_a_hostname():
    """Only an IP literal is turned into the CloudDNS name."""
    conn = _conn(host="miniserver.example")
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 1})
    assert conn.tls_hostname is None


def test_plain_http_with_tls_available_logs_hint_once(caplog):
    conn = _conn()
    caplog.set_level(logging.INFO, logger="pyloxone_api.connection")
    for _ in range(2):  # open() runs again on every reconnect
        conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 1})
    hints = [r for r in caplog.records if "supports HTTPS" in r.getMessage()]
    assert len(hints) == 1
    assert "192-168-1-47.504F94AABBCC.dyndns.loxonecloud.com" in hints[0].getMessage()


def test_expired_certificate_logs_warning(caplog):
    conn = _conn()
    caplog.set_level(logging.WARNING, logger="pyloxone_api.connection")
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 2})
    assert any("expired" in r.getMessage() for r in caplog.records)


def test_https_connection_gets_no_hint(caplog):
    conn = _conn(host="https://miniserver.example", port=443)
    caplog.set_level(logging.INFO, logger="pyloxone_api.connection")
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 1})
    assert not [r for r in caplog.records if "supports HTTPS" in r.getMessage()]


def test_redirect_updates_the_host_used_for_tls_hostname():
    conn = _conn()
    conn._apply_url("https", "12345.loxone.cloud:443")
    conn._apply_api_key_info({"snr": "504F94AABBCC", "httpsStatus": 1})
    assert conn.tls_hostname is None


async def _open_until_redirect_is_handled(conn, redirect_url, monkeypatch):
    """Run ``open()`` on a remote apiKey reply, stopping right after it."""
    api_key = json.dumps(
        {"version": "17.0.0", "snr": "504F94AABBCC", "local": False, "httpsStatus": 1}
    )
    reply = json.dumps(
        {"LL": {"code": 200, "control": "dev/cfg/apiKey", "value": api_key}}
    ).encode()

    async def get_with_retry(url, connector, **kwargs):
        return reply, redirect_url

    async def stop_open(connector):
        raise LoxoneServiceUnAvailableError("stop after the apiKey step")

    monkeypatch.setattr(conn, "_get_with_retry", get_with_retry)
    monkeypatch.setattr(conn, "_check_event_slots", stop_open)
    with pytest.raises(LoxoneServiceUnAvailableError):
        await conn.open(session=MagicMock(closed=False))


async def test_redirect_to_https_gets_no_plain_http_hint(caplog, monkeypatch):
    conn = _conn()
    caplog.set_level(logging.INFO, logger="pyloxone_api.connection")
    await _open_until_redirect_is_handled(
        conn, f"https://12345.loxone.cloud/{CMD_GET_API_KEY}", monkeypatch
    )
    assert conn.scheme == "https"
    assert not [r for r in caplog.records if "supports HTTPS" in r.getMessage()]


async def test_remote_connection_staying_on_http_gets_the_hint(caplog, monkeypatch):
    conn = _conn()
    caplog.set_level(logging.INFO, logger="pyloxone_api.connection")
    await _open_until_redirect_is_handled(
        conn, f"http://192.168.1.47/{CMD_GET_API_KEY}", monkeypatch
    )
    assert conn.scheme == "http"
    assert [r for r in caplog.records if "supports HTTPS" in r.getMessage()]
