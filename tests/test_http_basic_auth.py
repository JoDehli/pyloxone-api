"""Tests for the HTTP basic auth ``Authorization`` header.

``aiohttp.encode_basic_auth`` exists only since aiohttp 3.14. Older
versions get the same header from a small fallback, so the library runs
on both without the ``BasicAuth`` deprecation warning of newer versions.
"""

from __future__ import annotations

import asyncio
import base64
import warnings

import aiohttp
import pytest

from pyloxone_api import loxone_http_client
from pyloxone_api.loxone_http_client import (
    LoxoneAsyncHttpClient,
    _basic_auth_header,
)

_USER = "üser"
_PASSWORD = "pässwörd:€"
_EXPECTED = "Basic " + base64.b64encode(
    f"{_USER}:{_PASSWORD}".encode("utf-8")
).decode("ascii")


class _Response:
    status = 200


class _AsyncCM:
    async def __aenter__(self):
        return _Response()

    async def __aexit__(self, *args):
        return None


class _Session:
    closed = False

    def __init__(self) -> None:
        self.kwargs = None

    def get(self, url, **kwargs):
        self.kwargs = kwargs
        return _AsyncCM()


@pytest.fixture
def without_encode_basic_auth(monkeypatch):
    """Make aiohttp look like a version before 3.14."""
    monkeypatch.delattr(aiohttp, "encode_basic_auth", raising=False)


def test_header_is_utf8_basic_auth() -> None:
    assert _basic_auth_header(_USER, _PASSWORD) == _EXPECTED


def test_fallback_builds_the_same_header(without_encode_basic_auth) -> None:
    assert not hasattr(aiohttp, "encode_basic_auth")
    assert _basic_auth_header(_USER, _PASSWORD) == _EXPECTED


def test_fallback_rejects_colon_in_username(without_encode_basic_auth) -> None:
    with pytest.raises(ValueError):
        _basic_auth_header("us:er", "password")


def test_aiohttp_helper_is_used_when_available(monkeypatch) -> None:
    calls = []

    def fake_encode(login, password="", encoding="utf-8"):
        calls.append((login, password, encoding))
        return "Basic from-aiohttp"

    monkeypatch.setattr(aiohttp, "encode_basic_auth", fake_encode, raising=False)

    assert _basic_auth_header("user", "password") == "Basic from-aiohttp"
    assert calls == [("user", "password", "utf-8")]


def test_header_emits_no_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _basic_auth_header(_USER, _PASSWORD)


@pytest.mark.parametrize("old_aiohttp", [False, True])
def test_get_sends_authorization_header(monkeypatch, old_aiohttp) -> None:
    if old_aiohttp:
        monkeypatch.delattr(aiohttp, "encode_basic_auth", raising=False)
    session = _Session()
    client = LoxoneAsyncHttpClient("192.0.2.1", _USER, _PASSWORD, session=session)

    async def consume() -> None:
        async with client.get("/jdev/cfg/apiKey"):
            pass

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        asyncio.run(consume())

    assert session.kwargs["headers"] == {"Authorization": _EXPECTED}
    assert "auth" not in session.kwargs


def test_module_does_not_reference_basic_auth_class() -> None:
    """``aiohttp.BasicAuth`` is deprecated since aiohttp 3.14."""
    assert not hasattr(loxone_http_client, "BasicAuth")
