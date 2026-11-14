"""Tests for the HTTP basic auth ``Authorization`` header.

The header is built once per client. ``aiohttp.encode_basic_auth`` is
used when it exists (aiohttp 3.14 and later, where ``BasicAuth`` and
``auth=`` are deprecated); older versions get the same header from a
small fallback.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import inspect
import warnings

import aiohttp
import pytest

from pyloxone_api import connection, loxone_http_client
from pyloxone_api.loxone_http_client import (
    LoxoneAsyncHttpClient,
    _basic_auth_header,
)

_USER = "üser"
_PASSWORD = "pässwörd:€"
_EXPECTED = "Basic " + base64.b64encode(
    f"{_USER}:{_PASSWORD}".encode()
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


def _get(client: LoxoneAsyncHttpClient) -> None:
    async def consume() -> None:
        async with client.get("/jdev/cfg/apiKey"):
            pass

    asyncio.run(consume())


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
    """Guards the ``getattr`` lookup: it must not be removed."""
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
def test_constructor_rejects_colon_in_username(monkeypatch, old_aiohttp) -> None:
    if old_aiohttp:
        monkeypatch.delattr(aiohttp, "encode_basic_auth", raising=False)
    with pytest.raises(ValueError, match="Username"):
        LoxoneAsyncHttpClient("192.0.2.1", "us:er", "password", session=_Session())


def test_constructor_rejects_colon_before_creating_a_session(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("no session may be created for invalid input")

    monkeypatch.setattr(aiohttp, "ClientSession", fail)

    with pytest.raises(ValueError, match="Username"):
        LoxoneAsyncHttpClient("192.0.2.1", "us:er", "password")


def test_header_is_built_once_per_client(monkeypatch) -> None:
    calls = []

    def counting(username: str, password: str) -> str:
        calls.append((username, password))
        return _EXPECTED

    monkeypatch.setattr(loxone_http_client, "_basic_auth_header", counting)
    client = LoxoneAsyncHttpClient(
        "192.0.2.1", _USER, _PASSWORD, session=_Session()
    )
    _get(client)
    _get(client)

    assert calls == [(_USER, _PASSWORD)]


@pytest.mark.parametrize("old_aiohttp", [False, True])
def test_get_sends_authorization_header(monkeypatch, old_aiohttp) -> None:
    if old_aiohttp:
        monkeypatch.delattr(aiohttp, "encode_basic_auth", raising=False)
    session = _Session()
    client = LoxoneAsyncHttpClient("192.0.2.1", _USER, _PASSWORD, session=session)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _get(client)

    assert session.kwargs["headers"] == {"Authorization": _EXPECTED}
    assert "auth" not in session.kwargs


def test_http_client_source_does_not_use_basic_auth() -> None:
    """``aiohttp.BasicAuth`` and ``auth=`` are deprecated since aiohttp 3.14."""
    tree = ast.parse(inspect.getsource(loxone_http_client))
    names = {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Name))
    }
    keywords = {
        node.arg for node in ast.walk(tree) if isinstance(node, ast.keyword)
    }

    assert "BasicAuth" not in names
    assert "auth" not in keywords


def test_connection_does_not_use_top_level_client_connection() -> None:
    """websockets 14.0 does not export ``ClientConnection`` at the top level."""
    tree = ast.parse(inspect.getsource(connection))
    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr == "ClientConnection"
        and isinstance(node.value, ast.Name)
        and node.value.id in ("wslib", "websockets")
    ]

    assert offenders == []
