"""The structure file comes over the authenticated websocket, and the HTTP
bootstrap carries no credentials (spec "Communicating with the Miniserver":
"Login information is not sent as plain text"; "Structure-File: Download")."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from _fake_miniserver import STRUCTURE, FakeMiniserver
from Crypto.PublicKey import RSA

from pyloxone_api import connection as conn_mod
from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.exceptions import LoxoneConnectionError
from pyloxone_api.loxone_http_client import LoxoneAsyncHttpClient

_RSA = RSA.generate(2048)
_CERT = (
    _RSA.publickey().export_key().decode()
    .replace("BEGIN PUBLIC KEY", "BEGIN CERTIFICATE")
    .replace("END PUBLIC KEY", "END CERTIFICATE")
)


def _ll(control: str, value) -> bytes:
    return json.dumps({"LL": {"control": control, "value": value, "code": "200"}}).encode()


class _Response:
    status = 200
    url = ""

    def __init__(self, body: bytes):
        self._body = body
        self.content = self

    async def read(self):
        return self._body


class _CM:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *args):
        return None


class _HttpSession:
    """Records every GET with its headers."""

    closed = False

    def __init__(self):
        self.requests: list[tuple[str, dict]] = []

    def get(self, url, **kwargs):
        self.requests.append((url, kwargs.get("headers") or {}))
        if "apiKey" in url:
            body = _ll("dev/cfg/apiKey", json.dumps({"version": "17.0.1", "snr": "504F94AABBCC", "local": True}))
        elif "cfg/api" in url:
            body = _ll("dev/cfg/api", "{'hasEventSlots': true}")
        elif "getPublicKey" in url:
            body = _ll("dev/sys/getPublicKey", _CERT)
        else:
            body = b"{}"
        return _CM(_Response(body))

    async def close(self):
        return None


def _conn(**kwargs) -> LoxoneConnection:
    return LoxoneConnection("192.0.2.1", "user", "password", port=8080, **kwargs)


@pytest.fixture
def servers(monkeypatch):
    """Each websocket connect gets a new FakeMiniserver; the list collects them."""
    created: list[FakeMiniserver] = []
    holder: dict = {}

    async def fake_connect(*args, **kwargs):
        ms = FakeMiniserver(holder["conn"], **holder.get("kwargs", {}))
        created.append(ms)
        return ms

    monkeypatch.setattr(conn_mod.wslib, "connect", fake_connect)

    def bind(conn, **kwargs):
        holder["conn"] = conn
        holder["kwargs"] = kwargs
        return created

    return bind


async def _wait_for(predicate, timeout=2.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        if loop.time() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


class TestHttpBootstrapWithoutCredentials:
    @pytest.mark.asyncio
    async def test_no_request_carries_basic_auth(self, servers):
        conn = _conn()
        servers(conn)
        http = _HttpSession()

        await conn.open(session=http, connect_websocket=False)

        assert http.requests, "the bootstrap must still use HTTP"
        for url, headers in http.requests:
            assert "Authorization" not in headers, url

    @pytest.mark.asyncio
    async def test_structure_file_is_not_fetched_over_http(self, servers):
        conn = _conn()
        servers(conn)
        http = _HttpSession()

        await conn.open(session=http, connect_websocket=False)

        assert not [u for u, _ in http.requests if "LoxAPP3" in u]

    def test_http_client_without_credentials_sends_no_header(self):
        client = LoxoneAsyncHttpClient(url="192.0.2.1", session=_HttpSession())
        assert client._auth_header is None


class TestBootstrapSession:
    @pytest.mark.asyncio
    async def test_open_loads_structure_over_websocket(self, servers):
        conn = _conn()
        created = servers(conn)
        states: list[str] = []
        conn._on_state = states.append

        await conn.open(session=_HttpSession(), connect_websocket=False)

        assert conn.structure_file["controls"] == STRUCTURE["controls"]
        assert conn.structure_file["softwareVersion"] == [17, 0, 1]
        (ms,) = created
        assert "data/LoxAPP3.json" in ms.sent
        # The bootstrap session only fetches the file: no state updates,
        # no "connected", and the socket is closed again.
        assert "jdev/sps/enablebinstatusupdate" not in ms.sent
        assert ms.closed
        assert conn.connection is None
        assert "connected" not in states
        assert conn._websocket_deferred is True

    @pytest.mark.asyncio
    async def test_new_token_from_bootstrap_is_kept(self, servers):
        conn = _conn()
        servers(conn)
        await conn.open(session=_HttpSession(), connect_websocket=False)
        assert conn.get_token_dict()["token"] == "TOKEN"

    @pytest.mark.asyncio
    async def test_structure_body_is_not_parsed_as_ll(self, servers, caplog):
        conn = _conn()
        servers(conn)
        caplog.set_level(logging.ERROR)
        await conn.open(session=_HttpSession(), connect_websocket=False)
        assert not [r for r in caplog.records if "Failed to parse" in r.getMessage()]

    @pytest.mark.asyncio
    async def test_open_uses_executor_for_the_parse(self, servers):
        calls = []

        async def executor(target, *args):
            calls.append(target)
            return target(*args)

        conn = _conn(executor=executor)
        servers(conn)
        await conn.open(session=_HttpSession(), connect_websocket=False)
        assert json.loads in calls

    @pytest.mark.asyncio
    async def test_open_parses_inline_without_executor(self, servers):
        conn = _conn()
        servers(conn)
        assert conn.executor is None
        await conn.open(session=_HttpSession(), connect_websocket=False)
        assert conn.structure_file["lastModified"] == STRUCTURE["lastModified"]

    @pytest.mark.asyncio
    async def test_executor_errors_propagate_from_open(self, servers):
        async def failing(target, *args):
            raise RuntimeError("executor boom")

        conn = _conn(executor=failing)
        servers(conn)
        with pytest.raises(RuntimeError, match="executor boom"):
            await conn.open(session=_HttpSession(), connect_websocket=False)
        assert conn.connection is None

    @pytest.mark.asyncio
    async def test_socket_closed_before_structure_raises(self, servers, monkeypatch):
        conn = _conn()
        servers(conn)
        original = FakeMiniserver._answer

        def drop_structure(self, command):
            if command == "data/LoxAPP3.json":
                self._inbox.put_nowait(None)  # socket ends instead
                return
            original(self, command)

        monkeypatch.setattr(FakeMiniserver, "_answer", drop_structure)

        with pytest.raises(LoxoneConnectionError):
            await conn.open(session=_HttpSession(), connect_websocket=False)
        assert conn.connection is None


class TestListeningSession:
    @pytest.mark.asyncio
    async def test_first_session_after_open_does_not_download_again(self, servers):
        conn = _conn()
        created = servers(conn)
        await conn.open(session=_HttpSession(), connect_websocket=False)

        task = asyncio.create_task(conn.start_listening())
        try:
            await _wait_for(lambda: len(created) == 2 and "jdev/sps/enablebinstatusupdate" in created[1].sent)
            assert "data/LoxAPP3.json" not in created[1].sent
        finally:
            await conn.close()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_reconnect_downloads_before_updates_and_connected(self, servers):
        """On a reconnect (no open() before), the file is loaded after the
        login, before state updates are enabled and before "connected"."""
        conn = _conn()
        created = servers(conn)
        seen: dict = {}

        def on_state(state):
            if state == "connected":
                seen["structure"] = dict(conn.structure_file)

        conn._on_state = on_state
        http = _HttpSession()
        monkey_http = conn_mod.LoxoneAsyncHttpClient

        class _Client(monkey_http):
            def __init__(self, *args, **kwargs):
                kwargs["session"] = http
                super().__init__(*args, **kwargs)

        conn_mod.LoxoneAsyncHttpClient = _Client
        task = asyncio.create_task(conn.start_listening())
        try:
            await _wait_for(lambda: created and "jdev/sps/enablebinstatusupdate" in created[0].sent)
            sent = created[0].sent
            assert sent.index("data/LoxAPP3.json") < sent.index("jdev/sps/enablebinstatusupdate")
            assert seen["structure"]["controls"] == STRUCTURE["controls"]
        finally:
            conn_mod.LoxoneAsyncHttpClient = monkey_http
            await conn.close()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_rejected_stored_token_falls_back_to_password(servers):
    """A stale stored token must not fail open(): the token is dropped and
    the bootstrap logs in again with the password."""
    import datetime

    from pyloxone_api.loxone_token import LOXONE_EPOCH

    valid = (datetime.datetime.now() - LOXONE_EPOCH).total_seconds() + 100_000
    conn = _conn(token={"token": "OLD", "valid_until": valid, "hash_alg": "SHA256"})
    created = servers(conn, authwithtoken_code=401)

    await conn.open(session=_HttpSession(), connect_websocket=False)

    assert conn.structure_file["controls"] == STRUCTURE["controls"]
    assert conn.get_token_dict()["token"] == "TOKEN"
    assert len(created) == 2
    assert any(c.startswith("jdev/sys/getjwt/") for c in created[1].sent)
