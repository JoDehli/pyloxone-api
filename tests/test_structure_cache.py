"""Structure file caching (spec "Structure-File: LoxAPP3.json", Download and
caching): compare ``jdev/sps/LoxAPPversion3`` with ``lastModified`` and
download only on a change."""

from __future__ import annotations

import asyncio

import pytest

from _fake_miniserver import STRUCTURE, FakeMiniserver
from pyloxone_api import connection as conn_mod
from pyloxone_api.connection import LoxoneConnection
from test_structure_over_websocket import _HttpSession, _wait_for

SERIAL_STRUCTURE = {**STRUCTURE, "msInfo": {"serialNr": "504F94AABBCC"}}


class _Cache:
    def __init__(self, data=None, fail=False):
        self.data = data
        self.saved: list[dict] = []
        self.fail = fail

    def load(self):
        if self.fail:
            raise OSError("disk gone")
        return self.data

    def save(self, structure):
        self.saved.append(structure)


@pytest.fixture
def servers(monkeypatch):
    created: list[FakeMiniserver] = []
    holder: dict = {}

    async def fake_connect(*args, **kwargs):
        ms = FakeMiniserver(holder["conn"], **holder["kwargs"])
        created.append(ms)
        return ms

    monkeypatch.setattr(conn_mod.wslib, "connect", fake_connect)
    http = _HttpSession()
    original = conn_mod.LoxoneAsyncHttpClient

    class _Client(original):
        def __init__(self, *args, **kwargs):
            kwargs["session"] = http
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(conn_mod, "LoxoneAsyncHttpClient", _Client)

    def bind(conn, **kwargs):
        holder["conn"] = conn
        holder["kwargs"] = kwargs
        return created

    return bind


def _conn(**kwargs) -> LoxoneConnection:
    return LoxoneConnection("192.0.2.1", "user", "password", port=8080, **kwargs)


async def _listen_until_updates(conn, created, index):
    task = asyncio.create_task(conn.start_listening())
    await _wait_for(
        lambda: len(created) > index
        and "jdev/sps/enablebinstatusupdate" in created[index].sent
    )
    return task


async def _stop(conn, task):
    await conn.close()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


class TestInMemory:
    @pytest.mark.asyncio
    async def test_unchanged_version_skips_download_on_reconnect(self, servers):
        conn = _conn()
        created = servers(conn)
        await conn.open(connect_websocket=False)
        first = conn.structure_file

        # Simulate a reconnect: the next session is not right after open().
        conn._structure_fresh = False
        task = await _listen_until_updates(conn, created, 1)
        try:
            sent = created[1].sent
            assert "jdev/sps/LoxAPPversion3" in sent
            assert "data/LoxAPP3.json" not in sent
            # Same object: callers that compare by identity see no change.
            assert conn.structure_file is first
        finally:
            await _stop(conn, task)

    @pytest.mark.asyncio
    async def test_changed_version_downloads(self, servers):
        conn = _conn()
        created = servers(conn, version="2026-11-14 08:00:00")
        await conn.open(connect_websocket=False)

        conn._structure_fresh = False
        task = await _listen_until_updates(conn, created, 1)
        try:
            assert "data/LoxAPP3.json" in created[1].sent
        finally:
            await _stop(conn, task)

    @pytest.mark.asyncio
    async def test_no_version_reply_downloads(self, servers, monkeypatch):
        monkeypatch.setattr(conn_mod, "STRUCTURE_VERSION_TIMEOUT", 0.05)
        original = FakeMiniserver._answer

        def silent(self, command):
            if command != "jdev/sps/LoxAPPversion3":
                original(self, command)

        monkeypatch.setattr(FakeMiniserver, "_answer", silent)
        conn = _conn()
        created = servers(conn)
        await conn.open(connect_websocket=False)

        conn._structure_fresh = False
        task = await _listen_until_updates(conn, created, 1)
        try:
            assert "data/LoxAPP3.json" in created[1].sent
        finally:
            await _stop(conn, task)


class TestPersistentCache:
    @pytest.mark.asyncio
    async def test_cached_file_of_same_version_is_used(self, servers):
        cache = _Cache(dict(SERIAL_STRUCTURE))
        conn = _conn(structure_cache=cache)
        created = servers(conn, structure=SERIAL_STRUCTURE)

        await conn.open(connect_websocket=False)

        assert "data/LoxAPP3.json" not in created[0].sent
        assert conn.structure_file["msInfo"]["serialNr"] == "504F94AABBCC"
        assert cache.saved == []

    @pytest.mark.asyncio
    async def test_download_is_saved(self, servers):
        cache = _Cache(None)
        conn = _conn(structure_cache=cache)
        servers(conn, structure=SERIAL_STRUCTURE)

        await conn.open(connect_websocket=False)

        assert len(cache.saved) == 1
        assert cache.saved[0]["lastModified"] == STRUCTURE["lastModified"]
        assert "softwareVersion" not in cache.saved[0]

    @pytest.mark.asyncio
    async def test_cache_of_another_miniserver_is_ignored(self, servers):
        other = {**SERIAL_STRUCTURE, "msInfo": {"serialNr": "504F94000000"}}
        conn = _conn(structure_cache=_Cache(other))
        created = servers(conn, structure=SERIAL_STRUCTURE)

        await conn.open(connect_websocket=False)

        assert "data/LoxAPP3.json" in created[0].sent
        assert conn.structure_file["msInfo"]["serialNr"] == "504F94AABBCC"

    @pytest.mark.asyncio
    async def test_failing_cache_is_not_fatal(self, servers):
        conn = _conn(structure_cache=_Cache(fail=True))
        created = servers(conn, structure=SERIAL_STRUCTURE)

        await conn.open(connect_websocket=False)

        assert "data/LoxAPP3.json" in created[0].sent

    def test_cache_needs_load_and_save(self):
        with pytest.raises(ValueError):
            _conn(structure_cache=object())
