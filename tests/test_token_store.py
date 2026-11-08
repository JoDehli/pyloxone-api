"""Optional ``token_store`` hook for :class:`LoxoneConnection`.

The library never writes files. The caller passes an object with
``load()`` and ``save(token)``:

- ``save(dict)`` is called after every login and every refresh, and
  ``save(None)`` when the token is reset.
- ``load()`` is called once in the constructor and must return the dict
  saved last, or ``None``.

A stored token is used only if it is bound to the same host, port and user,
its data is valid, and more than ``TOKEN_MIN_REMAINING_SECONDS`` remain.
Everything else counts as "no token".
"""

from __future__ import annotations

import datetime

import pytest

from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.loxone_token import LOXONE_EPOCH


class MemoryStore:
    def __init__(self, initial=None, load_exc=None, save_exc=None):
        self.data = initial
        self.saved: list = []
        self.load_exc = load_exc
        self.save_exc = save_exc

    def load(self):
        if self.load_exc is not None:
            raise self.load_exc
        return self.data

    def save(self, token):
        if self.save_exc is not None:
            raise self.save_exc
        self.saved.append(token)
        self.data = token


def _now_loxone() -> float:
    return (datetime.datetime.now() - LOXONE_EPOCH).total_seconds()


def _conn(**kwargs) -> LoxoneConnection:
    return LoxoneConnection(
        host="192.0.2.1", username="user", password="pw", port=8080, **kwargs
    )


def _stored(conn: LoxoneConnection, valid_in: float = 3600, **binding_override):
    """A stored dict as this connection would save it, with optional changes."""
    binding = {"url": conn.url, "port": conn.port, "user": conn.username}
    binding.update(binding_override)
    return {
        "token": "stored-token",
        "valid_until": _now_loxone() + valid_in,
        "hash_alg": "SHA256",
        "unsecure_password": False,
        "binding": binding,
    }


class TestSave:
    def test_save_writes_token_and_binding(self):
        store = MemoryStore()
        conn = _conn(token_store=store)
        conn._token.token = "t1"
        conn._token.valid_until = _now_loxone() + 3600
        conn._token.hash_alg = "SHA256"

        conn._signal_token_changed()

        saved = store.saved[-1]
        assert saved["token"] == "t1"
        assert saved["hash_alg"] == "SHA256"
        assert saved["valid_until"] == conn._token.valid_until
        assert saved["binding"] == {
            "url": conn.url,
            "port": 8080,
            "user": "user",
        }

    def test_save_failure_does_not_raise(self):
        conn = _conn(token_store=MemoryStore(save_exc=OSError("disk")))
        conn._token.token = "t1"
        conn._token.valid_until = _now_loxone() + 3600
        conn._signal_token_changed()  # must not raise

    def test_reset_token_clears_store(self):
        store = MemoryStore(initial=_stored(_conn()))
        conn = _conn(token_store=store)
        conn.reset_token()
        assert store.saved[-1] is None


class TestLoad:
    def test_round_trip_is_used_by_new_connection(self):
        first = _conn(token_store=MemoryStore())
        first._token.token = "t1"
        first._token.valid_until = _now_loxone() + 3600
        first._token.hash_alg = "SHA256"
        first._signal_token_changed()
        store = MemoryStore(initial=first._token_store.saved[-1])

        second = _conn(token_store=store)

        assert second._token.token == "t1"
        assert second._token.hash_alg == "SHA256"

    def test_empty_store_starts_without_token(self):
        conn = _conn(token_store=MemoryStore(initial=None))
        assert conn._token.token == ""

    @pytest.mark.parametrize(
        "override",
        [
            {"url": "198.51.100.7"},
            {"port": 9090},
            {"user": "someone-else"},
        ],
    )
    def test_token_of_other_binding_is_discarded(self, override):
        conn_for_binding = _conn()
        store = MemoryStore(initial=_stored(conn_for_binding, **override))
        conn = _conn(token_store=store)
        assert conn._token.token == ""

    @pytest.mark.parametrize(
        "broken",
        [
            "not a dict",
            {},
            {"valid_until": 1},
            {"token": "", "valid_until": 1, "hash_alg": "SHA256"},
            {"token": "x", "valid_until": "soon", "hash_alg": "SHA256"},
            {"token": "x", "valid_until": 1, "hash_alg": "MD5"},
        ],
    )
    def test_broken_data_is_no_token(self, broken):
        conn = _conn(token_store=MemoryStore(initial=broken))
        assert conn._token.token == ""

    def test_missing_binding_is_no_token(self):
        data = _stored(_conn())
        del data["binding"]
        conn = _conn(token_store=MemoryStore(initial=data))
        assert conn._token.token == ""

    def test_token_with_too_little_time_left_is_discarded(self):
        conn_for_binding = _conn()
        store = MemoryStore(initial=_stored(conn_for_binding, valid_in=60))
        conn = _conn(token_store=store)
        assert conn._token.token == ""

    def test_load_failure_is_no_token(self):
        conn = _conn(token_store=MemoryStore(load_exc=RuntimeError("corrupt")))
        assert conn._token.token == ""


class TestArguments:
    def test_token_and_token_store_together_rejected(self):
        with pytest.raises(ValueError):
            _conn(
                token={"token": "x", "valid_until": 1, "hash_alg": "SHA256"},
                token_store=MemoryStore(),
            )
