"""Pinning the Miniserver's public key (trust on first use).

The spec asks to verify the Miniserver certificate against the Loxone root
certificate stored on the client. Loxone does not publish that certificate,
so the library pins the key it saw first and refuses a different one later.
"""

from __future__ import annotations

import hashlib

import pytest
from Crypto.PublicKey import RSA

from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.exceptions import (
    LoxoneConnectionError,
    LoxonePublicKeyMismatchError,
)
from test_structure_over_websocket import _RSA, _HttpSession

EXPECTED_PIN = "sha256:" + hashlib.sha256(_RSA.publickey().export_key("DER")).hexdigest()
OTHER_PIN = "sha256:" + "0" * 64
BINDING = {"url": "192.0.2.1:8080", "port": 8080, "user": "user"}


class _Store:
    def __init__(self, data):
        self.data = data
        self.saved = []

    def load(self):
        return self.data

    def save(self, token):
        self.saved.append(token)


def _conn(**kwargs) -> LoxoneConnection:
    return LoxoneConnection("192.0.2.1", "user", "password", port=8080, **kwargs)


@pytest.mark.asyncio
async def test_first_connect_learns_the_pin():
    conn = _conn()
    assert conn.public_key_pin is None

    await conn._http_bootstrap(_HttpSession())

    assert conn.public_key_pin == EXPECTED_PIN
    assert conn.get_token_dict()["public_key_pin"] == EXPECTED_PIN


@pytest.mark.asyncio
async def test_matching_pin_is_accepted():
    conn = _conn(public_key_pin=EXPECTED_PIN)
    await conn._http_bootstrap(_HttpSession())
    assert conn.public_key_pin == EXPECTED_PIN


@pytest.mark.asyncio
async def test_other_key_is_refused():
    conn = _conn(public_key_pin=OTHER_PIN)
    with pytest.raises(LoxonePublicKeyMismatchError, match="public key"):
        await conn._http_bootstrap(_HttpSession())
    assert conn.public_key_pin == OTHER_PIN


def test_mismatch_is_final_for_run():
    """Retrying cannot help; the user has to confirm the new key."""
    assert not issubclass(LoxonePublicKeyMismatchError, LoxoneConnectionError)
    assert not issubclass(
        LoxonePublicKeyMismatchError, LoxoneConnection.RETRYABLE_SESSION_ERRORS
    )


@pytest.mark.asyncio
async def test_pin_is_restored_from_the_token_store():
    store = _Store({"token": "", "public_key_pin": OTHER_PIN, "binding": BINDING})
    conn = _conn(token_store=store)
    with pytest.raises(LoxonePublicKeyMismatchError):
        await conn._http_bootstrap(_HttpSession())


@pytest.mark.asyncio
async def test_pin_of_another_connection_is_not_restored():
    other = {**BINDING, "url": "192.0.2.99:8080"}
    store = _Store({"token": "", "public_key_pin": OTHER_PIN, "binding": other})
    conn = _conn(token_store=store)
    await conn._http_bootstrap(_HttpSession())
    assert conn.public_key_pin == EXPECTED_PIN


@pytest.mark.asyncio
async def test_pin_from_token_argument():
    conn = _conn(token={"token": "", "public_key_pin": OTHER_PIN})
    with pytest.raises(LoxonePublicKeyMismatchError):
        await conn._http_bootstrap(_HttpSession())


@pytest.mark.asyncio
async def test_newly_learned_pin_is_saved_when_a_token_exists():
    """With a stored token the session logs in with authwithtoken and no new
    token is saved, so the pin is saved right away."""
    import datetime

    from pyloxone_api.loxone_token import LOXONE_EPOCH

    valid = (datetime.datetime.now() - LOXONE_EPOCH).total_seconds() + 100_000
    store = _Store({"token": "T", "valid_until": valid, "hash_alg": "SHA256", "binding": BINDING})
    conn = _conn(token_store=store)

    await conn._http_bootstrap(_HttpSession())

    assert store.saved and store.saved[-1]["public_key_pin"] == EXPECTED_PIN


@pytest.mark.parametrize("bad", ["", "abc", "sha256:xyz", "sha1:" + "0" * 40, 5])
def test_invalid_pin_is_rejected(bad):
    with pytest.raises(ValueError):
        _conn(public_key_pin=bad)


def test_pin_is_case_insensitive():
    conn = _conn(public_key_pin=EXPECTED_PIN.upper().replace("SHA256:", "sha256:"))
    assert conn.public_key_pin == EXPECTED_PIN


def test_other_rsa_key_gives_other_pin():
    other = RSA.generate(1024).publickey().export_key("DER")
    assert "sha256:" + hashlib.sha256(other).hexdigest() != EXPECTED_PIN
