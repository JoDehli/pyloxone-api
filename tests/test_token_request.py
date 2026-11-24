"""Parameters of the token request ``getjwt/{hash}/{user}/{permission}/{uuid}/{info}``
(spec "Communicating with the Miniserver", Tokens / Permissions)."""

from __future__ import annotations

import re

import pytest

from pyloxone_api.connection import LoxoneConnection

LOXONE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{16}$")
FIXED_UUID = "098802e1-02b4-603c-ffffeee000d80cfd"


def _conn(**kwargs) -> LoxoneConnection:
    return LoxoneConnection("192.0.2.1", "user", "password", port=8080, **kwargs)


def _parts(conn: LoxoneConnection) -> list[str]:
    conn.miniserver_version = [17, 0]
    return conn._token_request_command("HASH").split("/")


class _Store:
    def __init__(self, data):
        self.data = data
        self.saved = []

    def load(self):
        return self.data

    def save(self, token):
        self.saved.append(token)


class TestClientUuid:
    def test_generated_uuid_has_loxone_format(self):
        conn = _conn()
        assert LOXONE_UUID.match(conn.client_uuid)

    def test_generated_uuid_differs_per_instance(self):
        """The old code sent one hard-coded uuid from every installation."""
        assert _conn().client_uuid != _conn().client_uuid

    def test_explicit_uuid_is_used_in_the_request(self):
        parts = _parts(_conn(client_uuid=FIXED_UUID))
        assert parts[:3] == ["jdev", "sys", "getjwt"]
        assert parts[6] == FIXED_UUID

    @pytest.mark.parametrize(
        "bad", ["", "not-a-uuid", "098802e1-02b4-603c-ffff", 123]
    )
    def test_invalid_uuid_is_rejected(self, bad):
        with pytest.raises(ValueError):
            _conn(client_uuid=bad)

    def test_uuid_is_saved_with_the_token(self):
        conn = _conn(client_uuid=FIXED_UUID)
        assert conn.get_token_dict()["client_uuid"] == FIXED_UUID

    def test_uuid_is_restored_from_the_token_store(self):
        binding = {"url": "192.0.2.1:8080", "port": 8080, "user": "user"}
        store = _Store({"token": "", "client_uuid": FIXED_UUID, "binding": binding})
        assert _conn(token_store=store).client_uuid == FIXED_UUID

    def test_uuid_of_another_connection_is_not_restored(self):
        binding = {"url": "192.0.2.99:8080", "port": 8080, "user": "user"}
        store = _Store({"token": "", "client_uuid": FIXED_UUID, "binding": binding})
        assert _conn(token_store=store).client_uuid != FIXED_UUID

    def test_uuid_is_restored_from_token_argument(self):
        conn = _conn(token={"token": "", "client_uuid": FIXED_UUID})
        assert conn.client_uuid == FIXED_UUID

    def test_explicit_uuid_wins_over_stored(self):
        other = "aaaaaaaa-bbbb-cccc-dddddddddddddddd"
        conn = _conn(client_uuid=other, token={"token": "", "client_uuid": FIXED_UUID})
        assert conn.client_uuid == other


class TestClientInfo:
    def test_default_info(self):
        assert _parts(_conn())[7] == "pyloxone_api"

    def test_info_is_url_encoded(self):
        assert _parts(_conn(client_info="Home Assistant/1"))[7] == "Home%20Assistant%2F1"


class TestPermission:
    def test_default_is_app_permission(self):
        """The spec: 2 (web) is short lived and meant for the web interface,
        4 (app) is long lived. A long-running client is an app."""
        assert _parts(_conn())[5] == "4"

    def test_web_permission_can_be_chosen(self):
        assert _parts(_conn(token_permission=2))[5] == "2"

    @pytest.mark.parametrize("bad", [0, 1, 3, 8, "4", True])
    def test_other_permissions_are_rejected(self, bad):
        with pytest.raises(ValueError):
            _conn(token_permission=bad)


def test_legacy_firmware_uses_gettoken():
    conn = _conn(client_uuid=FIXED_UUID)
    conn.miniserver_version = [10, 1]
    assert conn._token_request_command("HASH") == (
        f"jdev/sys/gettoken/HASH/user/4/{FIXED_UUID}/pyloxone_api"
    )
