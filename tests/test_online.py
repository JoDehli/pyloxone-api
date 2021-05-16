"""
These tests require access to a live miniserver. Pass --host, --port, --username,
 --password to pytest as command-line options. Port defaults to 80, username and
pasword to 'admin'

"""
import pytest
from pyloxone_api import LoxApp

# mark all tests in this module as 'online'. They will
# be skipped unless a --hostname is provided

pytestmark = pytest.mark.online


@pytest.mark.asyncio
async def test_online(online_credentials):
    app = LoxApp()
    app.lox_user = online_credentials["username"]
    app.lox_pass = online_credentials["password"]
    app.host = online_credentials["host"]
    app.port = online_credentials["port"]
    request_code = await app.getJson()
    assert request_code == 200
