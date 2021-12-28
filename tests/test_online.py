"""
These tests require access to a live miniserver. Pass --host, --port, --username,
 --password to pytest as command-line options. Port defaults to 80, username and
pasword to 'admin'

"""
import pytest

from pyloxone_api import Miniserver

# mark all tests in this module as 'online'. They will
# be skipped unless a --hostname is provided

pytestmark = pytest.mark.online


@pytest.mark.asyncio
async def test_online(online_credentials):
    api = Miniserver(
        user=online_credentials["username"],
        password=online_credentials["password"],
        host=online_credentials["host"],
        port=online_credentials["port"],
        use_tls=online_credentials["use_tls"],
    )

    await api._getStructureFile()
