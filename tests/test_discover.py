import pytest
from pyloxone_api.discover import discover
from ipaddress import ip_address


@pytest.mark.online
@pytest.mark.asyncio
async def test_discover():
    ip, port, response = await discover()
    assert ip_address(ip)
    assert isinstance(port, int)
    assert response.startswith("LoxLIVE")
    assert await discover(0) is None
