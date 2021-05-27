import pytest
from pyloxone_api import LoxAPI
from pyloxone_api.const import LOXAPPPATH

API_KEY_RETURN_HTTPS_STATUS_1 = """{
  "LL": {
    "control": "dev/cfg/apiKey",
    "value": "{'snr': '12:34:56:78:9A:BC', 'version':'12.0.2.24', 'key':'1234', 'httpsStatus':1}",
    "Code": "200"
  }
}"""
API_KEY_RETURN_HTTPS_STATUS_0 = """{
  "LL": {
    "control": "dev/cfg/apiKey",
    "value": "{'snr': '12:34:56:78:9A:BC', 'version':'12.0.2.24', 'key':'1234', 'httpsStatus':0}",
    "Code": "200"
  }
}"""
VERSION_RETURN = (
    """{"LL": { "control": "dev/cfg/version", "value": "12.0.2.24", "Code": "200"}}"""
)

LOXAPP3 = """{
  "lastModified": "2021-05-11 23:09:38",
  "msInfo": {
    "serialNr": "DECAFC0FFEEE",
    "msName": "MyLoxone",
    "projectName": "MyProject",
    "localUrl": "myloxone.localdomain",
    "remoteUrl": "",
    "tempUnit": 0,
    "currency": "Â€",
    "squareMeasure": "mÂ²",
    "location": "Somewhere",
    "languageCode": "ENG",
    "heatPeriodStart": "10-01",
    "heatPeriodEnd": "04-30",
    "coolPeriodStart": "05-01",
    "coolPeriodEnd": "09-30",
    "catTitle": "Categories",
    "roomTitle": "Rooms",
    "miniserverType": 2
  }
}"""


@pytest.fixture
def dummy_miniserver():
    """A dummy LoxApp() with fake credentials"""
    api = LoxAPI(user="", password="", host="example.com", port=80)

    return api


def test_LoxApp_init():
    """Test class initialisation"""
    api = LoxAPI()
    assert api._host is None
    assert api._port is None
    assert api._user is None
    assert api._password is None
    assert api.json is None
    assert api.version is None
    assert api.https_status is None
    assert api.url == None


@pytest.mark.asyncio
async def test_LoxApp_json_http_error(httpx_mock, dummy_miniserver):
    """Test http error from server"""
    httpx_mock.add_response(status_code=404)
    result = await dummy_miniserver.getJson()
    assert result is False


@pytest.mark.asyncio
async def test_LoxApp_getversion_http_status_0(httpx_mock, dummy_miniserver):
    """Test identification of https_status"""
    httpx_mock.add_response(
        url="http://example.com/jdev/cfg/apiKey", data=API_KEY_RETURN_HTTPS_STATUS_0
    )
    httpx_mock.add_response(
        url="http://example.com/jdev/cfg/version", data=VERSION_RETURN
    )
    httpx_mock.add_response(url=f"http://example.com{LOXAPPPATH}", data=LOXAPP3)
    _ = await dummy_miniserver.getJson()
    assert dummy_miniserver.https_status == 0


@pytest.mark.asyncio
async def test_LoxApp_getversion(httpx_mock, dummy_miniserver):
    """Test fetching of https_status, version and json"""
    httpx_mock.add_response(
        url="http://example.com/jdev/cfg/apiKey", data=API_KEY_RETURN_HTTPS_STATUS_1
    )
    httpx_mock.add_response(
        url="http://example.com/jdev/cfg/version", data=VERSION_RETURN
    )
    httpx_mock.add_response(url=f"http://example.com{LOXAPPPATH}", data=LOXAPP3)

    _ = await dummy_miniserver.getJson()
    assert dummy_miniserver.version == [12, 0, 2, 24]
    assert dummy_miniserver.https_status == 1
    assert dummy_miniserver.json["lastModified"] == "2021-05-11 23:09:38"
    assert dummy_miniserver.url == "http://example.com"
