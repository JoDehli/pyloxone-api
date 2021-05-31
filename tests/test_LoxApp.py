import pytest
from pyloxone_api import LoxAPI
import pyloxone_api
from pyloxone_api.api import _SaltMine
from pyloxone_api.const import LOXAPPPATH
from pyloxone_api.exceptions import LoxoneHTTPStatusError


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
    assert api._https_status is None
    assert api._tls_check_hostname is True
    assert api._use_tls is False


@pytest.mark.asyncio
class Test_get_json:
    """Test operation of get_json method"""

    API_KEY_RETURN = """{
    "LL": {
        "control": "dev/cfg/apiKey",
        "value": "{'snr': '12:34:56:78:9A:BC', 'version':'12.0.2.24', 'key':'1234', 'httpsStatus':1}",
        "Code": "200"
    }
    }"""

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

    PUBLIC_KEY_RETURN = (
        '{"LL": { "control": "dev/sys/getPublicKey", '
        '"value": "-----BEGIN CERTIFICATE-----MIIjBa+DNDQVOHKDKw0BAQEFAAOC'
        "Ag8AMIICCgKCAgEAiLCS0w2o+Qw/KL63JTJ5hBOKPEtoc3cXbwnFMwxtk2QVU/L3w"
        'l6O85ECAwEAAQ==-----END CERTIFICATE-----", "Code": "200"}}'
    )

    @pytest.mark.parametrize("status_code", [404, 500, 900])
    async def test_LoxApp_json_http_error(
        self, httpx_mock, dummy_miniserver, status_code
    ):
        """Test http error from server"""
        httpx_mock.add_response(status_code)
        with pytest.raises(LoxoneHTTPStatusError):
            await dummy_miniserver.getJson()

    async def test_LoxApp_getversion(self, httpx_mock, dummy_miniserver):
        """Test fetching of https_status, version, json etc"""
        httpx_mock.add_response(
            url="http://example.com/jdev/cfg/apiKey", data=self.API_KEY_RETURN
        )
        httpx_mock.add_response(
            url=f"http://example.com{LOXAPPPATH}", data=self.LOXAPP3
        )
        httpx_mock.add_response(
            url="http://example.com/jdev/sys/getPublicKey", data=self.PUBLIC_KEY_RETURN
        )

        _ = await dummy_miniserver.getJson()
        assert dummy_miniserver.version == "12.0.2.24"
        assert dummy_miniserver._version == [12, 0, 2, 24]
        assert dummy_miniserver.snr == "12:34:56:78:9A:BC"
        assert dummy_miniserver._https_status == 1
        assert dummy_miniserver.json["lastModified"] == "2021-05-11 23:09:38"
        assert dummy_miniserver._public_key != ""


def test_salt(monkeypatch):
    monkeypatch.setattr(pyloxone_api.api, "SALT_MAX_USE_COUNT", 2)
    s = _SaltMine()
    salt1 = s.get_salt()
    assert not salt1.is_new
    # Check that value is a 32 character hex string
    assert len(salt1.value) == 32
    assert int(salt1.value, 16)

    salt2 = s.get_salt()
    assert salt2 == salt1
    assert s._used_count == 2
    salt3 = s.get_salt()  # Should trigger new salt generation
    assert s._used_count == 0
    assert salt3.is_new
    assert salt3.value != salt2.value
    assert salt3.previous == salt2.value
