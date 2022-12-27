import pytest

import pyloxone_api
from pyloxone_api import Miniserver
from pyloxone_api.exceptions import LoxoneHTTPStatusError


@pytest.fixture
def dummy_miniserver():
    """A dummy LoxApp() with fake credentials"""
    return Miniserver(user="admin", password="password", host="example.com", port=80)


def test_Miniserver_init():
    """Test class initialisation"""
    api = Miniserver()
    assert api.host == ""
    assert api.port == 80
    assert api.user == ""
    assert api.password == ""
    assert api._version == ""
    assert api._https_status == 0
    assert api._tls_check_hostname is True
    assert api._use_tls is False


@pytest.mark.asyncio
class Test_get_json:
    """Test operation of basicInfo methods"""

    API_KEY_RETURN = """{
    "LL": {
        "control": "dev/cfg/apiKey",
        "value":
        "{'snr': '12:34:56:78:9A:BC', 'version':'12.0.2.24', 'key':'1234', 'httpsStatus':1}",
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
    async def test_Miniserver_json_http_error(
        self, httpx_mock, dummy_miniserver, status_code
    ):
        """Test http error from server"""
        httpx_mock.add_response(status_code=status_code)
        with pytest.raises(LoxoneHTTPStatusError):
            await dummy_miniserver._ensure_reachable_and_get_structure()

    async def test_Miniserver_getmsInfo(self, httpx_mock, dummy_miniserver):
        """Test fetching of https_status, version, json etc"""
        httpx_mock.add_response(
            url="http://example.com/jdev/cfg/apiKey", text=self.API_KEY_RETURN
        )
        httpx_mock.add_response(
            url="http://example.com/data/LoxAPP3.json", text=self.LOXAPP3
        )
        httpx_mock.add_response(
            url="http://example.com/jdev/sys/getPublicKey", text=self.PUBLIC_KEY_RETURN
        )

        _ = await dummy_miniserver._ensure_reachable_and_get_structure()
        assert dummy_miniserver.version == [12, 0, 2, 24]
        assert dummy_miniserver._https_status == 1
        assert dummy_miniserver.structure["lastModified"] == "2021-05-11 23:09:38"
        assert dummy_miniserver._public_key != ""
        assert dummy_miniserver.host == "example.com"
        assert dummy_miniserver.port == 80
        assert dummy_miniserver.user == "admin"
        assert dummy_miniserver.password == "password"
        assert dummy_miniserver.msInfo.projectName == "MyProject"
        assert dummy_miniserver.msInfo.roomTitle == "Rooms"


# def test_salt(monkeypatch):
#     monkeypatch.setattr(pyloxone_api.api, "SALT_MAX_USE_COUNT", 2)
#     s = _SaltMine()
#     salt1 = s.get_salt()
#     assert not salt1.is_new
#     # Check that value is a 32 character hex string
#     assert len(salt1.value) == 32
#     assert int(salt1.value, 16)

#     salt2 = s.get_salt()
#     assert salt2 == salt1
#     assert s._used_count == 2
#     salt3 = s.get_salt()  # Should trigger new salt generation
#     assert s._used_count == 0
#     assert salt3.is_new
#     assert salt3.value != salt2.value
#     assert salt3.previous == salt2.value


def test_hash(dummy_miniserver):
    dummy_miniserver._hash_alg = "SHA1"
    dummy_miniserver._hash_credentials()
