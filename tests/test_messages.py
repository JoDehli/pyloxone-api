from pyloxone_api.exceptions import LoxoneException
from pyloxone_api.message import parse_header, MessageType, LoxoneResponse
import pytest

HEADER1 = b"\x03\x01\xFF\x00\x9c\x17\x00\x00"
BADMESSAGE1 = b"\x03\x01\x00\x00\x9c\x17\x00\x00\x03"
BADMESSAGE2 = b"\x02\x01\x00\x00\x9c\x17\x00\x00"


def test_header():
    l = parse_header(HEADER1)
    assert l.message_type == MessageType.BINARY
    assert l.estimated is True
    assert l.payload_length == 6044


@pytest.mark.parametrize("message", [BADMESSAGE1, BADMESSAGE2])
def test_bad_header(message):
    with pytest.raises(LoxoneException):
        parse_header(message)


class Test_LL_Response:

    LL_RESPONSE = (
        '{"LL": { "control": "dev/sys/getPublicKey", '
        '"value": "my hovercraft is full of eels",'
        '"Code": "200"}}'
    )
    NESTED_LL_RESPONSE = (
        '{"LL": { "control": "dev/sys/getPublicKey", '
        '"value": { "text": "my hovercraft is full of eels"} ,'
        '"Code": "200"}}'
    )
    BAD_LL_RESPONSE_NOT_INT = (
        '{"LL": { "control": "dev/sys/getPublicKey", '
        '"value": "my hovercraft is full of eels",'
        '"Code": "a"}}'
    )
    BAD_LL_RESPONSE_NO_VALUE = (
        '{"LL": { "control": "dev/sys/getPublicKey", ' '"Code": "200"}}'
    )

    def test_LL_response(self):
        response = LoxoneResponse(self.LL_RESPONSE)
        assert response.control == "dev/sys/getPublicKey"
        assert response.code == 200
        assert response.value == "my hovercraft is full of eels"
        assert response.value_as_dict == {"value": "my hovercraft is full of eels"}

    def test_LL_nested_response(self):
        response = LoxoneResponse(self.NESTED_LL_RESPONSE)
        assert response.control == "dev/sys/getPublicKey"
        assert response.code == 200
        assert response.value == "{'text': 'my hovercraft is full of eels'}"
        assert response.value_as_dict == {
            "value": "{'text': 'my hovercraft is full of eels'}",
            "text": "my hovercraft is full of eels",
        }
        assert response.value_as_dict["text"] == "my hovercraft is full of eels"

    @pytest.mark.parametrize(
        "response", [BAD_LL_RESPONSE_NOT_INT, BAD_LL_RESPONSE_NO_VALUE]
    )
    def test_bad_LL_response(self, response):
        with pytest.raises(ValueError):
            assert LoxoneResponse(response)
