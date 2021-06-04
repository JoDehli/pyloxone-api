from pyloxone_api.exceptions import LoxoneException
from pyloxone_api.message import parse_header, MessageType
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
