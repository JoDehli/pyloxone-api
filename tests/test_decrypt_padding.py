"""Tolerant padding removal in ``LoxoneConnection._decrypt``.

The Miniserver answers with PKCS#7 padding in most cases, but some replies
are zero-padded. Both must decrypt; only a valid PKCS#7 tail is stripped as
PKCS#7.
"""

from __future__ import annotations

import base64

import pytest
from Crypto.Cipher import AES
from Crypto.Util import Padding

from pyloxone_api.connection import LoxoneConnection

PREFIX = "jdev/sys/enc/"


@pytest.fixture
def conn():
    c = LoxoneConnection(host="192.0.2.1", username="user", password="pw", port=8080)
    c._aes_key = bytes(range(32))
    c._iv = bytes(range(16))
    return c


def _encrypt_raw(conn, plain: bytes) -> str:
    """Encrypt ``plain`` as given (length must be a multiple of 16)."""
    assert len(plain) % 16 == 0
    cipher = AES.new(conn._aes_key, AES.MODE_CBC, conn._iv)
    return PREFIX + base64.b64encode(cipher.encrypt(plain)).decode()


def _pkcs7(conn, plain: bytes) -> str:
    return _encrypt_raw(conn, Padding.pad(plain, 16))


def _zero_pad(conn, plain: bytes) -> str:
    padded = plain + b"\x00" * (-len(plain) % 16)
    return _encrypt_raw(conn, padded)


class TestDecryptPadding:
    def test_pkcs7_reply_is_unpadded(self, conn):
        text = b"jdev/sys/getkey2/ok"
        assert conn._decrypt(_pkcs7(conn, text)) == text

    def test_zero_padded_reply_is_accepted(self, conn):
        text = b"jdev/sys/getkey2/ok"
        assert conn._decrypt(_zero_pad(conn, text)) == text

    def test_zero_padded_reply_with_salt_prefix(self, conn):
        text = b"salt/0123abcd/jdev/sys/getvisusalt/ok"
        assert conn._decrypt(_zero_pad(conn, text)) == text

    def test_zero_padded_reply_with_next_salt_prefix(self, conn):
        text = b"nextSalt/aa/bb/jdev/sys/getvisusalt/ok"
        assert conn._decrypt(_zero_pad(conn, text)) == text

    def test_last_plain_byte_zero_is_not_a_padding_error(self, conn):
        # Last decrypted byte is 0x00, which is not a valid PKCS#7 count.
        text = b"jdev/sys/ok"
        assert conn._decrypt(_encrypt_raw(conn, text + b"\x00" * 5)) == text

    def test_unpadded_plaintext_is_returned_as_is(self, conn):
        # Exactly one block, last byte is a letter (not a PKCS#7 count).
        text = b"abcdefghijklmnop"
        assert conn._decrypt(_encrypt_raw(conn, text)) == text

    def test_pkcs7_count_equal_to_block_size(self, conn):
        # A full block of 0x10 bytes is a valid PKCS#7 pad of 16 bytes.
        text = b""
        assert conn._decrypt(_pkcs7(conn, text)) == text

    def test_pkcs7_tail_with_mismatched_bytes_is_not_stripped(self, conn):
        # Last byte is 3, but the last three bytes are 04 05 03, not 03 03 03:
        # not valid PKCS#7, and there are no trailing zero bytes to remove.
        plain = b"helloworld" + b"\x01\x02\x03\x04\x05" + b"\x03"
        assert len(plain) == 16
        assert conn._decrypt(_encrypt_raw(conn, plain)) == plain
