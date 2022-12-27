"""Tests for the LoxToken class"""
from datetime import datetime, timedelta

import pytest

from pyloxone_api.loxtoken import LoxToken
from pyloxone_api.exceptions import LoxoneTokenError


def test_seconds_to_expire():
    # It is hard to test functions involving time, because it is hard to mock
    # datetime. This test might fail if it takes too long to run.
    # Loxone epoch is 00:00 1.1.2009. Calculate a fake valid_until, 1 hour in the future
    epoch = datetime(2009, 1, 1, 0, 0, 0)
    now = datetime.now()
    difference = now - epoch
    valid_until = difference + timedelta(hours=1)  # 1 hour in the future
    t = LoxToken(valid_until=valid_until.total_seconds())  #
    assert t.seconds_to_expire() == pytest.approx(3600, 2)  # Approx 1 hour left


def test_save_load(tmp_path):
    t = LoxToken(token_dir=tmp_path, token_filename="test_token")
    t.token = "TOKEN"
    t.valid_until = 100
    t.hash_alg = "SHA1"
    t.save_to_file()
    t2 = LoxToken(token_dir=tmp_path, token_filename="test_token")
    t2.load_from_file()
    assert t2.token == t.token
    assert t2.valid_until == t.valid_until
    assert t2.hash_alg == t.hash_alg
    t3 = LoxToken(token_dir=tmp_path, token_filename="test_not_token")
    with pytest.raises(LoxoneTokenError):
        t3.load_from_file()


def test_delete(tmp_path):
    t = LoxToken(token_dir=tmp_path, token_filename="test_token")
    t.token = "TOKEN"
    t.valid_until = 100
    t.hash_alg = "SHA1"
    t.save_to_file()
    t.delete()
    with pytest.raises(LoxoneTokenError):
        t.load_from_file()


def test_hash_credentials():
    pass
