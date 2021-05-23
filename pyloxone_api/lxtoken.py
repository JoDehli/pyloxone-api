"""The LxToken class, used for persisting token information """
import json
import logging
import os
import time
from datetime import datetime

from pyloxone_api.const import ERROR_VALUE

_LOGGER = logging.getLogger(__name__)


class LxToken:
    def __init__(
        self,
        token="",
        valid_until=0,
        hash_alg="SHA1",
        token_dir=".",
        token_filename="",
    ):
        self.token = token
        self.valid_until = valid_until
        self.hash_alg = hash_alg
        self.token_dir = token_dir
        self.token_filename = token_filename

    def seconds_to_expire(self):
        # Loxone epoch is 1.1.2009
        loxone_epoch = datetime(2009, 1, 1, 0, 0)
        # convert to seconds since Unix epoch
        start_seconds = int(loxone_epoch.strftime("%s"))
        end_seconds = start_seconds + self.valid_until
        # substract seconds since Unix epoch
        return end_seconds - int(round(time.time()))

    def load(self):
        try:
            persist_token = os.path.join(self.token_dir, self.token_filename)
            try:
                with open(persist_token) as f:
                    try:
                        dict_token = json.load(f)
                    except ValueError:
                        return ERROR_VALUE
            except FileNotFoundError:
                with open(self.token_filename) as f:
                    try:
                        dict_token = json.load(f)
                    except ValueError:
                        return ERROR_VALUE
            self.token = dict_token["_token"]
            self.valid_until = dict_token["_valid_until"]
            self.hash_alg = dict_token["_hash_alg"]

            _LOGGER.debug("load_token successfully...")
            return True
        except OSError:
            _LOGGER.debug("error load_token...")
            return ERROR_VALUE

    def save(self):
        try:
            persist_token = os.path.join(self.token_dir, self.token_filename)
            dict_token = {
                "_token": self.token,
                "_valid_until": self.valid_until,
                "_hash_alg": self.hash_alg,
            }
            try:
                with open(persist_token, "w") as write_file:
                    json.dump(dict_token, write_file)
            except FileNotFoundError:
                with open(self.token_filename, "w") as write_file:
                    json.dump(dict_token, write_file)

            _LOGGER.debug("save_token successfully...")
            return True
        except OSError:
            _LOGGER.debug("error save_token...")
            _LOGGER.debug(f"tokenpath: {persist_token}")
            return ERROR_VALUE

    def delete(self):
        try:
            persist_token = os.path.join(self.token_dir, self.token_filename)
            try:
                os.remove(persist_token)
            except FileNotFoundError:
                os.remove(self.token_filename)

        except OSError:
            _LOGGER.debug("error deleting token...")
            return ERROR_VALUE
