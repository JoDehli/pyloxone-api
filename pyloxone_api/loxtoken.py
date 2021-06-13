"""The LxToken class, used for persisting token information """
import json
import logging
import os
from datetime import datetime

_LOGGER = logging.getLogger(__name__)


class LoxToken:
    def __init__(
        self,
        token: str = "",
        valid_until: float = 0,
        hash_alg: str = "SHA1",
        token_dir: str = ".",
        token_filename: str = "",
    ):
        self.token = token
        self.valid_until = valid_until  # seconds since 1.1.2009
        self.hash_alg = hash_alg
        self.token_dir = token_dir
        self.token_filename = token_filename

    def seconds_to_expire(self) -> float:
        # Loxone epoch is 1.1.2009
        loxone_epoch = datetime(2009, 1, 1, 0, 0)
        # current number of seconds since epoch
        current_seconds_since_epoch = (datetime.now() - loxone_epoch).total_seconds()
        # work out how many seconds are left
        return self.valid_until - current_seconds_since_epoch

    def load(self) -> bool:
        persist_token = os.path.join(self.token_dir, self.token_filename)
        try:
            with open(persist_token) as f:
                dict_token = json.load(f)
                self.token = dict_token["_token"]
                self.valid_until = dict_token["_valid_until"]
                self.hash_alg = dict_token["_hash_alg"]
        except (ValueError, KeyError, OSError):
            _LOGGER.debug(f"Cannot load token from {persist_token}")
            return False
        _LOGGER.debug(f"load_token successfully from {persist_token}")
        return True

    def save(self) -> bool:
        try:
            persist_token = os.path.join(self.token_dir, self.token_filename)
            dict_token = {
                "_token": self.token,
                "_valid_until": self.valid_until,
                "_hash_alg": self.hash_alg,
            }
            with open(persist_token, "w") as write_file:
                json.dump(dict_token, write_file)
        except OSError:
            _LOGGER.debug(f"Unable to save token to {persist_token}")
            return False
        return True

    def delete(self) -> bool:
        try:
            persist_token = os.path.join(self.token_dir, self.token_filename)
            os.remove(persist_token)
        except OSError:
            _LOGGER.debug("Error deleting token.")
            return False
        return True
