"""
Loxone Api

For more details about this component, please refer to the documentation at
https://github.com/JoDehli/pyloxone-api
"""
import asyncio
import binascii
import hashlib
import json
import logging
import queue
import time
import traceback
import urllib.request as req
import uuid
from base64 import b64encode
from collections import namedtuple
from math import floor  # pylint: disable=no-name-in-module
from struct import unpack  # pylint: disable=no-name-in-module

import httpx
import websockets as wslib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
import ssl

from .const import (
    AES_KEY_SIZE,
    CMD_AUTH_WITH_TOKEN,
    CMD_ENABLE_UPDATES,
    CMD_ENCRYPT_CMD,
    CMD_GET_KEY,
    CMD_GET_KEY_AND_SALT,
    CMD_GET_PUBLIC_KEY,
    CMD_GET_VISUAL_PASSWD,
    CMD_KEY_EXCHANGE,
    CMD_REFRESH_TOKEN,
    CMD_REFRESH_TOKEN_JSON_WEB,
    CMD_REQUEST_TOKEN,
    CMD_REQUEST_TOKEN_JSON_WEB,
    DEFAULT_TOKEN_PERSIST_NAME,
    ERROR_VALUE,
    IV_BYTES,
    KEEP_ALIVE_PERIOD,
    LOXAPPPATH,
    SALT_BYTES,
    SALT_MAX_AGE_SECONDS,
    SALT_MAX_USE_COUNT,
    TIMEOUT,
    TOKEN_PERMISSION,
)


from .exceptions import LoxoneHTTPStatusError, LoxoneRequestError
from .loxtoken import LoxToken

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler())


class LoxAPI:
    def __init__(
        self,
        host=None,
        port=None,
        user=None,
        password=None,
        use_tls=False,
        token_persist_filename=DEFAULT_TOKEN_PERSIST_NAME,
    ):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._token_persist_filename = token_persist_filename
        self._use_tls = use_tls
        # If use_tls is True, certificate hostnames will be checked. This means that
        # an IP address cannot be used as a hostname. Set _tls_check_hostname to false
        # to disable this check. This creates a SECURITY RISK.
        self._tls_check_hostname = True

        self._iv = get_random_bytes(IV_BYTES)
        self._key = get_random_bytes(AES_KEY_SIZE)
        self._saltmine = _SaltMine()
        self._public_key = None
        self._rsa_cipher = None
        self._session_key = None
        self._ws = None
        self._current_message_typ = None
        self._encryption_ready = False
        self._visual_hash = None

        self.message_call_back = None
        self.connect_retries = 20
        self.connect_delay = 10
        self._state = "CLOSED"
        self._secured_queue = queue.Queue(maxsize=1)
        self.config_dir = "."
        self.json = None
        self.snr = ""
        self.version = None  # a string, eg "12.0.1.2"
        self._version = 0  # a list of ints eg [12,0,1,2]
        self._https_status = None  # None = no TLS, 1 = TLS available, 2 = cert expired
        self._token = LoxToken(
            token_dir=self.config_dir,
            token_filename=self._token_persist_filename,
        )

    async def _raise_if_not_200(self, response):
        """An httpx event hook, to ensure that http responses other than 200
        raise an exception"""
        # Loxone response codes are a bit odd. It is not clear whether a response which
        # is not 200 is ever OK (eg it is unclear whether redirect response are issued).
        # json responses also have a "Code" key, but it is unclear whether this is ever
        # different from the http response code. At the moment, we ignore it.
        #
        # And there are references to non-standard codes in the docs (eg a 900 error).
        # At present, treat any non-200 code as an exception.
        if response.status_code != 200:
            raise LoxoneHTTPStatusError(
                f"Code {response.status_code}. Miniserver response was {response.text}"
            )

    async def getJson(self):
        """Obtain basic info from the miniserver"""
        # All initial http/https requests are carried out here, for simplicity. They
        # can all use the same httpx.AsyncClient instance. Any non-200 response from
        # the miniserver will cause an exception to be raised, via the event_hook
        scheme = "https" if self._use_tls else "http"
        client = httpx.AsyncClient(
            auth=(self._user, self._password),
            base_url=f"{scheme}://{self._host}:{self._port}",
            verify=self._tls_check_hostname,
            timeout=TIMEOUT,
            event_hooks={"response": [self._raise_if_not_200]},
        )
        try:
            api_resp = await client.get("/jdev/cfg/apiKey")
            api_data = api_resp.json()
            value = api_data.get("LL", {}).get("value", "{}")
            # The json returned by the miniserver is invalid. It contains " and '.
            # We need to normalise it
            value = json.loads(value.replace("'", '"'))
            self._https_status = value.get("httpsStatus")
            self.version = value.get("version")
            self._version = (
                [int(x) for x in self.version.split(".")] if self.version else []
            )
            self.snr = value.get("snr")

            # Get the structure file
            loxappdata = await client.get(LOXAPPPATH)
            status = loxappdata.status_code
            if status == 200:
                self.json = loxappdata.json()
                self.json[
                    "softwareVersion"
                ] = self._version  # FIXME Legacy use only. Need to fix pyloxone

            # Get the public key
            pk_data = await client.get(CMD_GET_PUBLIC_KEY)
            pk_json = pk_data.json()
            pk = pk_json.get("LL", {}).get("value", "")
            # The certificate returned by Loxone is not properly PEM encoded. It needs
            # newlines inserting. Python does not insist on 64 char line lengths
            # however. If, for some reason, no certificate is returned, _public_key will
            # be ""
            self._public_key = pk.replace(
                "-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n"
            ).replace("-----END CERTIFICATE-----", "\n-----END PUBLIC KEY-----\n")

        # Handle errors. An http error getting any of the required data is
        # probably fatal, so log it and raise it for handling elsewhere. Other errors
        # are (hopefully) unlikely, but are not handled here, so will be raised
        # normally.
        except httpx.RequestError as exc:
            _LOGGER.error(
                f'An error "{exc}" occurred while requesting {exc.request.url!r}.'
            )
            raise LoxoneRequestError(exc) from None
        except LoxoneHTTPStatusError as exc:
            _LOGGER.error(exc)
            raise

        else:
            return
        finally:
            # Async httpx client must always be closed
            await client.aclose()

    async def _refresh_token(self):
        while True:
            seconds_to_refresh = self._token.seconds_to_expire()
            await asyncio.sleep(seconds_to_refresh)
            command = f"{CMD_GET_KEY}"
            enc_command = self._encrypt(command)
            await self._ws.send(enc_command)
            message = await self._ws.recv()
            resp_json = json.loads(message)
            token_hash = None
            if "LL" in resp_json:
                if "value" in resp_json["LL"]:
                    key = resp_json["LL"]["value"]
                    if key == "":
                        if self._version < [12, 0]:
                            digester = HMAC.new(
                                binascii.unhexlify(key),
                                self._token.token.encode("utf-8"),
                                SHA1,
                            )
                        else:
                            digester = HMAC.new(
                                binascii.unhexlify(key),
                                self._token.token.encode("utf-8"),
                                SHA256,
                            )
                        token_hash = digester.hexdigest()

            if token_hash is not None:
                if self._version < [10, 2]:
                    command = f"{CMD_REFRESH_TOKEN}{token_hash}/{self._user}"
                else:
                    command = f"{CMD_REFRESH_TOKEN_JSON_WEB}{token_hash}/{self._user}"

                enc_command = self._encrypt(command)
                await self._ws.send(enc_command)
                message = await self._ws.recv()
                resp_json = json.loads(message)

                _LOGGER.debug(
                    f"Seconds before refresh: {self._token.seconds_to_expire()}"
                )

                if "LL" in resp_json:
                    if "value" in resp_json["LL"]:
                        if "validUntil" in resp_json["LL"]["value"]:
                            self._token.valid_until = resp_json["LL"]["value"][
                                "validUntil"
                            ]

                self._token.save()

    async def start(self):
        consumer_task = self._ws_listen()
        keep_alive_task = self._keep_alive(KEEP_ALIVE_PERIOD)
        refresh_token_task = self._refresh_token()

        _, pending = await asyncio.wait(
            [consumer_task, keep_alive_task, refresh_token_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        # The first task has completed. Cancel the others
        for task in pending:
            task.cancel()
        # Wait until they have cancelled properly
        await asyncio.wait(pending)

        if self._state != "STOPPING" and self._state != "CONNECTED":
            await self._reconnect()

    async def _reconnect(self):
        for i in range(self.connect_retries):
            _LOGGER.debug(f"reconnect: {i + 1} from {self.connect_retries}")
            await self.stop()
            self._state = "CONNECTING"
            _LOGGER.debug(f"wait for {self.connect_delay} seconds...")
            await asyncio.sleep(self.connect_delay)
            res = await self.async_init()
            if res is True:
                await self.start()
                break

    # https://github.com/aio-libs/aiohttp/issues/754
    async def stop(self):
        try:
            self._state = "STOPPING"
            if not self._ws.closed:
                await self._ws.close()
            return 1
        except:
            return -1

    async def _keep_alive(self, second):
        while True:
            await asyncio.sleep(second)
            if self._encryption_ready:
                await self._ws.send("keepalive")

    async def _send_secured(self, device_uuid, value, code):
        pwd_hash_str = f"{code}:{self._visual_hash.salt}"
        if self._visual_hash.hash_alg == "SHA1":
            m = hashlib.sha1()
        elif self._visual_hash.hash_alg == "SHA256":
            m = hashlib.sha256()
        else:
            _LOGGER.error(
                "Unrecognised hash algorithm: {}".format(self._visual_hash.hash_alg)
            )
            return -1

        m.update(pwd_hash_str.encode("utf-8"))
        pwd_hash = m.hexdigest().upper()
        if self._visual_hash.hash_alg == "SHA1":
            digester = HMAC.new(
                binascii.unhexlify(self._visual_hash.key),
                pwd_hash.encode("utf-8"),
                SHA1,
            )
        elif self._visual_hash.hash_alg == "SHA256":
            digester = HMAC.new(
                binascii.unhexlify(self._visual_hash.key),
                pwd_hash.encode("utf-8"),
                SHA256,
            )

        command = f"jdev/sps/ios/{digester.hexdigest()}/{device_uuid}/{value}"
        await self._ws.send(command)

    async def send_secured__websocket_command(self, device_uuid, value, code):
        self._secured_queue.put((device_uuid, value, code))
        # Get visual hash
        command = f"{CMD_GET_VISUAL_PASSWD}{self._user}"
        enc_command = self._encrypt(command)
        await self._ws.send(enc_command)

    async def send_websocket_command(self, device_uuid, value):
        """Send a websocket command to the Miniserver."""
        command = f"jdev/sps/io/{device_uuid}/{value}"
        _LOGGER.debug(f"send command: {command}")
        await self._ws.send(command)

    async def async_init(self):
        # Read token from file

        _LOGGER.debug("try to get_token_from_file")

        if self._token.load():
            _LOGGER.debug("token successfully loaded from file")
        else:
            _LOGGER.debug("error token read")

        # Init resa cipher
        try:
            self._rsa_cipher = PKCS1_v1_5.new(RSA.importKey(self._public_key))
            _LOGGER.debug("init_rsa_cipher successfully...")
            result = True
        except KeyError:
            _LOGGER.debug("init_rsa_cipher error...")
            _LOGGER.debug(f"{traceback.print_exc()}")
            result = False
        rsa_gen = result
        if not rsa_gen:
            return ERROR_VALUE

        # Generate session key
        try:
            aes_key = binascii.hexlify(self._key).decode("utf-8")
            iv = binascii.hexlify(self._iv).decode("utf-8")
            sess = f"{aes_key}:{iv}"
            sess = self._rsa_cipher.encrypt(bytes(sess, "utf-8"))
            self._session_key = b64encode(sess).decode("utf-8")
            _LOGGER.debug("generate_session_key successfully...")
            result1 = True
        except KeyError:
            _LOGGER.debug("error generate_session_key...")
            result1 = False
        session_gen = result1
        if not session_gen:
            return ERROR_VALUE

        # Exchange keys
        try:
            scheme = "wss" if self._use_tls else "ws"
            url = f"{scheme}://{self._host}:{self._port}/ws/rfc6455"
            if self._use_tls:
                # pylint: disable=no-member
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = self._tls_check_hostname
                self._ws = await wslib.connect(url, timeout=TIMEOUT, ssl=ssl_context)
            else:
                # pylint: disable=no-member
                self._ws = await wslib.connect(url, timeout=TIMEOUT)

            await self._ws.send(f"{CMD_KEY_EXCHANGE}{self._session_key}")

            message = await self._ws.recv()
            self._unpack_loxone_message(message)
            if self._current_message_typ != 0:
                _LOGGER.debug("error by getting the session key response...")
                return ERROR_VALUE

            message = await self._ws.recv()
            resp_json = json.loads(message)
            if "LL" in resp_json:
                if "Code" in resp_json["LL"]:
                    if resp_json["LL"]["Code"] != "200":
                        return ERROR_VALUE
            else:
                return ERROR_VALUE

        except ConnectionError:
            _LOGGER.debug("connection error...")
            return ERROR_VALUE

        self._encryption_ready = True

        if (
            self._token is None
            or self._token.token == ""
            or self._token.seconds_to_expire() < 300
        ):
            res = await self._acquire_token()
        else:
            res = await self._use_token()
            # Delete old token
            if res is ERROR_VALUE:
                self._token.delete()
                _LOGGER.debug(
                    "Old Token found and deleted. Please restart Homeassistant to acquire new token."
                )
                return ERROR_VALUE

        if res is ERROR_VALUE:
            return ERROR_VALUE

        if self._ws.closed:
            _LOGGER.debug(f"Connection closed. Reason {self._ws.close_code}")
            return False

        command = f"{CMD_ENABLE_UPDATES}"
        enc_command = self._encrypt(command)
        await self._ws.send(enc_command)
        if self._ws.closed:
            _LOGGER.debug(f"Connection closed. Reason {self._ws.close_code}")
            return False
        _ = await self._ws.recv()
        _ = await self._ws.recv()

        self._state = "CONNECTED"
        return True

    async def _ws_listen(self):
        """Listen to all commands from the Miniserver."""
        try:
            while True:
                message = await self._ws.recv()
                await self._async_process_message(message)
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            _LOGGER.debug("Cancelling .....")
            raise
        except:
            await asyncio.sleep(5)
            if self._ws.closed and self._ws.close_code in [4004, 4005]:
                self._token.delete()

            elif self._ws.closed and self._ws.close_code:
                await self._reconnect()

    async def _async_process_message(self, message):
        """Process the messages."""
        if len(message) == 8:
            unpacked_data = unpack("ccccI", message)
            self._current_message_typ = int.from_bytes(
                unpacked_data[1], byteorder="big"
            )
            if self._current_message_typ == 6:
                _LOGGER.debug("Keep alive response received...")
        else:
            parsed_data = self._parse_loxone_message(message)
            _LOGGER.debug(
                "message [type:{}]):{}".format(
                    self._current_message_typ, json.dumps(parsed_data, indent=2)
                )
            )

            try:
                resp_json = json.loads(parsed_data)
            except TypeError:
                resp_json = None

            # Visual hash and key response
            if resp_json is not None and "LL" in resp_json:
                if (
                    "control" in resp_json["LL"]
                    and "code" in resp_json["LL"]
                    and resp_json["LL"]["code"] in [200, "200"]
                ):
                    if "value" in resp_json["LL"]:
                        if (
                            "key" in resp_json["LL"]["value"]
                            and "salt" in resp_json["LL"]["value"]
                        ):
                            key_and_salt = LxJsonKeySalt()
                            key_and_salt.read_user_salt_response(parsed_data)
                            self._visual_hash = key_and_salt

                            while not self._secured_queue.empty():
                                secured_message = self._secured_queue.get()
                                await self._send_secured(
                                    secured_message[0],
                                    secured_message[1],
                                    secured_message[2],
                                )

            if self.message_call_back is not None:
                if "LL" not in parsed_data and parsed_data != {}:
                    # pylint: disable=not-callable
                    await self.message_call_back(parsed_data)
            self._current_message_typ = None
            await asyncio.sleep(0)

    def _parse_loxone_message(self, message):
        """Parser of the Loxone message."""
        event_dict = {}
        if self._current_message_typ == 0:
            event_dict = message
        elif self._current_message_typ == 1:
            pass
        elif self._current_message_typ == 2:
            length = len(message)
            num = length / 24
            start = 0
            end = 24
            for _ in range(int(num)):
                packet = message[start:end]
                event_uuid = uuid.UUID(bytes_le=packet[0:16])
                fields = event_uuid.urn.replace("urn:uuid:", "").split("-")
                uuidstr = f"{fields[0]}-{fields[1]}-{fields[2]}-{fields[3]}{fields[4]}"
                value = unpack("d", packet[16:24])[0]
                event_dict[uuidstr] = value
                start += 24
                end += 24
        elif self._current_message_typ == 3:
            start = 0

            def get_text(message, start, offset):
                first = start
                second = start + offset
                event_uuid = uuid.UUID(bytes_le=message[first:second])
                first += offset
                second += offset

                icon_uuid_fields = event_uuid.urn.replace("urn:uuid:", "").split("-")
                uuidstr = "{}-{}-{}-{}{}".format(
                    icon_uuid_fields[0],
                    icon_uuid_fields[1],
                    icon_uuid_fields[2],
                    icon_uuid_fields[3],
                    icon_uuid_fields[4],
                )

                icon_uuid = uuid.UUID(bytes_le=message[first:second])
                icon_uuid_fields = icon_uuid.urn.replace("urn:uuid:", "").split("-")

                first = second
                second += 4

                text_length = unpack("<I", message[first:second])[0]

                first = second
                second = first + text_length
                message_str = unpack(f"{text_length}s", message[first:second])[0]
                start += (floor((4 + text_length + 16 + 16 - 1) / 4) + 1) * 4
                event_dict[uuidstr] = message_str.decode("utf-8")
                return start

            while start < len(message):
                start = get_text(message, start, 16)

        elif self._current_message_typ == 6:
            event_dict["keep_alive"] = "received"
        else:
            self._current_message_typ = 7
        return event_dict

    async def _use_token(self):
        token_hash = await self._hash_token()
        if token_hash is ERROR_VALUE:
            return ERROR_VALUE
        command = f"{CMD_AUTH_WITH_TOKEN}{token_hash}/{self._user}"
        enc_command = self._encrypt(command)
        await self._ws.send(enc_command)
        message = await self._ws.recv()
        self._unpack_loxone_message(message)
        message = await self._ws.recv()
        resp_json = json.loads(message)
        if "LL" in resp_json:
            if "code" in resp_json["LL"]:
                if resp_json["LL"]["code"] == "200":
                    if "value" in resp_json["LL"]:
                        self._token.valid_until = resp_json["LL"]["value"]["validUntil"]
                    return True
        return ERROR_VALUE

    async def _hash_token(self):
        try:
            command = f"{CMD_GET_KEY}"
            enc_command = self._encrypt(command)
            await self._ws.send(enc_command)
            message = await self._ws.recv()
            self._unpack_loxone_message(message)
            message = await self._ws.recv()
            resp_json = json.loads(message)
            if "LL" in resp_json:
                if "value" in resp_json["LL"]:
                    key = resp_json["LL"]["value"]
                    if key != "":
                        if self._token.hash_alg == "SHA1":
                            digester = HMAC.new(
                                binascii.unhexlify(key),
                                self._token.token.encode("utf-8"),
                                SHA1,
                            )
                        elif self._token.hash_alg == "SHA256":
                            digester = HMAC.new(
                                binascii.unhexlify(key),
                                self._token.token.encode("utf-8"),
                                SHA256,
                            )
                        else:
                            _LOGGER.error(
                                "Unrecognised hash algorithm: {}".format(
                                    self._token.hash_alg
                                )
                            )
                            return ERROR_VALUE

                        return digester.hexdigest()
            return ERROR_VALUE
        except:
            return ERROR_VALUE

    async def _acquire_token(self):
        _LOGGER.debug("acquire_token")
        command = f"{CMD_GET_KEY_AND_SALT}{self._user}"
        enc_command = self._encrypt(command)

        if not self._encryption_ready or self._ws is None:
            return ERROR_VALUE

        await self._ws.send(enc_command)
        message = await self._ws.recv()
        self._unpack_loxone_message(message)

        message = await self._ws.recv()

        key_and_salt = LxJsonKeySalt()
        key_and_salt.read_user_salt_response(message)

        new_hash = self._hash_credentials(key_and_salt)

        if self._version < [10, 2]:
            command = (
                "{}{}/{}/{}/edfc5f9a-df3f-4cad-9dddcdc42c732be2"
                "/pyloxone_api".format(
                    CMD_REQUEST_TOKEN, new_hash, self._user, TOKEN_PERMISSION
                )
            )
        else:
            command = (
                "{}{}/{}/{}/edfc5f9a-df3f-4cad-9dddcdc42c732be2"
                "/pyloxone_api".format(
                    CMD_REQUEST_TOKEN_JSON_WEB,
                    new_hash,
                    self._user,
                    TOKEN_PERMISSION,
                )
            )

        enc_command = self._encrypt(command)
        await self._ws.send(enc_command)
        message = await self._ws.recv()
        self._unpack_loxone_message(message)
        message = await self._ws.recv()

        resp_json = json.loads(message)
        if "LL" in resp_json:
            if "value" in resp_json["LL"]:
                if (
                    "token" in resp_json["LL"]["value"]
                    and "validUntil" in resp_json["LL"]["value"]
                ):
                    self._token.token = resp_json["LL"]["value"]["token"]
                    self._token.valid_until = resp_json["LL"]["value"]["validUntil"]
                    self._token.hash_alg = key_and_salt.hash_alg

        if not self._token.save():
            return ERROR_VALUE
        return True

    def _encrypt(self, command):
        if not self._encryption_ready:
            return command
        salt = self._saltmine.get_salt()
        if salt.is_new:
            s = f"nextSalt/{salt.previous}/{salt.value}/{command}\x00"
        else:
            s = f"salt/{salt.value}/{command}\x00"

        s = Padding.pad(bytes(s, "utf-8"), 16)
        try:
            _new_aes = AES.new(self._key, AES.MODE_CBC, self._iv)
            _LOGGER.debug("get_new_aes_cipher successfully...")
            result = _new_aes
        except ValueError:
            _LOGGER.debug("error get_new_aes_cipher...")
            result = None
        aes_cipher = result
        encrypted = aes_cipher.encrypt(s)
        encoded = b64encode(encrypted)
        encoded_url = req.pathname2url(encoded.decode("utf-8"))
        return CMD_ENCRYPT_CMD + encoded_url

    def _hash_credentials(self, key_salt):
        try:
            pwd_hash_str = f"{self._password}:{key_salt.salt}"
            if key_salt.hash_alg == "SHA1":
                m = hashlib.sha1()
            elif key_salt.hash_alg == "SHA256":
                m = hashlib.sha256()
            else:
                _LOGGER.error(
                    "Unrecognised hash algorithm: {}".format(key_salt.hash_alg)
                )
                return None

            m.update(pwd_hash_str.encode("utf-8"))
            pwd_hash = m.hexdigest().upper()
            pwd_hash = f"{self._user}:{pwd_hash}"

            if key_salt.hash_alg == "SHA1":
                digester = HMAC.new(
                    binascii.unhexlify(key_salt.key), pwd_hash.encode("utf-8"), SHA1
                )
            elif key_salt.hash_alg == "SHA256":
                digester = HMAC.new(
                    binascii.unhexlify(key_salt.key), pwd_hash.encode("utf-8"), SHA256
                )
            _LOGGER.debug("hash_credentials successfully...")
            return digester.hexdigest()
        except ValueError:
            _LOGGER.debug("error hash_credentials...")
            return None

    def _unpack_loxone_message(self, message):
        if len(message) == 8:
            try:
                unpacked_data = unpack("ccccI", message)
                self._current_message_typ = int.from_bytes(
                    unpacked_data[1], byteorder="big"
                )
                _LOGGER.debug("unpack_message successfully...")
            except ValueError:
                _LOGGER.debug("error unpack_message...")


# Loxone Stuff


class LxJsonKeySalt:
    def __init__(self):
        self.key = None
        self.salt = None
        self.response = None
        self.hash_alg = None

    def read_user_salt_response(self, response):
        js = json.loads(response, strict=False)
        value = js["LL"]["value"]
        self.key = value["key"]
        self.salt = value["salt"]
        self.hash_alg = value.get("hashAlg", "SHA1")


Salt = namedtuple("Salt", ["value", "is_new", "previous"])


class _SaltMine:
    """A salt used for encrypting commands."""

    def __init__(self):
        self._salt = None
        self._generate_new_salt()

    def _generate_new_salt(self):
        self._previous = self._salt
        self._salt = get_random_bytes(SALT_BYTES).hex()
        self._timestamp = time.time()
        self._used_count = 0
        self._is_new = True
        _LOGGER.debug("Generating a new salt")

    def get_salt(self):
        """Get the current salt in use, or generate a new one if it has expired

        Returns a namedtuple, with attibutes value (the salt as a hex string),
        is_new (a boolean indicating whether this is the first time this
        salt has been returned), and previous (the value of the previous salt, or None).
        """

        self._used_count += 1
        self._is_new = False
        if (
            self._used_count > SALT_MAX_USE_COUNT
            or time.time() - self._timestamp > SALT_MAX_AGE_SECONDS
        ):
            # the salt has expired. Get a new one.
            self._previous = self._salt
            self._generate_new_salt()

        return Salt(self._salt, self._is_new, self._previous)
