"""
Loxone Api

For more details about this component, please refer to the documentation at
https://github.com/JoDehli/pyloxone-api
"""
import asyncio
import hashlib
import json
import logging
from pyloxone_api.websocket import Websocket
from pyloxone_api.message import MessageType, parse_header
import queue
import ssl
import time
import urllib.parse
import uuid
from base64 import b64decode, b64encode
from collections import namedtuple

import httpx
import websockets as wslib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

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
from .exceptions import LoxoneException, LoxoneHTTPStatusError, LoxoneRequestError
from .loxtoken import LoxToken

_LOGGER = logging.getLogger(__name__)


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
        self._socket_lock = asyncio.Lock()

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
            # Loxone returns a certificate instead of a key, and the certificate is not
            # properly PEM encoded because it does not contain newlines before/after the
            # boundaries. We need to fix both problems. Proper PEM encoding requires 64
            # char line lengths throughout, but Python does not seem to insist on this.
            # If, for some reason, no certificate is returned, _public_key will be an
            # empty string.
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
            # We need exlusive control of the websocket. Without this, the main
            # message receiving coroutine could be scheduled whilst we are
            # waiting for the refresh response, and it would intercept it.
            async with self._socket_lock:
                await self._ws.send(enc_command)
                message = await self._ws.recv_message()
            resp_json = json.loads(message.message)
            token_hash = None
            if "LL" in resp_json:
                if "value" in resp_json["LL"]:
                    key = resp_json["LL"]["value"]
                    if key != "":
                        if self._version < [12, 0]:
                            digester = HMAC.new(
                                bytes.fromhex(key),
                                self._token.token.encode("utf-8"),
                                SHA1,
                            )
                        else:
                            digester = HMAC.new(
                                bytes.fromhex(key),
                                self._token.token.encode("utf-8"),
                                SHA256,
                            )
                        token_hash = digester.hexdigest()

            if token_hash is not None:
                if self._version < [10, 2]:
                    command = f"{CMD_REFRESH_TOKEN}{token_hash}/{self._user}"
                else:
                    command = f"{CMD_REFRESH_TOKEN_JSON_WEB}{token_hash}/{self._user}"

                async with self._socket_lock:
                    enc_command = self._encrypt(command)
                    await self._ws.send(enc_command)
                    message = await self._ws.recv_message()
                resp_json = json.loads(message.message)

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
                async with self._socket_lock:
                    await self._ws.send("keepalive")
                    response = await self._ws.recv()  # the keepalive response
                    _LOGGER.debug(f"Keepalive response: {response}")

    async def _send_secured(self, device_uuid, value, code):
        pwd_hash_str = f"{code}:{self._visual_hash.salt}"
        if self._visual_hash.hash_alg == "SHA1":
            m = hashlib.sha1()
        elif self._visual_hash.hash_alg == "SHA256":
            m = hashlib.sha256()
        else:
            _LOGGER.error(f"Unrecognised hash algorithm: {self._visual_hash.hash_alg}")
            return -1

        m.update(pwd_hash_str.encode("utf-8"))
        pwd_hash = m.hexdigest().upper()
        if self._visual_hash.hash_alg == "SHA1":
            digester = HMAC.new(
                bytes.fromhex(self._visual_hash.key),
                pwd_hash.encode("utf-8"),
                SHA1,
            )
        elif self._visual_hash.hash_alg == "SHA256":
            digester = HMAC.new(
                bytes.fromhex(self._visual_hash.key),
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

        # Init RSA cipher
        try:
            # RSA PKCS1 has been broken for a long time. Loxone uses it anyway
            rsa_cipher = PKCS1_v1_5.new(RSA.importKey(self._public_key))
            _LOGGER.debug("init_rsa_cipher successfully...")
        except ValueError as exc:
            _LOGGER.error(f"Error creating RSA cipher: {exc}")
            raise LoxoneException(exc)

        # Generate session key
        aes_key = self._key.hex()
        iv = self._iv.hex()
        session_key = f"{aes_key}:{iv}"
        try:
            session_key = rsa_cipher.encrypt(bytes(session_key, "utf-8"))
            session_key = b64encode(session_key).decode("utf-8")
            _LOGGER.debug("generate_session_key successfully...")
        except ValueError as exc:
            _LOGGER.error(f"Error generating session key: {exc}")
            raise LoxoneException(exc)

        # Exchange keys

        # Open a websocket connection
        scheme = "wss" if self._use_tls else "ws"
        url = f"{scheme}://{self._host}:{self._port}/ws/rfc6455"
        # pylint: disable=no-member
        try:
            if self._use_tls:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = self._tls_check_hostname
                self._ws = await wslib.connect(
                    url,
                    timeout=TIMEOUT,
                    ssl=ssl_context,
                    create_protocol=Websocket,
                    subprotocols=["remotecontrol"],
                )
            else:
                self._ws = await wslib.connect(
                    url,
                    timeout=TIMEOUT,
                    create_protocol=Websocket,
                    subprotocols=["remotecontrol"],
                )
        except wslib.WebSocketException as exc:
            _LOGGER.error("Unable to open websocket")
            raise LoxoneException(f"Unable to open websocket: {exc}")

        # Pass the session key to the miniserver
        await self._ws.send(f"{CMD_KEY_EXCHANGE}{session_key}")

        message = await self._ws.recv_message()
        if message.message_type is not MessageType.TEXT:
            _LOGGER.debug("error by getting the session key response...")
            return ERROR_VALUE

        # message = await self._ws.recv()
        resp_json = json.loads(message.message)
        if "LL" in resp_json:
            if "Code" in resp_json["LL"]:
                if resp_json["LL"]["Code"] != "200":
                    return ERROR_VALUE
        else:
            return ERROR_VALUE

        self._encryption_ready = True

        # Read token from file
        self._token = LoxToken(
            token_dir=self.config_dir,
            token_filename=self._token_persist_filename,
        )
        loaded = self._token.load()
        if loaded:
            _LOGGER.debug("token successfully loaded from file")
        else:
            _LOGGER.debug("error token read")
        if not loaded or (self._token.seconds_to_expire() < 300):
            res = await self._acquire_token()
        else:
            res = await self._use_token()
            # Delete old token
            if res is ERROR_VALUE:
                self._token.delete()
                _LOGGER.debug(
                    "Old Token found and deleted. Please restart to acquire new token."
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
        _ = await self._ws.recv_message()

        self._state = "CONNECTED"
        return True

    async def _ws_listen(self):
        """Listen to all commands from the Miniserver."""
        try:
            while True:

                await self._async_process_message()
        except asyncio.CancelledError:
            _LOGGER.debug("Cancelling .....")
            raise
        except Exception as exc:
            _LOGGER.exception(exc)
            await asyncio.sleep(5)
            if self._ws.closed and self._ws.close_code in [4004, 4005]:
                self._token.delete()

            elif self._ws.closed and self._ws.close_code:
                await self._reconnect()

    async def _async_process_message(self):
        """Process the messages."""
        async with self._socket_lock:
            message = await self._ws.recv_message()

        parsed_data = message.as_dict()
        try:
            _LOGGER.debug(
                "message [type:{}]):{}".format(
                    message.message_type, json.dumps(parsed_data, indent=2)
                )
            )
        except:
            pass

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
        await asyncio.sleep(0)

    async def _use_token(self):
        token_hash = await self._hash_token()
        if token_hash is ERROR_VALUE:
            return ERROR_VALUE
        command = f"{CMD_AUTH_WITH_TOKEN}{token_hash}/{self._user}"
        enc_command = self._encrypt(command)
        await self._ws.send(enc_command)
        message = await self._ws.recv_message()
        resp_json = json.loads(message.message)
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
            message = await self._ws.recv_message()
            resp_json = json.loads(message.message)
            if "LL" in resp_json:
                if "value" in resp_json["LL"]:
                    key = resp_json["LL"]["value"]
                    if key != "":
                        if self._token.hash_alg == "SHA1":
                            digester = HMAC.new(
                                bytes.fromhex(key),
                                self._token.token.encode("utf-8"),
                                SHA1,
                            )
                        elif self._token.hash_alg == "SHA256":
                            digester = HMAC.new(
                                bytes.fromhex(key),
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
        message = await self._ws.recv_message()

        key_and_salt = LxJsonKeySalt()
        key_and_salt.read_user_salt_response(message.message)

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
        message = await self._ws.recv_message()
        resp_json = json.loads(message.message)
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
        encoded_url = urllib.parse.quote(encoded.decode("utf-8"))
        return CMD_ENCRYPT_CMD + encoded_url

    def _decrypt(self, command: str) -> bytes:
        """AES decrypt a command returned by the miniserver."""
        # control will be in the form:
        # "jdev/sys/enc/CHG6k...A=="
        # Encrypted strings returned by the miniserver are not %encoded (even
        # if they were when sent to the miniserver )
        remove_text = "jdev/sys/enc/"
        enc_text = (
            command[len(remove_text) :] if command.startswith(remove_text) else command
        )
        decoded = b64decode(enc_text)
        aes_cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        decrypted = aes_cipher.decrypt(decoded)
        unpadded = Padding.unpad(decrypted, 16)
        # The miniserver seems to terminate the text with a zero byte
        return unpadded.rstrip(b"\x00")

    def _hash_credentials(self, key_salt):
        try:
            pwd_hash_str = f"{self._password}:{key_salt.salt}"
            if key_salt.hash_alg == "SHA1":
                m = hashlib.sha1()
            elif key_salt.hash_alg == "SHA256":
                m = hashlib.sha256()
            else:
                _LOGGER.error(f"Unrecognised hash algorithm: {key_salt.hash_alg}")
                return None

            m.update(pwd_hash_str.encode("utf-8"))
            pwd_hash = m.hexdigest().upper()
            pwd_hash = f"{self._user}:{pwd_hash}"

            if key_salt.hash_alg == "SHA1":
                digester = HMAC.new(
                    bytes.fromhex(key_salt.key), pwd_hash.encode("utf-8"), SHA1
                )
            elif key_salt.hash_alg == "SHA256":
                digester = HMAC.new(
                    bytes.fromhex(key_salt.key), pwd_hash.encode("utf-8"), SHA256
                )
            _LOGGER.debug("hash_credentials successfully...")
            return digester.hexdigest()
        except ValueError:
            _LOGGER.debug("error hash_credentials...")
            return None


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
