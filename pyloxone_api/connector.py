"""A mixin containing methods representing the steps necessary 
for connecting to the Miniserver."""

from __future__ import annotations

import json
import logging
import ssl
from base64 import b64encode
from collections import namedtuple
from typing import Any, Final

import httpx
import websockets as wslib
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from pyloxone_api.exceptions import (
    LoxoneException,
    LoxoneHTTPStatusError,
    LoxoneRequestError,
)
from pyloxone_api.message import LoxoneResponse, MessageType
from pyloxone_api.types import MiniserverProtocol
from pyloxone_api.websocket import Websocket

_LOGGER = logging.getLogger(__name__)
TIMEOUT: Final = 10


async def _raise_if_error(response: httpx.Response) -> None:
    """An httpx event hook, to ensure that http error responses
    raise an exception"""
    # Loxone response codes are a bit odd. It is not clear whether a response
    # which is not 200 is ever OK, though there are reports of the occasional
    # 307. JSON responses also have a "Code" key, but it is unclear whether
    # this is ever different from the http response code. At the moment, we
    # ignore it.
    #
    # And there are references to non-standard codes in the docs (eg a 900
    # error). At present, treat any >=400 code as an exception.
    if response.status_code >= 400:
        await response.aread()  #  https://github.com/encode/httpx/discussions/1856
        raise LoxoneHTTPStatusError(
            f"Code {response.status_code}. Miniserver response was {response.text}"
        )


class ConnectorMixin(MiniserverProtocol):
    # The necessary steps for creating a connection to a miniserver are detailed in
    # Loxone's document "Communicating with the Loxone Miniserver", available from
    # Loxone's website (at the time of writing, https://www.loxone.com/enen/kb/api/).
    # In short, there are 10 steps:
    # 1. Ensure the miniserver is reachable
    # 2. Acquire the miniserver's public key
    # 3. Open a websocket connection
    # 4. Generate an AES256-CBC key
    # 5. Generate a random AES iv (16 byte)
    # 6. RSA Encrypt the AES key+iv with the public key
    # 7. Pass the encrypted session-key to the miniserver
    # 8. Generate a random salt
    # 9. Autheticate with the token (if it exists), or acquire a token
    # 10. Done!

    # Step 1: Ensure the miniserver is reachable. It is convenient, whilst we have an
    # http connection, to use it to obtain the Loxone Structure File as well
    # Step 2: Acquire the miniserver's public key
    async def _ensure_reachable_and_get_structure(self) -> None:
        scheme = "https" if self._use_tls else "http"
        _base_url = f"{scheme}://{self._host}:{self._port}"
        auth = (self._user, self._password) if (self._user and self._password) else None
        # Create the http client. The event hook ensures that any errors encountered in the response
        # are raised as exceptions, and caught below.
        # TODO: Replace with aiohttp
        # TODO: Check what happens with Cloud server and external access
        http_client = httpx.AsyncClient(
            auth=auth,
            base_url=_base_url,
            verify=self._tls_check_hostname,
            timeout=TIMEOUT,
            event_hooks={"response": [_raise_if_error]},
        )
        try:
            response = await http_client.get("/jdev/cfg/apiKey")
            value = LoxoneResponse(response.text).value
            _LOGGER.debug("Retrieved API key data")
            # The json returned by the miniserver is invalid. It contains " and '.
            # We need to normalise it
            value_dict: dict[str, Any] = json.loads(value.replace("'", '"'))
            self._https_status = value_dict.get("httpsStatus", 0)
            self._version = value_dict.get("version", "")
            self._snr = value_dict.get("snr", "")
            self._local = value_dict.get("local", True)
            if not self._local:
                url = str(response.url)
                http_client.base_url = httpx.URL(url.replace("/jdev/cfg/apiKey", ""))

            # The Loxone Structure File is described in a document available at
            # https://www.loxone.com/enen/kb/api/  It describes certain global
            # and external information, such as weather servers and infformation
            # about the miniserver itself, as well as information which does not
            # change frequently (eg categories, controls etc).

            # It is convenient to fetch it here, whilst we have an httpx client

            structure_file = await http_client.get("/data/LoxAPP3.json")
            _LOGGER.debug("Retrieved structure file")
            self._structure = dict(structure_file.json())

            # The msInfo record contains static information about the
            # miniserver. It is part of the structure file.
            # Create an msInfo attribute. Dynamically add sub-attributes
            # representing each member of the msInfo dict. eg,
            # self.msInfo.msName, self.msInfo.projectName, etc
            MsInfo = namedtuple("MsInfo", self._structure["msInfo"].keys())  # type: ignore
            self._msInfo = MsInfo._make(self._structure["msInfo"].values())

            # Get the miniserver's public key
            pk_data = await http_client.get("jdev/sys/getPublicKey")
            _LOGGER.debug("Retrieved public key data")
            pk = LoxoneResponse(pk_data.text).value
            # Loxone returns a certificate instead of a key, and the certificate is not
            # properly PEM encoded because it does not contain newlines before/after the
            # boundaries. We need to fix both problems. Proper PEM encoding requires 64
            # char line lengths throughout, but Python does not seem to insist on this.
            # If, for some reason, no certificate is returned, _public_key will be an
            # empty string.
            self._public_key = pk.replace(
                "-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n"
            ).replace("-----END CERTIFICATE-----", "\n-----END PUBLIC KEY-----")

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
            raise LoxoneHTTPStatusError(exc) from None
        else:
            return
        finally:
            # Async httpx client must always be closed
            await http_client.aclose()

    # Step 3: Open a websocket connection
    async def _open_websocket(self) -> None:
        scheme = "wss" if self._use_tls else "ws"
        url = f"{scheme}://{self._host}:{self._port}/ws/rfc6455"
        # pylint: disable=no-member
        try:
            if self._use_tls:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = self._tls_check_hostname
                self._ws = await wslib.client.connect(
                    url,
                    timeout=TIMEOUT,
                    ssl=ssl_context,
                    create_protocol=Websocket,
                    subprotocols=["remotecontrol"],  # type: ignore
                )
            else:
                self._ws = await wslib.client.connect(
                    url,
                    timeout=TIMEOUT,
                    create_protocol=Websocket,
                    subprotocols=["remotecontrol"],  # type: ignore
                )
        except wslib.exceptions.WebSocketException as exc:
            _LOGGER.error("Unable to open websocket")
            raise LoxoneException("Unable to open websocket") from exc
        _LOGGER.debug(f"Opened websocket to {url}")

    # Step 4: Generate an AES256-CBC key
    # Step 5: Generate a random AES iv (16 byte)
    # Step 6: RSA Encrypt the AES key+iv with the public key
    # Step 7: Pass the encrypted session-key to the miniserver
    async def _generate_and_pass_key(self) -> None:
        # Generate an AES256-CBC key.
        self._aes_key = get_random_bytes(32)
        # Generate random 16 byte AES initialisation vector (iv)
        self._iv = get_random_bytes(16)
        # RSA Encrypt the AES key+iv with the public key
        try:
            # RSA PKCS1 has been broken for a long time. Loxone uses it anyway
            rsa_cipher = PKCS1_v1_5.new(RSA.importKey(self._public_key))
            session_key = rsa_cipher.encrypt(
                f"{self._aes_key.hex()}:{self._iv.hex()}".encode()
            )
            encrypted_session_key = b64encode(session_key).decode()
        except ValueError as exc:
            _LOGGER.error(f"Error creating RSA cipher: {exc}")
            raise LoxoneException(exc) from exc
        _LOGGER.debug("Succesfully generated session key")
        # Pass the encrypted session key to the miniserver
        message = await self._send_text_command(
            f"jdev/sys/keyexchange/{encrypted_session_key}"
        )
        if message.message_type != MessageType.TEXT:
            raise LoxoneException("Error in getting a session key response")

        if message.code != 200:
            _LOGGER.error(
                f"Error in getting a session key response. Code {message.code}"
            )
            raise LoxoneException(
                f"Error in getting a session key response. Code {message.code}"
            )
        _LOGGER.debug("Succesfully exchanged encrypted session key")

    # Step 8. Generate a random salt
    def _generate_salt(self) -> None:
        _LOGGER.debug("Generating a new salt")
        self._salt = get_random_bytes(1).hex()
        self._salt_has_expired = False

    # Step 9. Autheticate with the token (if it exists), or acquire a token
    async def _authenticate_with_token(self) -> None:
        # A Loxone token can be fairly long lived (eg 4 weeks). So we could save
        # it to a file, and retrieve it on the next connection (if still valid).
        # But this requires filenames, loading from files etc. It is easier just
        # to ask for a new token on each connection. There might be a problem if
        # the miniserver keeps all the old, unexpired tokens, and then runs out
        # of space, but so far, so good!

        if self._token is None:
            # Once a new token is acquired, there is no need to authenticate separately
            await self._acquire_token()
        else:
            # Authenticate using the existing token
            token_hash = await self._hash_token()
            auth_command = f"authwithtoken/{token_hash}/{self._user}"
            message = await self._send_text_command(auth_command, encrypted=True)
            if (
                message.message_type is MessageType.TEXT
                and message.code == 200
                and "validUntil" in message.value_as_dict
            ):
                self._token.valid_until = message.value_as_dict["validUntil"]
            raise LoxoneException(f"Authentication error: {message}")
