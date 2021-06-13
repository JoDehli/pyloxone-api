"""A websocket implementation with useful methods.

This class will log messages sent and received, at the DEBUG level.
"""
from __future__ import annotations

import logging

from websockets.client import WebSocketClientProtocol

from pyloxone_api.exceptions import LoxoneException
from pyloxone_api.message import BaseMessage, MessageType, parse_header, parse_message

_LOGGER = logging.getLogger(__name__)


class Websocket(WebSocketClientProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def recv(self) -> str | bytes:
        result = await super().recv()
        _LOGGER.debug(f"Received: {result[:80]!r}")
        return result

    async def send(self, msg) -> None:
        result = await super().send(msg)
        _LOGGER.debug(f"Sent:{msg}")
        return result

    async def recv_message(self) -> BaseMessage:
        """Receive a header and message from the miniserver""

        Return an instance of the appropriate message.BaseMessage subclass
        """
        # The Loxone API docs say:
        #
        # > As mentioned in the chapter on how to setup a connection, messages sent by
        # > the Miniserver are always prequeled by a binary message that contains a
        # > MessageHeader. So at ﬁrst you’ll receive the binary Message-Header and then
        # > the payload follows in a separate message.
        #
        # But this is not quite right because the docs also say, for an out-of-service
        # indicator:
        #
        # > No message is going to follow this header, the Miniserver closes the
        # > connection afterwards, the client may try to reconnect.
        #
        # And:
        #
        # > An Estimated-Header is always followed by an exact Header to be able to read
        # > the data correctly!
        #
        # And:
        #
        # a keepalive header is sent by itself. No message body follows it. We
        # don't need to worry about that here, because keepalive messages are
        # handled in their own coroutine

        header_data = await self.recv()
        if not isinstance(header_data, bytes):
            raise LoxoneException(
                f"Expected a bytes header, but received {header_data}"
            )
        _LOGGER.debug(f"Parsing header {header_data[:80]!r}")
        header = parse_header(header_data)
        if header.message_type is MessageType.OUT_OF_SERVICE:
            raise LoxoneException("Miniserver is out of service")
        # get the message body
        message_data = await self.recv()

        _LOGGER.debug(f"Parsing message {message_data[:80]!r}")
        message = parse_message(message_data, header.message_type)
        return message
