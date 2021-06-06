"""A websocket implementation with useful methods"""
import asyncio
from pyloxone_api.message import MessageType, parse_header, parse_message
from websockets.client import WebSocketClientProtocol


class Websocket(WebSocketClientProtocol):
    socket_lock = asyncio.Lock()

    async def recv(self):
        async with self.socket_lock:
            result = await super().recv()
        return result

    async def recv_message(self):
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
        # But this is not quite right. The docs also say, for an out-of-service
        # indicator:
        #
        # > No message is going to follow this header, the Miniserver closes the
        # > connection afterwards, the client may try to reconnect.
        #
        # And:
        #
        # > An Estimated-Header is always followed by an exact Header to be able to read
        # > the data correctly!

        async with self.socket_lock:
            header_data = await super().recv()
            header = parse_header(header_data)
            if header.message_type is MessageType.OUT_OF_SERVICE:
                return None
            # get the message body
            message_data = await super().recv()

        message = parse_message(message_data, header.message_type)
        return message.message
