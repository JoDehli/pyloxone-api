"""Classes for handling messages from a miniserver"""
from __future__ import annotations

import json
import math
import struct
import uuid
from enum import IntEnum
from typing import Any

from pyloxone_api.exceptions import LoxoneException


class LLResponse:
    """A class for parsing LL Responses from the miniserver

    An LL Response is a json object often returned by a miniserver in response
    to a command. It begins "{"LL": {..." and has a control, code and value
    keys. This class provides easy access to code (as an integer), value and
    control attributes (as strings), which should be present in every case. If
    value has sub-values, it will be returned as a dict instead. Raises
    ValueError if the response cannot be parsed.

    """

    def __init__(self, response: str | bytes) -> None:
        try:
            parsed = json.loads(response)
            # Sometimes, Loxone uses "Code", and sometimes "code"
            self.code: int = int(
                parsed.get("LL", {}).get("code", "")
                or parsed.get("LL", {}).get("Code", "")
            )
            self.value: dict[str, str] | str = parsed["LL"]["value"]
            self.control: str = parsed["LL"]["control"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(exc)


class MessageType(IntEnum):
    """The different types of message which the miniserver might send"""

    TEXT = 0
    BINARY = 1
    VALUE_STATES = 2
    TEXT_STATES = 3
    DAYTIMER_STATES = 4
    OUT_OF_SERVICE = 5
    KEEPALIVE = 6
    WEATHER_STATES = 7
    UNKNOWN = -1


class MessageHeader:
    def __init__(self, header: bytes) -> None:
        # From the Loxone API docs, the header is as follows
        # typedef struct {
        #   BYTE cBinType;     // fix 0x03
        #   BYTE cIdentifier;  // 8-Bit Unsigned Integer (little endian)
        #   BYTE cInfo;        // Info
        #   BYTE cReserved;    // reserved
        #   UINT nLen;         // 32-Bit Unsigned Integer (little endian)
        # } PACKED WsBinHdr;
        self.header = header
        if not header[0] == 3:
            raise LoxoneException(r"Invalid header received: first byte is not \0x03")
        try:
            unpacked_data = struct.unpack("<cBccI", header)
        except (struct.error, TypeError) as exc:
            raise LoxoneException(f"Invalid header received: {exc}")
        self.message_type: MessageType = MessageType(unpacked_data[1])
        # First bit indicates that length is only estimated
        self.estimated: bool = ord(unpacked_data[2]) >> 7 == 1
        self.payload_length: int = int(unpacked_data[4])


class BaseMessage:
    """The base class for all messages from the miniserver"""

    message_type = MessageType.UNKNOWN

    def __init__(self, message: bytes) -> None:
        self.message: bytes = message
        # For the base class, the dict is the message
        self._dict = message

    def as_dict(self) -> Any:
        """Return the contents of the message as a dict"""
        return self._dict


class TextMessage(BaseMessage):
    message_type = MessageType.TEXT

    def __init__(self, message: bytes) -> None:
        super().__init__(message)
        ll_message = LLResponse(message)
        self.code = ll_message.code
        self.control = ll_message.control
        self.value = ll_message.value


class BinaryFile(BaseMessage):
    message_type = MessageType.BINARY

    # The message is a binary file. There is nothing parse
    def as_dict(self):
        return {}


class ValueStatesTable(BaseMessage):
    message_type = MessageType.VALUE_STATES

    # A value state is as follows:
    # typedef struct {
    #     PUUID uuid;   // 128-Bit uuid
    #     double dVal;  // 64-Bit Float (little endian) value
    # } PACKED EvData;

    def as_dict(self):
        event_dict = {}
        length = len(self.message)
        num = length / 24
        start = 0
        end = 24
        for _ in range(int(num)):
            packet = self.message[start:end]
            event_uuid = uuid.UUID(bytes_le=packet[0:16])
            fields = event_uuid.urn.replace("urn:uuid:", "").split("-")
            uuidstr = f"{fields[0]}-{fields[1]}-{fields[2]}-{fields[3]}{fields[4]}"
            value = struct.unpack("d", packet[16:24])[0]
            event_dict[uuidstr] = value
            start += 24
            end += 24
        return event_dict


class TextStatesTable(BaseMessage):
    message_type = MessageType.TEXT_STATES

    # A text event state is as follows:
    # typedef struct {                 // starts at multiple of 4
    #     PUUID uuid;                  // 128-Bit uuid
    #     PUUID uuidIcon;              // 128-Bit uuid of icon
    #     unsigned long textLength;    // 32-Bit Unsigned Integer (little endian)
    #     // text follows here
    #     } PACKED EvDataText;
    def as_dict(self):
        event_dict = {}
        start = 0

        def get_text(message, start, offset):
            first = start
            second = start + offset
            event_uuid = uuid.UUID(bytes_le=self.message[first:second])
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

            icon_uuid = uuid.UUID(bytes_le=self.message[first:second])
            icon_uuid_fields = icon_uuid.urn.replace("urn:uuid:", "").split("-")

            first = second
            second += 4

            text_length = struct.unpack("<I", message[first:second])[0]

            first = second
            second = first + text_length
            message_str = struct.unpack(f"{text_length}s", message[first:second])[0]
            start += (math.floor((4 + text_length + 16 + 16 - 1) / 4) + 1) * 4
            event_dict[uuidstr] = message_str.decode("utf-8")
            return start

        while start < len(self.message):
            start = get_text(self.message, start, 16)
        return event_dict


class DaytimerStatesTable(BaseMessage):
    message_type = MessageType.DAYTIMER_STATES

    # We dont currently handle this.
    def as_dict(self):
        return {}


class OutOfServiceIndicator(BaseMessage):
    message_type = MessageType.OUT_OF_SERVICE

    # There can be no such message. If an out-of-service header is sent, the
    # miniserver will close the connection before sending a message.
    pass


class Keepalive(BaseMessage):
    message_type = MessageType.KEEPALIVE

    # Nothing to do. The dict is the message (which is b'keepalive')
    def as_dict(self):
        return {"keep_alive": "received"}


class WeatherStatesTable(BaseMessage):
    message_type = MessageType.WEATHER_STATES

    def as_dict(self):
        return {}


def parse_header(header: bytes) -> MessageHeader:
    return MessageHeader(header)


def parse_message(message: bytes, message_type: int) -> BaseMessage:
    """Return an instance of the appropriate BaseMessage subclass"""
    for klass in BaseMessage.__subclasses__():
        if klass.message_type == message_type:
            return klass(message)
    raise LoxoneException(f"Unknown message type {message_type}")
