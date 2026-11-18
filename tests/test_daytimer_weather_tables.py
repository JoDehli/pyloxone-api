"""Daytimer and weather event tables (spec "Communicating with the Miniserver",
Event-Tables: EvDataDaytimer / EvDataWeather)."""

from __future__ import annotations

import asyncio
import struct
import uuid
from types import SimpleNamespace

import pytest

from pyloxone_api.connection import LoxoneConnection
from pyloxone_api.exceptions import LoxoneConnectionClosedOk
from pyloxone_api.message import (
    DaytimerStatesTable,
    MessageType,
    WeatherStatesTable,
)

UUID_A = uuid.UUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
UUID_B = uuid.UUID("10203040-5060-7080-90a0-b0c0d0e0f001")


def _key(u: uuid.UUID) -> str:
    """Loxone compact key form, as used for value and text states."""
    text = str(u)
    return text[:23] + text[24:]


def _daytimer(u: uuid.UUID, default: float, entries: list[tuple]) -> bytes:
    out = u.bytes_le + struct.pack("<di", default, len(entries))
    for mode, frm, to, need_activate, value in entries:
        out += struct.pack("<iiiid", mode, frm, to, need_activate, value)
    return out


def _weather(u: uuid.UUID, last_update: int, entries: list[tuple]) -> bytes:
    out = u.bytes_le + struct.pack("<Ii", last_update, len(entries))
    for e in entries:
        out += struct.pack("<iiiiidddddd", *e)
    return out


class TestDaytimerTable:
    def test_two_daytimers_with_entries(self):
        body = _daytimer(
            UUID_A, 21.5, [(0, 360, 480, 0, 22.0), (3, 1020, 1320, 1, 23.5)]
        ) + _daytimer(UUID_B, 0.0, [])

        result = DaytimerStatesTable(body).as_dict()

        assert result == {
            _key(UUID_A): {
                "default_value": 21.5,
                "entries": [
                    {"mode": 0, "from": 360, "to": 480, "need_activate": False, "value": 22.0},
                    {"mode": 3, "from": 1020, "to": 1320, "need_activate": True, "value": 23.5},
                ],
            },
            _key(UUID_B): {"default_value": 0.0, "entries": []},
        }

    def test_empty_body(self):
        assert DaytimerStatesTable(b"").as_dict() == {}

    def test_truncated_entry_keeps_complete_daytimers(self):
        good = _daytimer(UUID_A, 1.0, [(0, 0, 60, 0, 1.0)])
        broken = _daytimer(UUID_B, 2.0, [(0, 0, 60, 0, 1.0)])[:-5]

        result = DaytimerStatesTable(good + broken).as_dict()

        assert list(result) == [_key(UUID_A)]


class TestWeatherTable:
    ENTRY = (1000, 3, 180, 450, 65, 12.5, 11.0, 6.2, 0.4, 3.3, 1013.2)

    def test_weather_entries(self):
        body = _weather(UUID_A, 559_000_000, [self.ENTRY])

        result = WeatherStatesTable(body).as_dict()

        assert result == {
            _key(UUID_A): {
                "last_update": 559_000_000,
                "entries": [
                    {
                        "timestamp": 1000,
                        "weather_type": 3,
                        "wind_direction": 180,
                        "solar_radiation": 450,
                        "relative_humidity": 65,
                        "temperature": 12.5,
                        "perceived_temperature": 11.0,
                        "dew_point": 6.2,
                        "precipitation": 0.4,
                        "wind_speed": 3.3,
                        "barometric_pressure": 1013.2,
                    }
                ],
            }
        }

    def test_truncated_table_returns_complete_part(self):
        good = _weather(UUID_A, 1, [self.ENTRY])
        broken = _weather(UUID_B, 2, [self.ENTRY])[:30]

        result = WeatherStatesTable(good + broken).as_dict()

        assert list(result) == [_key(UUID_A)]


def _header(message_type: int, payload_length: int) -> bytes:
    return struct.pack("<cBccI", b"\x03", message_type, b"\x00", b"\x00", payload_length)


class _FakeConnection:
    def __init__(self, frames):
        self._frames = list(frames)
        self.state = SimpleNamespace(CLOSED="CLOSED", OPEN="OPEN", name="OPEN")

    async def __aiter__(self):
        for frame in self._frames:
            yield frame

    async def send(self, *args, **kwargs):
        return None

    async def close(self, *args, **kwargs):
        return None


async def _listen(frames, **kwargs) -> list[dict]:
    fired: list[dict] = []

    async def callback(data: dict) -> None:
        fired.append(data)

    conn = LoxoneConnection("192.0.2.1", "user", "password", port=8080, **kwargs)
    with pytest.raises(LoxoneConnectionClosedOk):
        await conn._do_start_listening(callback, _FakeConnection(frames))
    await asyncio.sleep(0)
    return fired


def _table_frames() -> list[bytes]:
    daytimer = _daytimer(UUID_A, 1.0, [(0, 0, 60, 0, 1.0)])
    weather = _weather(UUID_B, 5, [TestWeatherTable.ENTRY])
    return [
        _header(MessageType.DAYTIMER_STATES, len(daytimer)),
        daytimer,
        _header(MessageType.WEATHER_STATES, len(weather)),
        weather,
    ]


@pytest.mark.asyncio
async def test_tables_not_forwarded_by_default():
    """Existing callbacks expect scalar values; they must not get dicts."""
    assert await _listen(_table_frames()) == []


@pytest.mark.asyncio
async def test_tables_forwarded_when_enabled():
    fired = await _listen(_table_frames(), forward_daytimer_weather=True)

    assert len(fired) == 2
    assert fired[0][_key(UUID_A)]["default_value"] == 1.0
    assert fired[1][_key(UUID_B)]["last_update"] == 5


def test_option_must_be_bool():
    with pytest.raises(ValueError):
        LoxoneConnection("192.0.2.1", "user", "password", forward_daytimer_weather="yes")
