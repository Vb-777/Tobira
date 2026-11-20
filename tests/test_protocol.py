from __future__ import annotations

import asyncio

import pytest

from tobira.protocol import (
    MAX_FRAME_SIZE,
    Frame,
    FrameType,
    Msg,
    ProtocolError,
    control,
    data,
    read_frame,
)


def _reader(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


async def test_control_frame_round_trip() -> None:
    frame = control(Msg.OPEN, stream_id=7, app="payroll")
    decoded = await read_frame(_reader(frame.encode()))
    assert decoded.type is FrameType.CONTROL
    assert decoded.stream_id == 7
    assert decoded.json == {"msg": "open", "app": "payroll"}


async def test_data_frame_round_trip() -> None:
    frame = data(3, b"\x00\xffbinary")
    decoded = await read_frame(_reader(frame.encode()))
    assert decoded.type is FrameType.DATA
    assert decoded.payload == b"\x00\xffbinary"


async def test_several_frames_in_one_buffer() -> None:
    buffer = control(Msg.PING).encode() + data(1, b"abc").encode()
    reader = _reader(buffer)
    first = await read_frame(reader)
    second = await read_frame(reader)
    assert first.json["msg"] == "ping"
    assert second.payload == b"abc"


def test_oversized_frame_is_refused() -> None:
    with pytest.raises(ProtocolError):
        Frame(FrameType.DATA, 1, b"x" * (MAX_FRAME_SIZE + 1)).encode()


async def test_unknown_frame_type_is_refused() -> None:
    import struct

    bogus = struct.pack(">BII", 99, 0, 0)
    with pytest.raises(ProtocolError):
        await read_frame(_reader(bogus))


async def test_announced_oversize_is_refused_before_allocating() -> None:
    import struct

    header = struct.pack(">BII", int(FrameType.DATA), 1, MAX_FRAME_SIZE + 10)
    with pytest.raises(ProtocolError):
        await read_frame(_reader(header))


def test_json_accessor_rejects_non_control() -> None:
    with pytest.raises(ProtocolError):
        _ = data(1, b"{}").json
