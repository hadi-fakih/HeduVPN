"""Concurrent producers must not reorder records.

A single codec is shared by every stream, cover traffic and the keepalive.  If
two tasks encode in one order and write in another, the peer's counter-based
nonce sequence desynchronises and every subsequent record fails authentication.
"""

import asyncio
import struct

from heduvpn import protocol


def test_concurrent_sends_keep_counter_order():
    async def scenario():
        sender = protocol.FrameCodec(b"a" * 32, b"b" * 32, padding="random", jitter_ms=25)
        receiver = protocol.FrameCodec(b"b" * 32, b"a" * 32, padding="random")
        stream = protocol.MemoryStream()

        async def produce(i: int) -> None:
            await sender.send(stream, protocol.F_DATA, struct.pack(">I", i), stream_id=i + 1)

        await asyncio.gather(*(produce(i) for i in range(24)))
        incoming = protocol.MemoryStream()
        incoming.feed(bytes(stream.written))
        seen = []
        for _ in range(24):
            frame = await asyncio.wait_for(receiver.recv(incoming), 2)
            assert frame.type == protocol.F_DATA
            seen.append(struct.unpack(">I", frame.payload)[0])
        assert seen == list(range(24))

    asyncio.run(scenario())


def test_concurrent_sends_from_many_tasks():
    async def scenario():
        sender = protocol.FrameCodec(b"c" * 32, b"d" * 32, jitter_ms=10)
        receiver = protocol.FrameCodec(b"d" * 32, b"c" * 32)
        stream = protocol.MemoryStream()
        await asyncio.gather(*(sender.send(stream, protocol.F_PAD, b"x") for _ in range(32)))
        incoming = protocol.MemoryStream()
        incoming.feed(bytes(stream.written))
        frames = [await asyncio.wait_for(receiver.recv(incoming), 2) for _ in range(32)]
        assert all(frame.type == protocol.F_PAD for frame in frames)

    asyncio.run(scenario())
