import asyncio

from heduvpn import websocket
from heduvpn.transport import close_server



def _unmask(frame: bytes) -> tuple[int, bytes]:
    """Decode a masked client frame into (opcode, unmasked payload)."""
    opcode = frame[0] & 0x0F
    assert frame[1] & 0x80, "client frames must be masked"
    length = frame[1] & 0x7F
    offset = 2
    if length == 126:
        length = int.from_bytes(frame[offset:offset + 2], "big")
        offset += 2
    elif length == 127:
        length = int.from_bytes(frame[offset:offset + 8], "big")
        offset += 8
    key = frame[offset:offset + 4]
    offset += 4
    masked = frame[offset:offset + length]
    return opcode, websocket._apply_mask(masked, key)


def test_encode_frame_lengths_and_masking():
    for size in (0, 1, 125, 126, 65535, 65536):
        payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
        frame = websocket.encode_frame(websocket.OP_BINARY, payload, mask=True)
        assert frame[0] & 0x0F == websocket.OP_BINARY
        assert frame[1] & 0x80
        # Deterministic check: undoing the frame's own mask restores the
        # payload.  (Asserting "masked != plaintext" is subtly flaky: for a
        # 1-byte payload the random mask byte is 0x00 about 1 time in 256.)
        opcode, restored = _unmask(frame)
        assert opcode == websocket.OP_BINARY
        assert restored == payload
        assert len(frame) == len(payload) + (6 if size < 126 else 8 if size < 65536 else 14)
        # An unmasked (server) frame carries the payload verbatim.
        server_frame = websocket.encode_frame(websocket.OP_BINARY, payload)
        assert server_frame[1] & 0x80 == 0
        assert server_frame.endswith(payload) if payload else True
    assert websocket.accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_binary_roundtrip_over_sockets():
    async def scenario():
        got = {}

        async def handler(reader, writer):
            ws = await websocket.server_handshake(reader, writer)
            data = await ws.read_exact(5)
            got["data"] = data
            await ws.write(b"echo:" + data)
            ws.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        ws = await websocket.client_handshake(reader, writer, host="localhost", path="/ws")
        await ws.write(b"hello")
        echoed = await asyncio.wait_for(ws.read_exact(10), 5)
        assert echoed == b"echo:hello"
        assert got["data"] == b"hello"
        ws.close()
        await close_server(server)

    asyncio.run(scenario())


def test_text_frames_are_ignored():
    async def scenario():
        async def handler(reader, writer):
            ws = await websocket.server_handshake(reader, writer)
            data = await ws.read_exact(3)
            await ws.write(data)
            ws.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        ws = await websocket.client_handshake(reader, writer, host="localhost", path="/ws")
        writer.write(websocket.encode_frame(websocket.OP_TEXT, b"injected", mask=True))
        await writer.drain()
        await ws.write(b"abc")
        assert await asyncio.wait_for(ws.read_exact(3), 5) == b"abc"
        ws.close()
        await close_server(server)

    asyncio.run(scenario())


def test_ping_is_answered():
    async def scenario():
        async def handler(reader, writer):
            ws = await websocket.server_handshake(reader, writer)
            await ws.write(b"ready")
            try:
                await ws.read_exact(1)  # processes the ping while waiting for data
            except Exception:
                pass
            ws.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        ws = await websocket.client_handshake(reader, writer, host="localhost", path="/ws")
        assert await asyncio.wait_for(ws.read_exact(5), 5) == b"ready"
        writer.write(websocket.encode_frame(websocket.OP_PING, b"p", mask=True))
        await writer.drain()
        fin, opcode, payload = await asyncio.wait_for(ws._read_frame(), 5)
        assert opcode == websocket.OP_PONG and payload == b"p"
        ws.close()
        await close_server(server)

    asyncio.run(scenario())


def test_rejects_bad_upgrade():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        reader.feed_eof()
        from heduvpn.httpwire import read_request

        req = await read_request(reader)
        assert not websocket.is_websocket_request(req)

    asyncio.run(scenario())
