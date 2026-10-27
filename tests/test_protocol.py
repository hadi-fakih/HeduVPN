import struct

import pytest

from heduvpn import crypto, protocol


def test_address_roundtrip():
    for host, port in (("93.184.216.34", 443), ("2001:db8::1", 8443), ("vpn.example.com", 53)):
        encoded = protocol.encode_address(host, port)
        decoded_host, decoded_port, consumed = protocol.decode_address(encoded)
        assert decoded_port == port
        assert consumed == len(encoded)
        if host[0].isdigit() and ":" not in host:
            assert decoded_host == host
        elif ":" in host:
            assert decoded_host == "2001:db8::1"
        else:
            assert decoded_host == host


def test_address_rejects_garbage():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_address(b"")
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_address(b"\x09abc")
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_address(b"\x03\x08short")


def test_address_rejects_long_hostname():
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_address("a" * 300, 80)


@pytest.mark.parametrize("padding", list(protocol.PAD_MODES))
def test_frame_codec_roundtrip(padding):
    psk = crypto.generate_psk()
    c2s, s2c = crypto.derive_session_keys(psk, b"a" * 16, b"b" * 16)
    sender = protocol.FrameCodec(c2s, s2c, padding=padding)
    receiver = protocol.FrameCodec(s2c, c2s, padding=padding)
    for body in (b"", b"x", b"hello world" * 100):
        wire = sender.encode(protocol.F_DATA, body, 7)
        head, ct = wire[:4], wire[4:]
        frame = receiver.decode(head, ct)
        assert frame.type == protocol.F_DATA
        assert frame.stream == 7
        assert frame.payload == body
        if padding == protocol.PAD_NONE:
            assert frame.pad == 0


def test_frame_rejects_tampering_and_replay_order():
    psk = crypto.generate_psk()
    c2s, s2c = crypto.derive_session_keys(psk, b"a" * 16, b"b" * 16)
    sender = protocol.FrameCodec(c2s, s2c, padding="none")
    receiver = protocol.FrameCodec(s2c, c2s, padding="none")
    wire = sender.encode(protocol.F_DATA, b"secret")
    tampered = bytearray(wire)
    tampered[-1] ^= 0xFF
    with pytest.raises(protocol.ProtocolError):
        receiver.decode(bytes(tampered[:4]), bytes(tampered[4:]))
    frame = receiver.decode(wire[:4], wire[4:])
    assert frame.payload == b"secret"
    # re-sending the same ciphertext fails because the receive counter moved
    with pytest.raises(protocol.ProtocolError):
        receiver.decode(wire[:4], wire[4:])


def test_frame_limits():
    psk = crypto.generate_psk()
    c2s, s2c = crypto.derive_session_keys(psk, b"a" * 16, b"b" * 16)
    codec = protocol.FrameCodec(c2s, s2c)
    with pytest.raises(protocol.ProtocolError):
        codec.encode(protocol.F_DATA, b"x" * (protocol.MAX_PAYLOAD + 1))
    with pytest.raises(protocol.ProtocolError):
        codec.decode(struct.pack(">I", 4), b"nope")


def test_padding_cells_aligns_records():
    psk = crypto.generate_psk()
    c2s, s2c = crypto.derive_session_keys(psk, b"a" * 16, b"b" * 16)
    codec = protocol.FrameCodec(c2s, s2c, padding="cells")
    for n in (1, 100, 200, 255, 256, 1000):
        size = len(codec.encode(protocol.F_DATA, b"x" * n))
        cell = 256
        target = ((n + 7 + cell - 1) // cell) * cell
        # 4-byte length, 16-byte tag and up to 24 bytes of extra noise
        assert target + 20 <= size <= target + 44, (n, size, target)


def test_handshake_message_helpers():
    async def scenario():
        stream = protocol.MemoryStream()
        psk = crypto.generate_psk()
        wire = protocol.build_hello(psk)
        stream.feed(wire)
        got = await protocol.read_handshake_message(stream, timeout=2)
        assert got == wire
        hello = protocol.parse_hello(psk, got)
        assert hello.client_nonce

    import asyncio

    asyncio.run(scenario())


def test_handshake_message_timeout():
    async def scenario():
        stream = protocol.MemoryStream()
        with pytest.raises(protocol.ProtocolError):
            await protocol.read_handshake_message(stream, timeout=0.05)

    import asyncio

    asyncio.run(scenario())


def test_handshake_message_rejects_oversized_length():
    async def scenario():
        stream = protocol.MemoryStream()
        stream.feed(struct.pack(">I", 99999) + b"x" * 100)
        with pytest.raises(protocol.ProtocolError):
            await protocol.read_handshake_message(stream, timeout=1)

    import asyncio

    asyncio.run(scenario())
