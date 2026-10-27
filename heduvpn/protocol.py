"""HeduVPN wire protocol v1.

Two layers live here:

1. A tiny authenticated **handshake** that proves knowledge of the PSK and
   establishes fresh per-connection session keys.  It travels inside TLS,
   but is independent of it.
2. A **record layer** of length-prefixed, padded, AEAD-sealed frames that
   carries stream data.

Wire format (all integers big-endian)::

    HELLO   := u32 total_len | 12-byte nonce | AEAD(handshake_key, nonce, hello, aad="")
    hello   := u8 version | u8 flags | 16-byte client_nonce | u64 timestamp | u16 pad_len | pad
    ACK     := u32 total_len | 12-byte nonce | AEAD(handshake_key, nonce, ack, aad=client_nonce)
    ack     := u8 version | u8 flags | 16-byte server_nonce | u64 timestamp | u16 pad_len | pad
    FRAME   := u32 ct_len | AEAD(session_key, counter, frame, aad=u32 ct_len)
    frame   := u8 type | u32 stream_id | u16 payload_len | payload | pad

Padding lives *inside* the ciphertext, so an observer cannot tell payload
bytes from cover bytes, nor recover the real payload length.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from . import crypto

VERSION = 1

# Handshake frames
F_HELLO = 0x01
F_HELLO_ACK = 0x02

# Data-plane frames
F_OPEN = 0x10
F_OPEN_OK = 0x11
F_DATA = 0x12
F_CLOSE = 0x13
F_PING = 0x14
F_PONG = 0x15
F_ERROR = 0x16
F_PAD = 0x17

FRAME_NAMES = {
    F_HELLO: "hello",
    F_HELLO_ACK: "hello_ack",
    F_OPEN: "open",
    F_OPEN_OK: "open_ok",
    F_DATA: "data",
    F_CLOSE: "close",
    F_PING: "ping",
    F_PONG: "pong",
    F_ERROR: "error",
    F_PAD: "pad",
}

# Error codes carried by F_ERROR
ERR_POLICY = 1
ERR_CONNECT = 2
ERR_PROTOCOL = 3
ERR_INTERNAL = 4

ERR_TEXT = {
    ERR_POLICY: "destination blocked by relay policy",
    ERR_CONNECT: "relay could not reach destination",
    ERR_PROTOCOL: "protocol error",
    ERR_INTERNAL: "internal relay error",
}

MAX_PAYLOAD = 16 * 1024
MAX_FRAME = 128 * 1024
MAX_PAD = 512
HANDSHAKE_SKEW = 120  # seconds

PAD_NONE = "none"
PAD_RANDOM = "random"
PAD_CELLS = "cells"
PAD_MODES = (PAD_NONE, PAD_RANDOM, PAD_CELLS)


class ProtocolError(Exception):
    """Peer violated the protocol or authentication failed."""


class PolicyError(ProtocolError):
    """Destination rejected by relay policy."""

    code = ERR_POLICY


class ConnectError(ProtocolError):
    """Relay failed to open the destination."""

    code = ERR_CONNECT


class StreamClosed(ProtocolError):
    """Peer closed the stream."""


class Stream(Protocol):
    """Minimal byte-stream interface shared by TLS and WebSocket transports."""

    async def read_exact(self, n: int) -> bytes: ...
    async def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...
    @property
    def peer(self) -> str: ...


class MemoryStream:
    """In-memory duplex stream used by tests and the dashboard's lab tools."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._closed = False
        self._waiter: asyncio.Future | None = None
        self.written = bytearray()

    def feed(self, data: bytes) -> None:
        self._buf.extend(data)
        if self._waiter and not self._waiter.done():
            self._waiter.set_result(None)

    async def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            if self._closed and not self._buf:
                raise StreamClosed("stream closed")
            self._waiter = asyncio.get_running_loop().create_future()
            try:
                await self._waiter
            finally:
                self._waiter = None
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def write(self, data: bytes) -> None:
        if self._closed:
            raise StreamClosed("stream closed")
        self.written.extend(data)

    def close(self) -> None:
        self._closed = True
        if self._waiter and not self._waiter.done():
            self._waiter.set_result(None)

    @property
    def peer(self) -> str:
        return "memory"


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


@dataclass
class Hello:
    version: int
    flags: int
    client_nonce: bytes
    timestamp: int
    wire: bytes
    pad_len: int = 0


@dataclass
class Ack:
    version: int
    flags: int
    server_nonce: bytes
    timestamp: int


def _handshake_envelope(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = secrets.token_bytes(crypto.NONCE_BYTES)
    ct = crypto.aead_encrypt(key, nonce, plaintext, aad)
    return struct.pack(">I", len(nonce) + len(ct)) + nonce + ct


def _open_envelope(key: bytes, wire: bytes, aad: bytes = b"") -> bytes:
    if len(wire) < 4 + crypto.NONCE_BYTES + crypto.AEAD_TAG:
        raise ProtocolError("handshake too short")
    (total,) = struct.unpack(">I", wire[:4])
    if total != len(wire) - 4 or total > 4096:
        raise ProtocolError("bad handshake length")
    nonce = wire[4 : 4 + crypto.NONCE_BYTES]
    ct = wire[4 + crypto.NONCE_BYTES :]
    try:
        return crypto.aead_decrypt(key, nonce, ct, aad)
    except crypto.CryptoError as exc:
        raise ProtocolError("handshake authentication failed") from exc


def build_hello(
    psk: bytes,
    client_nonce: bytes | None = None,
    flags: int = 0,
    pad_max: int = 48,
    now: float | None = None,
) -> bytes:
    """Build the first message a client sends on a fresh connection."""
    client_nonce = client_nonce or secrets.token_bytes(16)
    ts = int(now if now is not None else time.time())
    pad = os.urandom(random.randint(0, max(0, pad_max))) if pad_max else b""
    plaintext = (
        struct.pack(">BB16sQH", VERSION, flags, client_nonce, ts, len(pad)) + pad
    )
    return _handshake_envelope(crypto.handshake_key(psk), plaintext)


def parse_hello(psk: bytes, wire: bytes, skew: int = HANDSHAKE_SKEW, now: float | None = None) -> Hello:
    plaintext = _open_envelope(crypto.handshake_key(psk), wire)
    if len(plaintext) < 1 + 1 + 16 + 8 + 2:
        raise ProtocolError("short hello")
    version, flags, client_nonce, ts, pad_len = struct.unpack(">BB16sQH", plaintext[:28])
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if pad_len > len(plaintext) - 28:
        raise ProtocolError("bad padding")
    current = int(now if now is not None else time.time())
    if abs(current - ts) > skew:
        raise ProtocolError("stale handshake")
    return Hello(version, flags, client_nonce, ts, wire, pad_len)


def build_ack(psk: bytes, hello: Hello, pad_max: int = 48, now: float | None = None) -> tuple[bytes, bytes]:
    """Return ``(wire, server_nonce)``."""
    server_nonce = secrets.token_bytes(16)
    ts = int(now if now is not None else time.time())
    pad = os.urandom(random.randint(0, max(0, pad_max))) if pad_max else b""
    plaintext = struct.pack(">BB16sQH", VERSION, 0, server_nonce, ts, len(pad)) + pad
    wire = _handshake_envelope(
        crypto.handshake_key(psk), plaintext, aad=hello.client_nonce
    )
    return wire, server_nonce


def parse_ack(psk: bytes, wire: bytes, hello: Hello, skew: int = HANDSHAKE_SKEW) -> Ack:
    plaintext = _open_envelope(crypto.handshake_key(psk), wire, aad=hello.client_nonce)
    if len(plaintext) < 28:
        raise ProtocolError("short ack")
    version, flags, server_nonce, ts, pad_len = struct.unpack(">BB16sQH", plaintext[:28])
    if version != VERSION:
        raise ProtocolError("unsupported version")
    if pad_len > len(plaintext) - 28:
        raise ProtocolError("bad padding")
    if abs(int(time.time()) - ts) > skew:
        raise ProtocolError("stale ack")
    return Ack(version, flags, server_nonce, ts)


async def read_handshake_message(stream: Stream, timeout: float = 8.0) -> bytes:
    async def _read() -> bytes:
        head = await stream.read_exact(4)
        (total,) = struct.unpack(">I", head)
        if total < crypto.NONCE_BYTES + crypto.AEAD_TAG or total > 4096:
            raise ProtocolError("invalid handshake size")
        return head + await stream.read_exact(total)

    try:
        return await asyncio.wait_for(_read(), timeout)
    except asyncio.TimeoutError as exc:
        raise ProtocolError("handshake timeout") from exc


# ---------------------------------------------------------------------------
# Address encoding (SOCKS5 compatible)
# ---------------------------------------------------------------------------

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4


def encode_address(host: str, port: int) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            raw = host.encode("idna")
        except UnicodeError as exc:
            raise ProtocolError("invalid hostname") from exc
        if len(raw) > 255:
            raise ProtocolError("hostname too long")
        return struct.pack(">BB", ATYP_DOMAIN, len(raw)) + raw + struct.pack(">H", port)
    if ip.version == 4:
        return struct.pack(">B", ATYP_IPV4) + ip.packed + struct.pack(">H", port)
    return struct.pack(">B", ATYP_IPV6) + ip.packed + struct.pack(">H", port)


def decode_address(data: bytes) -> tuple[str, int, int]:
    """Return ``(host, port, bytes_consumed)``."""
    if not data:
        raise ProtocolError("empty address")
    atyp = data[0]
    if atyp == ATYP_IPV4:
        if len(data) < 7:
            raise ProtocolError("short ipv4 address")
        return str(ipaddress.IPv4Address(data[1:5])), struct.unpack(">H", data[5:7])[0], 7
    if atyp == ATYP_IPV6:
        if len(data) < 19:
            raise ProtocolError("short ipv6 address")
        return str(ipaddress.IPv6Address(data[1:17])), struct.unpack(">H", data[17:19])[0], 19
    if atyp == ATYP_DOMAIN:
        if len(data) < 2:
            raise ProtocolError("short domain")
        length = data[1]
        if len(data) < 2 + length + 2:
            raise ProtocolError("short domain")
        host = data[2 : 2 + length].decode("idna")
        port = struct.unpack(">H", data[2 + length : 4 + length])[0]
        return host, port, 4 + length
    raise ProtocolError(f"unknown address type {atyp}")


# ---------------------------------------------------------------------------
# Record layer
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    type: int
    payload: bytes
    stream: int = 1
    pad: int = 0

    @property
    def name(self) -> str:
        return FRAME_NAMES.get(self.type, f"0x{self.type:02x}")


def make_padding(mode: str, rng: random.Random, base_len: int) -> int:
    if mode == PAD_NONE:
        return 0
    if mode == PAD_RANDOM:
        return rng.randint(0, 96)
    if mode == PAD_CELLS:
        # Round the record body up to a cell boundary plus a little noise, so
        # sizes cluster like TLS records instead of tracking plaintext length.
        cell = 256
        target = ((base_len + 5 + 2 + cell - 1) // cell) * cell
        return max(0, target - (base_len + 7)) + rng.randint(0, 24)
    raise ValueError(f"unknown padding mode {mode}")


class FrameCodec:
    """Seals and opens records for one direction-pair of a connection."""

    def __init__(
        self,
        send_key: bytes,
        recv_key: bytes,
        padding: str = PAD_RANDOM,
        jitter_ms: int = 0,
        on_send: Callable[[Frame, int, int], None] | None = None,
        on_recv: Callable[[Frame, int, int], None] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if padding not in PAD_MODES:
            raise ValueError(f"unknown padding mode {padding}")
        self.send_key = send_key
        self.recv_key = recv_key
        self.padding = padding
        self.jitter_ms = max(0, jitter_ms)
        self.send_counter = 0
        self.recv_counter = 0
        self._on_send = on_send
        self._on_recv = on_recv
        self._rng = rng or random.Random()
        # Records must reach the wire in counter order, or the peer's nonce
        # sequence breaks and every following record fails authentication.
        # Several tasks (data streams, cover traffic, keepalive) share a codec,
        # so encoding and writing happen under one lock.
        self._send_lock = asyncio.Lock()

    def encode(self, ftype: int, payload: bytes = b"", stream_id: int = 1) -> bytes:
        if len(payload) > MAX_PAYLOAD:
            raise ProtocolError("payload too large")
        pad_len = make_padding(self.padding, self._rng, len(payload))
        plaintext = (
            struct.pack(">BIH", ftype, stream_id, len(payload)) + payload + os.urandom(pad_len)
        )
        nonce = crypto.nonce_from_counter(self.send_counter)
        ct_len = len(plaintext) + crypto.AEAD_TAG
        aad = struct.pack(">I", ct_len)
        ct = crypto.aead_encrypt(self.send_key, nonce, plaintext, aad)
        self.send_counter += 1
        if self._on_send:
            self._on_send(Frame(ftype, payload, stream_id, pad_len), len(ct) + 4, len(payload))
        return aad + ct

    def decode(self, head: bytes, ct: bytes) -> Frame:
        nonce = crypto.nonce_from_counter(self.recv_counter)
        try:
            plaintext = crypto.aead_decrypt(self.recv_key, nonce, ct, head)
        except crypto.CryptoError as exc:
            raise ProtocolError("record authentication failed") from exc
        self.recv_counter += 1
        if len(plaintext) < 7:
            raise ProtocolError("short record")
        ftype, stream_id, payload_len = struct.unpack(">BIH", plaintext[:7])
        if payload_len > len(plaintext) - 7:
            raise ProtocolError("bad payload length")
        frame = Frame(ftype, plaintext[7 : 7 + payload_len], stream_id, len(plaintext) - 7 - payload_len)
        if self._on_recv:
            self._on_recv(frame, len(ct) + 4, len(frame.payload))
        return frame

    async def send(self, stream: Stream, ftype: int, payload: bytes = b"", stream_id: int = 1) -> int:
        async with self._send_lock:
            # Jitter before encoding, so the counter sequence matches the order
            # in which records are actually written.
            if self.jitter_ms and len(payload) < 2048 and self._rng.random() < 0.35:
                await asyncio.sleep(self._rng.uniform(0, self.jitter_ms) / 1000.0)
            wire = self.encode(ftype, payload, stream_id)
            await stream.write(wire)
            return len(wire)

    async def recv(self, stream: Stream) -> Frame:
        head = await stream.read_exact(4)
        (ct_len,) = struct.unpack(">I", head)
        if ct_len < crypto.AEAD_TAG + 7 or ct_len > MAX_FRAME:
            raise ProtocolError("invalid record size")
        ct = await stream.read_exact(ct_len)
        return self.decode(head, ct)


# ---------------------------------------------------------------------------
# Small helpers used by relay + client
# ---------------------------------------------------------------------------
