"""A compact RFC 6455 WebSocket implementation (client + server).

The tunnel uses binary messages.  Wrapping tunnel records in WebSocket frames
makes traffic blend into the large population of legitimate WebSocket
applications (chat, collaboration tools, market data), and -- critically --
lets a relay sit behind any ordinary reverse proxy / CDN instead of needing
raw TCP or a VPN port.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import struct

from .httpwire import HttpError, build_request, read_response_headers_with_rest, read_request
from .protocol import ProtocolError, Stream, StreamClosed

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

MAX_MESSAGE = 1 << 20
MAX_FRAME = 1 << 18


def accept_key(key: str) -> str:
    digest = hashlib.sha1((key.strip() + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _apply_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    m = (mask * (n // 4 + 1))[:n]
    return bytes(a ^ b for a, b in zip(data, m))


def encode_frame(opcode: int, payload: bytes = b"", mask: bool = False, fin: bool = True) -> bytes:
    b0 = (0x80 if fin else 0) | (opcode & 0x0F)
    n = len(payload)
    if n < 126:
        header = struct.pack(">BB", b0, (0x80 if mask else 0) | n)
    elif n < (1 << 16):
        header = struct.pack(">BBH", b0, (0x80 if mask else 0) | 126, n)
    else:
        header = struct.pack(">BBQ", b0, (0x80 if mask else 0) | 127, n)
    if mask:
        key = os.urandom(4)
        return header + key + _apply_mask(payload, key)
    return header + payload


class WSStream(Stream):
    """Duplex stream that speaks binary WebSocket messages."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_client: bool,
        max_message: int = MAX_MESSAGE,
        initial: bytes = b"",
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.max_message = max_message
        self._buf = bytearray()
        self._raw = bytearray(initial)
        self._closed = False
        self._close_sent = False
        self._peer = "unknown"
        try:
            peer = writer.get_extra_info("peername")
            self._peer = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        except Exception:
            pass

    # -- Stream API --------------------------------------------------------
    async def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            await self._fill()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def write(self, data: bytes) -> None:
        if self._closed:
            raise StreamClosed("websocket closed")
        for i in range(0, len(data), MAX_FRAME):
            self.writer.write(
                encode_frame(OP_BINARY, data[i : i + MAX_FRAME], mask=self.is_client)
            )
        await self.writer.drain()

    def close(self) -> None:
        if self._close_sent:
            self._closed = True
            return
        self._close_sent = True
        self._closed = True
        try:
            self.writer.write(encode_frame(OP_CLOSE, b"\x03\xe8", mask=self.is_client))
            self.writer.close()
        except Exception:
            pass

    @property
    def peer(self) -> str:
        return self._peer

    # -- WebSocket internals ----------------------------------------------
    async def send_text(self, text: str) -> None:
        if self._closed:
            raise StreamClosed("websocket closed")
        self.writer.write(encode_frame(OP_TEXT, text.encode("utf-8"), mask=self.is_client))
        await self.writer.drain()

    async def _read_raw(self, n: int) -> bytes:
        while len(self._raw) < n:
            chunk = await self.reader.read(65536)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._raw), n)
            self._raw.extend(chunk)
        out = bytes(self._raw[:n])
        del self._raw[:n]
        return out

    async def _read_frame(self) -> tuple[bool, int, bytes]:
        head = await self._read_raw(2)
        b0, b1 = head[0], head[1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            (length,) = struct.unpack(">H", await self._read_raw(2))
        elif length == 127:
            (length,) = struct.unpack(">Q", await self._read_raw(8))
        if length > self.max_message:
            self.close()
            raise ProtocolError("websocket message too large")
        if opcode >= 0x8:
            if length > 125 or not fin:
                raise ProtocolError("invalid control frame")
        key = await self._read_raw(4) if masked else b""
        payload = await self._read_raw(length) if length else b""
        if masked:
            payload = _apply_mask(payload, key)
        return fin, opcode, payload

    async def _fill(self) -> None:
        """Read one complete binary message into the buffer, handling control frames."""
        fragments: list[bytes] = []
        total = 0
        in_text = False
        while True:
            try:
                fin, opcode, payload = await self._read_frame()
            except asyncio.IncompleteReadError as exc:
                self._closed = True
                raise StreamClosed("websocket connection lost") from exc

            if opcode == OP_PING:
                if not self._close_sent:
                    self.writer.write(encode_frame(OP_PONG, payload, mask=self.is_client))
                    await self.writer.drain()
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                if not self._close_sent:
                    self._close_sent = True
                    try:
                        self.writer.write(encode_frame(OP_CLOSE, payload[:2], mask=self.is_client))
                        await self.writer.drain()
                    except Exception:
                        pass
                self._closed = True
                raise StreamClosed("websocket closed by peer")
            if opcode not in (OP_BINARY, OP_TEXT, OP_CONT):
                raise ProtocolError(f"unsupported websocket opcode {opcode}")

            if opcode == OP_TEXT:
                # Text messages are never tunnel data.  Middleboxes sometimes
                # inject them; discard the whole (possibly fragmented) message.
                in_text = True
                fragments = []
                total = 0
                if fin:
                    in_text = False
                continue
            if opcode == OP_BINARY:
                in_text = False
                fragments = []
                total = 0
            if in_text:
                if fin:
                    in_text = False
                continue
            total += len(payload)
            if total > self.max_message:
                raise ProtocolError("websocket message too large")
            fragments.append(payload)
            if fin:
                self._buf.extend(b"".join(fragments))
                return


# ---------------------------------------------------------------------------
# Handshakes
# ---------------------------------------------------------------------------


def is_websocket_request(req) -> bool:
    upgrade = req.get("upgrade").lower()
    connection = req.get("connection").lower()
    return upgrade == "websocket" and "upgrade" in connection and bool(req.get("sec-websocket-key"))


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    path: str = "/ws",
    extra_headers: list[tuple[str, str]] | None = None,
    timeout: float = 15.0,
) -> WSStream:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    headers = [
        ("Host", host),
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Key", key),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Protocol", "binary"),
        ("User-Agent", "Mozilla/5.0"),
        ("Accept", "*/*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
    ]
    headers.extend(extra_headers or [])
    writer.write(build_request("GET", path, headers))
    await writer.drain()
    status, rheaders, rest = await read_response_headers_with_rest(reader, timeout=timeout)
    if status != 101:
        raise ProtocolError(f"websocket upgrade rejected with HTTP {status}")
    if rheaders.get("sec-websocket-accept", "") != accept_key(key):
        raise ProtocolError("websocket accept key mismatch")
    # The server may have started sending frames in the same TCP segment as
    # the 101 response; keep those bytes instead of dropping them.
    return WSStream(reader, writer, is_client=True, initial=rest)


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    request=None,
) -> WSStream:
    """Complete a server-side upgrade.  The caller has already validated the request."""
    req = request or await read_request(reader)
    if not is_websocket_request(req):
        raise HttpError("not a websocket request")
    if req.get("sec-websocket-version") != "13":
        raise HttpError("unsupported websocket version")
    accept = accept_key(req.get("sec-websocket-key"))
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept}",
    ]
    if "binary" in req.header_list("sec-websocket-protocol"):
        lines.append("Sec-WebSocket-Protocol: binary")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    await writer.drain()
    return WSStream(reader, writer, is_client=False, initial=req.rest)
