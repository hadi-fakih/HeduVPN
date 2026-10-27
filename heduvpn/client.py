"""HeduVPN client engine.

Exposes a local SOCKS5 proxy (and optionally an HTTP CONNECT proxy) and
multiplexes every connection through a single encrypted tunnel to the relay.

Design goals, in order:

* work from networks with aggressive filtering (looks like HTTPS/WebSocket,
  no proprietary port, TLS to port 443, certificate pinning instead of a CA);
* never block the tunnel on one stream (per-stream queues);
* reconnect silently and rotate sessions so long-lived flows do not stand out;
* leave enough counters for a UI to show what is happening.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import ipaddress
import os
import random
import secrets
import socket
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from . import crypto, protocol
from .config import ClientSettings
from .httpwire import HttpError, connect_established, read_request
from .protocol import (
    ERR_TEXT,
    F_CLOSE,
    F_DATA,
    F_ERROR,
    F_OPEN,
    F_OPEN_OK,
    F_PAD,
    F_PING,
    F_PONG,
    Frame,
    FrameCodec,
    ProtocolError,
    StreamClosed,
    encode_address,
    decode_address,
)
from .transport import (
    TLSInfo,
    TransportError,
    close_writer,
    socks5_connect,
    tls_connect,
    tls_upgrade,
)
from .websocket import client_handshake

STATE_IDLE = "idle"
STATE_CONNECTING = "connecting"
STATE_CONNECTED = "connected"
STATE_RECONNECTING = "reconnecting"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"


class TunnelError(Exception):
    pass


@dataclass
class _Counters:
    frames_out: int = 0
    frames_in: int = 0
    payload_out: int = 0
    payload_in: int = 0
    wire_out: int = 0
    wire_in: int = 0
    pad_out: int = 0
    pad_in: int = 0
    streams: int = 0
    active_streams: int = 0
    reconnects: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "frames_out": self.frames_out,
            "frames_in": self.frames_in,
            "payload_out": self.payload_out,
            "payload_in": self.payload_in,
            "wire_out": self.wire_out,
            "wire_in": self.wire_in,
            "pad_out": self.pad_out,
            "pad_in": self.pad_in,
            "streams": self.streams,
            "active_streams": self.active_streams,
            "reconnects": self.reconnects,
        }


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


class DnsError(Exception):
    pass


class DnsClient:
    """Minimal DNS-over-UDP A-record resolver (no third-party dependencies)."""

    def __init__(self, server: str, timeout: float = 4.0) -> None:
        self.server = server
        self.timeout = timeout

    def _query(self, host: str, txid: int) -> bytes:
        labels = b""
        for label in host.rstrip(".").split("."):
            raw = label.encode("idna")
            if not raw or len(raw) > 63:
                raise DnsError("invalid hostname")
            labels += bytes([len(raw)]) + raw
        return (
            struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + labels
            + b"\x00"
            + struct.pack(">HH", 1, 1)
        )

    @staticmethod
    def _skip_name(data: bytes, offset: int) -> int:
        while True:
            if offset >= len(data):
                raise DnsError("truncated DNS name")
            length = data[offset]
            if length == 0:
                return offset + 1
            if length & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + length

    async def resolve(self, host: str) -> list[str]:
        loop = asyncio.get_running_loop()
        for attempt in range(2):
            txid = secrets.randbelow(65536)
            query = self._query(host, txid)
            try:
                transport, protocol_ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol, remote_addr=(self.server, 53)
                )
            except OSError as exc:
                raise DnsError(f"cannot reach DNS server {self.server}: {exc}") from exc
            try:
                fut = loop.create_future()

                def _on_data(data: bytes) -> None:
                    if not fut.done():
                        fut.set_result(data)

                protocol_.datagram_received = lambda data, addr: _on_data(data)  # type: ignore[attr-defined]
                transport.sendto(query)
                try:
                    resp = await asyncio.wait_for(fut, self.timeout)
                except asyncio.TimeoutError:
                    continue
            finally:
                transport.close()
            if len(resp) < 12 or struct.unpack(">H", resp[:2])[0] != txid:
                continue
            flags, qd, an = struct.unpack(">HHH", resp[2:8])
            if flags & 0x000F:
                raise DnsError(f"DNS error {flags & 0x000F} for {host}")
            offset = 12
            for _ in range(qd):
                offset = self._skip_name(resp, offset) + 4
            addresses: list[str] = []
            for _ in range(an):
                offset = self._skip_name(resp, offset)
                if offset + 10 > len(resp):
                    break
                rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", resp[offset : offset + 10])
                offset += 10
                if rtype == 1 and rclass == 1 and rdlen == 4:
                    addresses.append(str(ipaddress.IPv4Address(resp[offset : offset + 4])))
                offset += rdlen
            if addresses:
                return addresses
        raise DnsError(f"could not resolve {host}")


async def resolve_target(settings: ClientSettings, host: str) -> str:
    """Map a SOCKS destination to what we put in the OPEN frame."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    cfg = settings.socks
    if cfg.dns == "remote":
        return host
    if cfg.dns == "dns":
        # Never fall back to the system resolver here: --dns dns is an explicit
        # promise that hostnames leave the machine only through the tunnel.
        return (await DnsClient(cfg.dns_server).resolve(host))[0]
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        return infos[0][4][0]
    except Exception as exc:
        raise DnsError(f"could not resolve {host}") from exc


# ---------------------------------------------------------------------------
# Local streams
# ---------------------------------------------------------------------------


class LocalConn:
    """Maps one local client socket to one multiplexed tunnel stream."""

    def __init__(
        self,
        session: "Session",
        stream_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        kind: str,
        initial: bytes = b"",
    ) -> None:
        self.session = session
        self.id = stream_id
        self.reader = reader
        self.writer = writer
        self.kind = kind
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=64)
        self.replied = False
        self.local_eof = False
        self.remote_eof = False
        self.closed = False
        self.initial = initial
        self.tasks: list[asyncio.Task] = []
        self.created = time.monotonic()
        self.sent = 0
        self.received = 0
        self.peer = "?"
        self.dest = ""

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self.tasks.append(asyncio.create_task(self._pump_local(), name=f"local-{self.id}"))
        self.tasks.append(asyncio.create_task(self._pump_writer(), name=f"writer-{self.id}"))

    async def _pump_local(self) -> None:
        try:
            while not self.closed:
                data = await self.reader.read(16 * 1024)
                if not data:
                    break
                self.sent += len(data)
                for i in range(0, len(data), protocol.MAX_PAYLOAD):
                    try:
                        await self.session.send(F_DATA, data[i : i + protocol.MAX_PAYLOAD], self.id)
                    except Exception:
                        await self.close(abort=True)
                        return
            self.local_eof = True
            with contextlib.suppress(Exception):
                await self.session.send(F_CLOSE, b"\x01", self.id)
            await self._maybe_finish()
        except (ConnectionError, OSError):
            await self.close(abort=True)
        except asyncio.CancelledError:
            raise

    async def _pump_writer(self) -> None:
        try:
            while True:
                item = await self.queue.get()
                if item is None:
                    if self.writer.can_write_eof():
                        with contextlib.suppress(Exception):
                            self.writer.write_eof()
                            await self.writer.drain()
                    self.remote_eof = True
                    await self._maybe_finish()
                    return
                self.received += len(item)
                self.writer.write(item)
                await self.writer.drain()
        except (ConnectionError, OSError):
            await self.close(abort=True)
        except asyncio.CancelledError:
            raise

    async def _maybe_finish(self) -> None:
        if self.local_eof and self.remote_eof and not self.closed:
            await self.close()

    async def close(self, abort: bool = False) -> None:
        if self.closed:
            return
        self.closed = True
        if abort:
            with contextlib.suppress(Exception):
                await self.session.send(F_CLOSE, b"\x00", self.id)
        self.session.remove_stream(self.id)
        for task in self.tasks:
            if task is not asyncio.current_task():
                task.cancel()
        await close_writer(self.writer)

    # -- tunnel events -----------------------------------------------------
    def reply_success(self, payload: bytes) -> None:
        if self.replied or self.closed:
            return
        self.replied = True
        try:
            self.writer.write(payload)
            if self.initial:
                self.queue.put_nowait(self.initial)
                self.initial = b""
        except Exception:
            asyncio.create_task(self.close(abort=True))

    def reply_error(self, payload: bytes) -> None:
        if self.replied or self.closed:
            return
        self.replied = True
        try:
            self.writer.write(payload)
        except Exception:
            pass
        asyncio.create_task(self.shutdown_now())

    async def shutdown_now(self) -> None:
        self.closed = True
        self.session.remove_stream(self.id)
        for task in self.tasks:
            if task is not asyncio.current_task():
                task.cancel()
        await close_writer(self.writer)

    def deliver(self, data: bytes) -> None:
        if self.closed:
            return
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            asyncio.create_task(self.close(abort=True))

    def remote_close(self) -> None:
        if self.closed:
            return
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            asyncio.create_task(self.close(abort=True))


# ---------------------------------------------------------------------------
# Session (one tunnel transport connection)
# ---------------------------------------------------------------------------

KEEPALIVE_INTERVAL = 15.0
KEEPALIVE_TIMEOUT = 75.0


class Session:
    """A single established tunnel; survives until the transport dies."""

    def __init__(
        self,
        client: "TunnelClient",
        transport,
        info: TLSInfo,
        send_key: bytes,
        recv_key: bytes,
    ) -> None:
        self.client = client
        camo = client.settings.camouflage
        self.codec = FrameCodec(
            send_key=send_key,
            recv_key=recv_key,
            padding=camo.padding,
            jitter_ms=camo.jitter_ms,
            on_send=self._on_send,
            on_recv=self._on_recv,
        )
        self.transport = transport
        self.info = info
        self.streams: dict[int, LocalConn] = {}
        self.next_stream_id = 1
        self.last_rx = time.monotonic()
        self.last_tx = time.monotonic()
        self.started = time.monotonic()
        self.rtt_ms: float = 0.0
        self.session_id = crypto.cert_fingerprint(os.urandom(16))[-12:]
        self.tasks: list[asyncio.Task] = []
        self.closed = asyncio.Event()
        self._error: Exception | None = None

    # -- framing -----------------------------------------------------------
    def _on_send(self, frame: Frame, wire: int, payload: int) -> None:
        c = self.client.counters
        c.frames_out += 1
        c.wire_out += wire
        c.payload_out += max(payload, 0)
        c.pad_out += max(frame.pad, 0)
        self._emit("out", frame, wire, payload)

    def _on_recv(self, frame: Frame, wire: int, payload: int) -> None:
        c = self.client.counters
        c.frames_in += 1
        c.wire_in += wire
        c.payload_in += max(payload, 0)
        c.pad_in += max(frame.pad, 0)
        self._emit("in", frame, wire, payload)

    def _emit(self, direction: str, frame: Frame, wire: int, payload: int) -> None:
        for cb in list(self.client.observers):
            try:
                cb(
                    {
                        "dir": direction,
                        "type": frame.name,
                        "wire": wire,
                        "payload": max(payload, 0),
                        "pad": max(frame.pad, 0),
                        "t": time.monotonic(),
                    }
                )
            except Exception:
                pass

    async def send(self, ftype: int, payload: bytes = b"", stream_id: int = 1) -> None:
        await self.codec.send(self.transport, ftype, payload, stream_id)
        self.last_tx = time.monotonic()

    def alloc_id(self) -> int:
        for _ in range(0xFFFF):
            sid = self.next_stream_id
            self.next_stream_id = (self.next_stream_id % 0xFFFFFFFF) + 1
            if sid not in self.streams:
                return sid
        raise TunnelError("stream id space exhausted")

    def remove_stream(self, sid: int) -> None:
        if self.streams.pop(sid, None) is not None:
            self.client.counters.active_streams = len(self.streams)

    # -- main loop ---------------------------------------------------------
    async def run(self) -> None:
        self.tasks = [
            asyncio.create_task(self._reader(), name="tunnel-reader"),
            asyncio.create_task(self._keepalive(), name="tunnel-keepalive"),
        ]
        with contextlib.suppress(Exception):
            await self.send(F_PING, struct.pack(">d", time.monotonic()))
        if self.client.settings.camouflage.cover != "none":
            self.tasks.append(asyncio.create_task(self._cover(), name="tunnel-cover"))
        try:
            await self.closed.wait()
        finally:
            for task in self.tasks:
                task.cancel()
            for task in self.tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            for conn in list(self.streams.values()):
                with contextlib.suppress(Exception):
                    await conn.close(abort=True)
            self.streams.clear()
            self.transport.close()

    def _fail(self, exc: Exception) -> None:
        if self._error is None:
            self._error = exc
        self.closed.set()

    @property
    def error(self) -> Exception | None:
        return self._error

    def uptime(self) -> float:
        return time.monotonic() - self.started

    # -- dispatch ----------------------------------------------------------
    async def _reader(self) -> None:
        try:
            while True:
                frame = await self.codec.recv(self.transport)
                self.last_rx = time.monotonic()
                if await self._dispatch(frame):
                    continue
        except asyncio.CancelledError:
            raise
        except (StreamClosed, ProtocolError, ConnectionError, OSError) as exc:
            self._fail(exc)
        except Exception as exc:  # pragma: no cover - defensive
            self._fail(exc)

    async def _dispatch(self, frame: Frame) -> bool:
        ftype = frame.type
        if ftype == F_DATA:
            conn = self.streams.get(frame.stream)
            if conn:
                conn.deliver(frame.payload)
            return True
        if ftype == F_OPEN_OK:
            conn = self.streams.get(frame.stream)
            if conn is None:
                return True
            conn.reply_success(self._success_payload(conn, frame.payload))
            return True
        if ftype == F_CLOSE:
            conn = self.streams.get(frame.stream)
            if conn is not None:
                if frame.payload[:1] == b"\x00":
                    asyncio.create_task(conn.shutdown_now())
                else:
                    conn.remote_close()
            return True
        if ftype == F_ERROR:
            conn = self.streams.get(frame.stream)
            if conn is not None:
                code = frame.payload[0] if frame.payload else 0
                conn.reply_error(self._error_payload(conn, code))
                await conn.shutdown_now()
            return True
        if ftype == F_PONG:
            try:
                sent = struct.unpack(">d", frame.payload[:8])[0]
                self.rtt_ms = (time.monotonic() - sent) * 1000.0
            except Exception:
                pass
            return True
        if ftype == F_PING:
            with contextlib.suppress(Exception):
                await self.send(F_PONG, frame.payload, frame.stream)
            return True
        if ftype == F_PAD:
            return True
        self.client.log(f"ignoring unexpected frame {frame.name}")
        return True

    @staticmethod
    def _success_payload(conn: LocalConn, payload: bytes) -> bytes:
        if conn.kind == "http":
            return connect_established()
        try:
            host, port, _ = decode_address(payload)
            ip = ipaddress.ip_address(host) if host else ipaddress.ip_address("0.0.0.0")
            if ip.version == 4:
                addr = b"\x01" + ip.packed
            else:
                addr = b"\x04" + ip.packed
        except Exception:
            addr = b"\x01" + b"\x00\x00\x00\x00"
            port = 0
        return b"\x05\x00\x00" + addr + struct.pack(">H", port)

    @staticmethod
    def _error_payload(conn: LocalConn, code: int) -> bytes:
        if conn.kind == "http":
            reason = ERR_TEXT.get(code, "tunnel error")
            body = f"502 Bad Gateway: {reason}\r\n".encode()
            head = (
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            return head + body
        rep = {protocol.ERR_POLICY: 0x02, protocol.ERR_CONNECT: 0x05}.get(code, 0x01)
        return b"\x05" + bytes([rep]) + b"\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"

    # -- background tasks --------------------------------------------------
    async def _keepalive(self) -> None:
        try:
            while True:
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                silence = time.monotonic() - self.last_rx
                if silence > KEEPALIVE_TIMEOUT:
                    self._fail(TunnelError("relay stopped responding"))
                    return
                # Ask for a pong whenever the channel has been quiet from the
                # relay's side.  last_tx is deliberately ignored: cover traffic
                # keeps writing, and that must not mask a dead peer.
                if silence >= KEEPALIVE_INTERVAL:
                    await self.send(F_PING, struct.pack(">d", time.monotonic()))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail(exc)

    async def _cover(self) -> None:
        rng = random.Random()
        cover = self.client.settings.camouflage.cover
        try:
            while True:
                if cover == "low":
                    await asyncio.sleep(rng.uniform(1.5, 5.0))
                    size = rng.randint(0, 32)
                else:
                    await asyncio.sleep(rng.uniform(0.4, 1.6))
                    size = rng.randint(0, 96)
                    if rng.random() < 0.08:
                        size = rng.randint(600, 1400)
                if time.monotonic() - self.last_tx > 1.0:
                    await self.send(F_PAD, os.urandom(size))
        except asyncio.CancelledError:
            raise
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class TunnelClient:
    """Runs the local proxies and keeps a tunnel session alive."""

    def __init__(
        self,
        settings: ClientSettings,
        log: Callable[[str], None] | None = None,
        on_state: Callable[[str, str], None] | None = None,
    ) -> None:
        settings.validate()
        self.settings = settings
        self.counters = _Counters()
        self._log_cb = log or (lambda msg: None)
        self._state_cb = on_state or (lambda state, detail: None)
        self.state = STATE_IDLE
        self.detail = ""
        self.session: Session | None = None
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._servers: list[asyncio.AbstractServer] = []
        self._session_ready = asyncio.Event()
        self._shutdown_done = False
        self._started_at = 0.0
        self._last_error = ""
        self.observers: list[Callable[[dict], None]] = []
        self._rate_sample = (time.monotonic(), 0, 0)
        self._history: list[tuple[float, float]] = []
        self._sampler_task: asyncio.Task | None = None
        self._connected_at = 0.0
        self.history_len = 90

    # -- public API --------------------------------------------------------
    def log(self, message: str) -> None:
        self._log_cb(f"{time.strftime('%H:%M:%S')}  {message}")

    def _set_state(self, state: str, detail: str = "") -> None:
        self.state = state
        self.detail = detail
        if state == STATE_CONNECTED:
            self._connected_at = time.time()
        self._state_cb(state, detail)

    async def run(self) -> None:
        await self.start()
        try:
            await self._stop.wait()
        finally:
            await self._shutdown()

    async def start(self) -> None:
        if self._tasks:
            return
        self._stop.clear()
        self._started_at = time.time()
        await self._start_listeners()
        self._tasks.append(asyncio.create_task(self._supervisor(), name="tunnel-supervisor"))
        self._sampler_task = asyncio.create_task(self._sampler(), name="rate-sampler")
        self.log(
            f"Local SOCKS5 proxy on {self.settings.socks.host}:{self.settings.socks.port}"
            + (
                f", HTTP proxy on {self.settings.socks.host}:{self.settings.socks.proxy_port}"
                if self.settings.socks.proxy_port
                else ""
            )
        )

    async def wait(self) -> None:
        await self._stop.wait()

    async def stop(self) -> None:
        self._stop.set()
        await self._shutdown()

    async def _shutdown(self) -> None:
        for server in self._servers:
            server.close()
        self._servers.clear()
        session = self.session
        self.session = None
        if session:
            session.transport.close()
            session.closed.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        if self._sampler_task:
            self._sampler_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._sampler_task
            self._sampler_task = None
        if not self._shutdown_done and self.state not in (STATE_ERROR, STATE_STOPPED):
            self._shutdown_done = True
            self._set_state(STATE_STOPPED, "")

    # -- listeners ---------------------------------------------------------
    async def _start_listeners(self) -> None:
        cfg = self.settings.socks
        server = await asyncio.start_server(self._socks_handler, cfg.host, cfg.port)
        self._servers.append(server)
        if cfg.proxy_port:
            proxy = await asyncio.start_server(self._http_handler, cfg.host, cfg.proxy_port)
            self._servers.append(proxy)

    def _peer_allowed(self, writer: asyncio.StreamWriter) -> bool:
        if self.settings.socks.allow_lan:
            return True
        peer = writer.get_extra_info("peername")
        if not peer:
            return False
        try:
            return ipaddress.ip_address(peer[0]).is_loopback
        except ValueError:
            return False

    async def _socks_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._peer_allowed(writer):
            writer.close()
            return
        try:
            await self._socks_negotiate(reader, writer)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError, HttpError):
            pass
        except Exception as exc:  # pragma: no cover - defensive
            self.log(f"socks handler error: {exc}")
            with contextlib.suppress(Exception):
                writer.close()

    async def _socks_negotiate(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await asyncio.wait_for(reader.readexactly(2), 15)
        if head[0] != 5:
            writer.close()
            return
        methods = set(await reader.readexactly(head[1]))
        cfg = self.settings.socks
        if cfg.username:
            if 0x02 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x02")
            await writer.drain()
            ver = await reader.readexactly(1)
            if ver[0] != 1:
                writer.close()
                return
            ulen = (await reader.readexactly(1))[0]
            user = (await reader.readexactly(ulen)).decode("utf-8", "replace")
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode("utf-8", "replace")
            if not hmac.compare_digest(user.encode(), cfg.username.encode()) or not hmac.compare_digest(
                password.encode(), cfg.password.encode()
            ):
                writer.write(b"\x01\x01")
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x01\x00")
            await writer.drain()
        else:
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x00")
            await writer.drain()

        req = await asyncio.wait_for(reader.readexactly(4), 15)
        if req[0] != 5:
            writer.close()
            return
        cmd = req[1]
        atyp = req[3]
        host, port = await self._read_socks_addr(reader, atyp)
        if cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        conn = await self._open_local_stream(reader, writer, "socks", host, port)
        if conn is None:
            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()

    async def _read_socks_addr(self, reader: asyncio.StreamReader, atyp: int) -> tuple[str, int]:
        if atyp == 1:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        elif atyp == 3:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("idna")
        else:
            raise HttpError("bad address type")
        port = struct.unpack(">H", await reader.readexactly(2))[0]
        return host, port

    async def _http_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._peer_allowed(writer):
            writer.close()
            return
        try:
            req = await read_request(reader)
            if req.method != "CONNECT":
                body = b"HTTP proxy: use CONNECT\r\n"
                writer.write(
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
                writer.close()
                return
            if ":" not in req.target:
                raise HttpError("CONNECT target must be host:port")
            host, _, port_s = req.target.rpartition(":")
            host = host.strip("[]")
            port = int(port_s)
            conn = await self._open_local_stream(reader, writer, "http", host, port, initial=req.rest)
            if conn is None:
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                writer.close()
        except (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            ConnectionError,
            OSError,
            HttpError,
            ValueError,
        ):
            with contextlib.suppress(Exception):
                writer.close()

    # -- stream setup ------------------------------------------------------
    async def _open_local_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        kind: str,
        host: str,
        port: int,
        initial: bytes = b"",
    ) -> LocalConn | None:
        if not 0 < port < 65536:
            return None
        session = self.session
        if session is None:
            try:
                await asyncio.wait_for(self._session_ready.wait(), timeout=15)
            except asyncio.TimeoutError:
                return None
            session = self.session
            if session is None:
                return None
        try:
            target = await asyncio.wait_for(resolve_target(self.settings, host), 8)
        except (DnsError, asyncio.TimeoutError):
            self.log(f"DNS failed for {host}")
            return None
        stream_id = session.alloc_id()
        conn = LocalConn(session, stream_id, reader, writer, kind, initial=initial)
        conn.dest = f"{host}:{port}"
        conn.peer = str(writer.get_extra_info("peername"))
        session.streams[stream_id] = conn
        self.counters.streams += 1
        self.counters.active_streams = len(session.streams)
        try:
            await session.send(F_OPEN, encode_address(target, port), stream_id)
        except Exception:
            session.remove_stream(stream_id)
            return None
        conn.start()
        return conn

    # -- supervisor --------------------------------------------------------
    async def _supervisor(self) -> None:
        backoff = 0.5
        while not self._stop.is_set():
            try:
                await self._run_session()
                backoff = 0.5
                if self._stop.is_set():
                    break
                self._set_state(STATE_RECONNECTING, "session rotated")
                await asyncio.sleep(0.4)
            except asyncio.CancelledError:
                raise
            except (TransportError, TunnelError, ProtocolError, OSError, StreamClosed, asyncio.TimeoutError) as exc:
                if self._stop.is_set():
                    break
                self.counters.reconnects += 1
                self._last_error = str(exc)
                self._set_state(STATE_RECONNECTING, str(exc))
                self.log(f"tunnel down: {exc} (retrying in {backoff:.1f}s)")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                    break
                except asyncio.TimeoutError:
                    pass
                backoff = min(30.0, backoff * 2) * random.uniform(0.9, 1.15)
            except Exception as exc:  # pragma: no cover - defensive
                if self._stop.is_set():
                    break
                self.counters.reconnects += 1
                self._last_error = str(exc)
                self._set_state(STATE_ERROR, str(exc))
                self.log(f"unexpected error: {exc}")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=min(backoff, 10.0))
                    break
                except asyncio.TimeoutError:
                    pass
                backoff = min(30.0, backoff * 2)

    async def _run_session(self) -> None:
        self._session_ready.clear()
        self._set_state(STATE_CONNECTING, f"connecting to {self.settings.connection.server}")
        self.log(
            f"connecting to {self.settings.connection.server}:{self.settings.connection.port}"
            f" via {self.settings.connection.transport}"
        )
        transport, info = await self._open_transport()
        psk = self.settings.psk_bytes
        client_nonce = secrets.token_bytes(16)
        hello_wire = protocol.build_hello(psk, client_nonce)
        hello = protocol.Hello(protocol.VERSION, 0, client_nonce, int(time.time()), hello_wire)
        await transport.write(hello_wire)
        ack_wire = await protocol.read_handshake_message(transport)
        ack = protocol.parse_ack(psk, ack_wire, hello)
        c2s, s2c = crypto.derive_session_keys(psk, client_nonce, ack.server_nonce)
        camo = self.settings.camouflage
        session = Session(self, transport, info, c2s, s2c)
        self.session = session
        self._session_ready.set()
        self.log(
            f"tunnel up · {info.description} · pin {info.pin[:23]}… · padding {camo.padding}"
            if info.pin
            else f"tunnel up · {info.description} · padding {camo.padding}"
        )
        self._set_state(STATE_CONNECTED, f"{info.alpn or 'tls'} · {info.cipher}")
        runner = asyncio.create_task(session.run(), name="session-runner")
        rotator: asyncio.Task | None = None
        if camo.rotate_minutes:
            rotator = asyncio.create_task(
                asyncio.sleep(camo.rotate_minutes * 60), name="session-rotate"
            )
        try:
            if rotator is not None:
                done, _ = await asyncio.wait(
                    {runner, rotator}, return_when=asyncio.FIRST_COMPLETED
                )
                if rotator in done:
                    self.log("rotating tunnel session (stealth rotation)")
                    session.closed.set()
            await runner
            if session.error and not self._stop.is_set():
                raise session.error
        finally:
            if rotator is not None:
                rotator.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await rotator
            self.session = None
            self._session_ready.clear()

    # -- transport ---------------------------------------------------------
    async def _open_transport(self) -> tuple[Any, TLSInfo]:
        cfg = self.settings.connection
        timeout = cfg.connect_timeout
        if cfg.upstream:
            url = urlparse(cfg.upstream)
            if not url.hostname or not url.port:
                raise TransportError("upstream proxy URL needs host and port")
            reader, writer = await socks5_connect(
                url.hostname,
                url.port,
                cfg.server,
                cfg.port,
                username=url.username or "",
                password=url.password or "",
                timeout=timeout,
            )
            tls = await tls_upgrade(reader, writer, cfg.verify, cfg.pin, cfg.sni, timeout)
        else:
            tls = await tls_connect(
                cfg.server, cfg.port, verify=cfg.verify, pin=cfg.pin, sni=cfg.sni, timeout=timeout
            )
        if cfg.transport == "tls":
            return tls, tls.info
        token = crypto.make_ws_token(self.settings.psk_bytes)
        ws = await client_handshake(
            tls.reader,
            tls.writer,
            host=cfg.ws_host_header,
            path=cfg.ws_path,
            extra_headers=[
                ("Cookie", f"{cfg.ws_cookie}={token}"),
                ("Origin", f"https://{cfg.ws_host_header}"),
            ],
            timeout=timeout,
        )
        return ws, tls.info

    # -- metrics -----------------------------------------------------------
    async def _sampler(self) -> None:
        try:
            while True:
                await asyncio.sleep(1.0)
                c = self.counters
                now = time.monotonic()
                t0, o0, i0 = self._rate_sample
                dt = max(now - t0, 0.001)
                up = (c.wire_out - o0) / dt
                down = (c.wire_in - i0) / dt
                self._rate_sample = (now, c.wire_out, c.wire_in)
                self._history.append((up, down))
                if len(self._history) > self.history_len:
                    self._history = self._history[-self.history_len :]
        except asyncio.CancelledError:
            raise

    def snapshot(self) -> dict[str, Any]:
        session = self.session
        t0, o0, i0 = self._rate_sample
        dt = max(time.monotonic() - t0, 0.001)
        c = self.counters
        info = session.info if session else TLSInfo()
        return {
            "state": self.state,
            "detail": self.detail,
            "name": self.settings.name,
            "server": self.settings.connection.server,
            "port": self.settings.connection.port,
            "transport": self.settings.connection.transport,
            "verify": self.settings.connection.verify,
            "padding": self.settings.camouflage.padding,
            "cover": self.settings.camouflage.cover,
            "jitter_ms": self.settings.camouflage.jitter_ms,
            "socks": f"{self.settings.socks.host}:{self.settings.socks.port}",
            "proxy": (
                f"{self.settings.socks.host}:{self.settings.socks.proxy_port}"
                if self.settings.socks.proxy_port
                else ""
            ),
            "dns": self.settings.socks.dns,
            "connected": bool(session),
            "connected_at": self._connected_at,
            "session_uptime": session.uptime() if session else 0.0,
            "session_id": session.session_id if session else "",
            "tls": info.description,
            "pin": info.pin,
            "cert_cn": info.cert_cn,
            "rtt_ms": session.rtt_ms if session else 0.0,
            "rate_up": (c.wire_out - o0) / dt,
            "rate_down": (c.wire_in - i0) / dt,
            "counters": c.as_dict(),
            "history": list(self._history),
            "last_error": self._last_error,
            "history_len": self.history_len,
        }
