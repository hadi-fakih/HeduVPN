"""HeduVPN relay server.

Listens on one port and speaks two things at once:

* ordinary HTTPS: probes get a normal nginx-style website (200/400/404);
* the tunnel: either native TLS or WebSocket, always inside TLS by default.

Nothing about the port says "VPN": no PPTP/L2TP/WireGuard/OpenVPN magic, no
idle "tunnel" banner, no CA-trust requirement.  Clients pin the certificate
fingerprint and authenticate with a 256-bit pre-shared key.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import ssl
import struct
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any, Callable

from . import crypto, protocol
from .httpwire import HttpError, HttpRequest, decoy_response, read_request
from .protocol import (
    ERR_CONNECT,
    ERR_POLICY,
    ERR_PROTOCOL,
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
    Stream,
    StreamClosed,
    encode_address,
    decode_address,
    read_handshake_message,
)
from .transport import (
    TLSInfo,
    TLSStream,
    TransportError,
    close_server,
    close_writer,
    server_ssl_context,
    tcp_connect,
)
from .websocket import WSStream, is_websocket_request, server_handshake

DEFAULT_BLOCK_PORTS = (25, 465, 587)  # SMTP: common abuse vector, configurable


class RelayError(Exception):
    pass


@dataclass
class RelaySettings:
    listen_host: str = "0.0.0.0"
    listen_port: int = 443
    domain: str = ""
    psk: str = ""
    certfile: str = ""
    keyfile: str = ""
    tls: bool = True  # false only when a reverse proxy / CDN terminates TLS
    behind_proxy: bool = False
    alpn: tuple[str, ...] = ("http/1.1",)
    ws_path: str = "/ws"
    ws_cookie: str = "hid"
    ws_token_ttl: int = 120
    allow_private: bool = False
    allow_ports: tuple[int, ...] = ()
    block_ports: tuple[int, ...] = DEFAULT_BLOCK_PORTS
    block_hosts: tuple[str, ...] = ()
    max_sessions: int = 0  # 0 = unlimited
    max_streams: int = 512  # per session
    idle_timeout: int = 300
    connect_timeout: float = 10.0
    decoy_site: str = "Hedu Labs"
    decoy_server: str = "nginx/1.24.0"
    padding: str = "random"
    log_path: str = ""

    def validate(self) -> None:
        if not self.psk:
            raise RelayError("relay requires a psk")
        crypto.decode_psk(self.psk)
        if not 1 <= int(self.listen_port) <= 65535:
            raise RelayError("listen_port must be between 1 and 65535")
        if self.tls:
            if not self.certfile or not self.keyfile:
                raise RelayError("TLS relay requires certfile and keyfile")
            for path in (self.certfile, self.keyfile):
                if not os.path.exists(path):
                    raise RelayError(f"missing certificate file: {path}")
        if not self.ws_path.startswith("/"):
            raise RelayError("ws_path must start with '/'")
        if self.padding not in protocol.PAD_MODES:
            raise RelayError(f"padding must be one of {', '.join(protocol.PAD_MODES)}")
        for port in self.allow_ports:
            if not 1 <= int(port) <= 65535:
                raise RelayError(f"invalid allow_ports entry {port}")

    @property
    def psk_bytes(self) -> bytes:
        return crypto.decode_psk(self.psk)


@dataclass
class _RelayCounters:
    sessions: int = 0
    active_sessions: int = 0
    streams: int = 0
    active_streams: int = 0
    payload_in: int = 0
    payload_out: int = 0
    wire_in: int = 0
    wire_out: int = 0
    handshakes_ok: int = 0
    handshakes_failed: int = 0
    decoys: int = 0
    policy_blocks: int = 0
    connect_failures: int = 0
    ws_upgrades: int = 0

    def as_dict(self) -> dict[str, int]:
        return self.__dict__.copy()


class RelayStream:
    """One outbound TCP connection, multiplexed over one tunnel session."""

    def __init__(self, session: "RelaySession", sid: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, dest: str) -> None:
        self.session = session
        self.sid = sid
        self.reader = reader
        self.writer = writer
        self.dest = dest
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=64)
        self.client_eof = False
        self.target_eof = False
        self.closed = False
        self.tasks: list[asyncio.Task] = []

    def start(self) -> None:
        self.tasks.append(asyncio.create_task(self._pump_target(), name=f"relay-read-{self.sid}"))
        self.tasks.append(asyncio.create_task(self._pump_writer(), name=f"relay-write-{self.sid}"))

    async def _pump_target(self) -> None:
        try:
            while not self.closed:
                data = await self.reader.read(16 * 1024)
                if not data:
                    break
                for i in range(0, len(data), protocol.MAX_PAYLOAD):
                    await self.session.send(F_DATA, data[i : i + protocol.MAX_PAYLOAD], self.sid)
        except (ConnectionError, OSError, ProtocolError, StreamClosed):
            pass
        except asyncio.CancelledError:
            raise
        self.target_eof = True
        with contextlib.suppress(Exception):
            await self.session.send(F_CLOSE, b"\x01", self.sid)
        await self.maybe_finish()

    async def _pump_writer(self) -> None:
        try:
            while True:
                item = await self.queue.get()
                if item is None:
                    if self.writer.can_write_eof():
                        with contextlib.suppress(Exception):
                            self.writer.write_eof()
                            await self.writer.drain()
                    return
                self.writer.write(item)
                await self.writer.drain()
        except (ConnectionError, OSError):
            await self.close(abort=True)
        except asyncio.CancelledError:
            raise

    async def maybe_finish(self) -> None:
        if self.client_eof and self.target_eof and not self.closed:
            await self.close()

    def deliver(self, data: bytes) -> None:
        if self.closed:
            return
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            asyncio.create_task(self.close(abort=True))

    def client_half_close(self) -> None:
        self.client_eof = True
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            asyncio.create_task(self.close(abort=True))
        asyncio.create_task(self.maybe_finish())

    async def close(self, abort: bool = False) -> None:
        if self.closed:
            return
        self.closed = True
        self.session.remove_stream(self.sid)
        for task in self.tasks:
            if task is not asyncio.current_task():
                task.cancel()
        await close_writer(self.writer)


class RelaySession:
    """An authenticated tunnel connection from one client."""

    def __init__(
        self,
        relay: "Relay",
        stream: Stream,
        info: TLSInfo,
        send_key: bytes,
        recv_key: bytes,
        peer: str,
    ) -> None:
        self.relay = relay
        self.stream = stream
        self.info = info
        self.peer = peer
        cfg = relay.settings
        self.codec = FrameCodec(
            send_key=send_key,
            recv_key=recv_key,
            padding=cfg.padding,
            on_send=self._on_send,
            on_recv=self._on_recv,
        )
        self.streams: dict[int, RelayStream] = {}
        self.tasks: list[asyncio.Task] = []
        self.closed = asyncio.Event()
        self.last_rx = time.monotonic()
        self.started = time.monotonic()
        self.session_id = os.urandom(4).hex()

    def _on_send(self, frame: Frame, wire: int, payload: int) -> None:
        c = self.relay.counters
        c.wire_out += wire
        c.payload_out += max(payload, 0)

    def _on_recv(self, frame: Frame, wire: int, payload: int) -> None:
        c = self.relay.counters
        c.wire_in += wire
        c.payload_in += max(payload, 0)

    async def send(self, ftype: int, payload: bytes = b"", sid: int = 1) -> None:
        await self.codec.send(self.stream, ftype, payload, sid)

    def remove_stream(self, sid: int) -> None:
        if self.streams.pop(sid, None) is not None:
            self.relay.counters.active_streams = sum(
                len(s.streams) for s in self.relay.sessions
            )

    async def run(self) -> None:
        self.tasks = [
            asyncio.create_task(self._reader(), name=f"session-reader-{self.session_id}"),
            asyncio.create_task(self._idle_watch(), name=f"session-idle-{self.session_id}"),
        ]
        try:
            await self.closed.wait()
        finally:
            for task in self.tasks:
                task.cancel()
            for task in self.tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            for stream in list(self.streams.values()):
                with contextlib.suppress(Exception):
                    await stream.close(abort=True)
            self.streams.clear()
            self.stream.close()
            self.relay.counters.active_streams = sum(len(s.streams) for s in self.relay.sessions)

    async def _reader(self) -> None:
        try:
            while True:
                frame = await self.codec.recv(self.stream)
                self.last_rx = time.monotonic()
                await self._dispatch(frame)
        except asyncio.CancelledError:
            raise
        except (ProtocolError, StreamClosed, ConnectionError, OSError) as exc:
            self.relay.log(f"session {self.session_id} ended: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            self.relay.log(f"session {self.session_id} error: {exc}")
        finally:
            self.closed.set()

    async def _idle_watch(self) -> None:
        try:
            while True:
                await asyncio.sleep(30)
                if time.monotonic() - self.last_rx > self.relay.settings.idle_timeout:
                    self.relay.log(f"session {self.session_id} idle timeout")
                    self.closed.set()
                    return
        except asyncio.CancelledError:
            raise

    async def _dispatch(self, frame: Frame) -> None:
        ftype = frame.type
        if ftype == F_OPEN:
            await self._open(frame)
        elif ftype == F_DATA:
            stream = self.streams.get(frame.stream)
            if stream:
                stream.deliver(frame.payload)
        elif ftype == F_CLOSE:
            stream = self.streams.get(frame.stream)
            if stream:
                if frame.payload[:1] == b"\x00":
                    await stream.close(abort=True)
                else:
                    stream.client_half_close()
        elif ftype == F_PING:
            await self.send(F_PONG, frame.payload, frame.stream)
        elif ftype == F_PONG:
            pass
        elif ftype == F_PAD:
            pass
        else:
            await self.send(F_ERROR, bytes([ERR_PROTOCOL]), frame.stream)

    async def _open(self, frame: Frame) -> None:
        sid = frame.stream
        if len(self.streams) >= self.relay.settings.max_streams:
            await self.send(F_ERROR, bytes([ERR_POLICY]), sid)
            return
        try:
            host, port, _ = decode_address(frame.payload)
        except ProtocolError:
            await self.send(F_ERROR, bytes([ERR_PROTOCOL]), sid)
            return
        if sid in self.streams:
            await self.send(F_ERROR, bytes([ERR_PROTOCOL]), sid)
            return
        relay = self.relay
        try:
            addresses = await relay.authorize(host, port)
        except protocol.PolicyError as exc:
            relay.counters.policy_blocks += 1
            relay.log(f"blocked {host}:{port} ({exc})")
            await self.send(F_ERROR, bytes([ERR_POLICY]), sid)
            return
        reader = writer = None
        last_error: Exception | None = None
        for addr in addresses:
            try:
                reader, writer = await asyncio.wait_for(
                    tcp_connect(addr, port, relay.settings.connect_timeout),
                    relay.settings.connect_timeout + 1,
                )
                host = addr
                break
            except (TransportError, OSError, asyncio.TimeoutError) as exc:
                last_error = exc
                continue
        if reader is None or writer is None:
            relay.counters.connect_failures += 1
            relay.log(f"connect failed {host}:{port}: {last_error}")
            await self.send(F_ERROR, bytes([ERR_CONNECT]), sid)
            return
        dest = f"{host}:{port}"
        socket_obj = writer.get_extra_info("socket")
        if socket_obj is not None:
            with contextlib.suppress(Exception):
                socket_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream = RelayStream(self, sid, reader, writer, dest)
        self.streams[sid] = stream
        relay.counters.streams += 1
        relay.counters.active_streams = sum(len(s.streams) for s in relay.sessions)
        relay.note_destination(host)
        await self.send(F_OPEN_OK, encode_address(host, port), sid)
        stream.start()
        relay.log(f"opened {dest} for {self.peer}")


class Relay:
    """The tunnel server plus its decoy website."""

    def __init__(
        self,
        settings: RelaySettings,
        log: Callable[[str], None] | None = None,
    ) -> None:
        settings.validate()
        self.settings = settings
        self.counters = _RelayCounters()
        self.sessions: set[RelaySession] = set()
        self.started_at = time.time()
        self._log_cb = log or (lambda msg: None)
        self._log_file = None
        self._server: asyncio.AbstractServer | None = None
        self._stopping = False
        self.destinations: Counter[str] = Counter()
        self._seen_nonces: dict[bytes, float] = {}
        self.recent: deque[dict[str, Any]] = deque(maxlen=40)
        self.bytes_history: deque[tuple[float, float]] = deque(maxlen=120)
        self._sample_task: asyncio.Task | None = None
        self._last_sample = (time.monotonic(), 0, 0)
        self.cert_cn = ""
        self.cert_pin = ""
        if settings.tls:
            with contextlib.suppress(Exception):
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                from cryptography.x509.oid import NameOID

                with open(settings.certfile, "rb") as fh:
                    cert = x509.load_pem_x509_certificate(fh.read())
                attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                self.cert_cn = attrs[0].value if attrs else ""
                self.cert_pin = crypto.cert_fingerprint(
                    cert.public_bytes(serialization.Encoding.DER)
                )
        if settings.log_path:
            self._log_file = open(settings.log_path, "a", encoding="utf-8")

    # -- logging -----------------------------------------------------------
    def log(self, message: str) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {message}"
        self._log_cb(line)
        if self._log_file:
            with contextlib.suppress(Exception):
                self._log_file.write(line + "\n")
                self._log_file.flush()

    def note_destination(self, host: str) -> None:
        try:
            ipaddress.ip_address(host)
            key = "IP literal"
        except ValueError:
            key = host.lower()[:80]
        self.destinations[key] += 1
        if len(self.destinations) > 200:
            for extra, _ in self.destinations.most_common()[150:]:
                self.destinations.pop(extra, None)

    # -- lifecycle ---------------------------------------------------------
    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.settings.tls:
            return None
        return server_ssl_context(self.settings.certfile, self.settings.keyfile, list(self.settings.alpn))

    async def start(self) -> None:
        ssl_ctx = self._ssl_context()
        self._server = await asyncio.start_server(
            self._on_client,
            host=self.settings.listen_host,
            port=self.settings.listen_port,
            ssl=ssl_ctx,
            ssl_handshake_timeout=12 if ssl_ctx else None,
            reuse_address=True,
        )
        self._sample_task = asyncio.create_task(self._sampler(), name="relay-sampler")
        mode = "TLS" if self.settings.tls else "plaintext (behind reverse proxy)"
        self.log(
            f"relay listening on {self.settings.listen_host}:{self.settings.listen_port} "
            f"[{mode}] · transports: WebSocket {self.settings.ws_path} + native TLS"
        )

    async def serve_forever(self) -> None:
        await self.start()
        try:
            assert self._server is not None
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._stopping = True
        # Ask every live session to finish *before* waiting on the listener.
        # Since Python 3.12, Server.wait_closed() waits for in-flight connection
        # handlers, and a handler here runs an entire tunnel session -- waiting
        # first would deadlock until the idle timeout.
        for session in list(self.sessions):
            session.closed.set()
        if self._server:
            await close_server(self._server)
            self._server = None
        for _ in range(50):
            if not self.sessions:
                break
            await asyncio.sleep(0.02)
        if self._sample_task:
            self._sample_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._sample_task
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    # -- connection handling -----------------------------------------------
    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_str = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer)
        if self.settings.max_sessions and len(self.sessions) >= self.settings.max_sessions:
            writer.close()
            return
        try:
            head = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            with contextlib.suppress(Exception):
                writer.close()
            return

        sslobj = writer.get_extra_info("ssl_object")
        info = TLSInfo()
        if sslobj is not None:
            try:
                der = sslobj.getpeercert(binary_form=True) or b""
            except Exception:
                der = b""
            info = TLSInfo(
                version=sslobj.version() or "",
                cipher=(sslobj.cipher() or ("",))[0],
                alpn=sslobj.selected_alpn_protocol() or "",
                sni=getattr(sslobj, "server_hostname", "") or "",
                cert_cn="",
                pin=crypto.cert_fingerprint(der) if der else "",
            )
            info.description = f"TLS {info.version} · {info.cipher} · ALPN {info.alpn or '-'}"
            if not info.sni:
                # Python exposes the SNI the client sent through the SSL object
                # in some versions only; keep the field useful either way.
                info.sni = ""

        if self._looks_http(head):
            await self._handle_http(reader, writer, head, info, peer_str)
            return

        raw = TLSStream(reader, writer, info)
        await self._handle_tunnel(raw, info, peer_str, initial=head)

    @staticmethod
    def _looks_http(head: bytes) -> bool:
        return head in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"CONN", b"PATC", b"TRAC")

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        head: bytes,
        info: TLSInfo,
        peer: str,
    ) -> None:
        cfg = self.settings
        try:
            req = await read_request(reader, initial=head)
        except HttpError:
            self.counters.decoys += 1
            with contextlib.suppress(Exception):
                writer.write(decoy_response("/", status=400, server=cfg.decoy_server))
                await writer.drain()
            with contextlib.suppress(Exception):
                writer.close()
            return

        valid_ws = (
            req.path == cfg.ws_path
            and is_websocket_request(req)
            and self._valid_ws_token(req)
        )
        if valid_ws:
            try:
                ws = await server_handshake(reader, writer, req)
            except HttpError:
                self.counters.decoys += 1
                with contextlib.suppress(Exception):
                    writer.close()
                return
            self.counters.ws_upgrades += 1
            await self._handle_tunnel(ws, info, peer, initial=b"")
            return

        self.counters.decoys += 1
        self.recent.appendleft(
            {
                "at": time.time(),
                "peer": peer,
                "kind": "probe",
                "detail": f"{req.method} {req.path}",
            }
        )
        try:
            response = decoy_response(
                req.path,
                req.method,
                server=cfg.decoy_server,
                site_title=cfg.decoy_site,
            )
            if req.method == "HEAD":
                response = response.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
            writer.write(response)
            await writer.drain()
        except Exception:
            pass
        with contextlib.suppress(Exception):
            writer.close()

    def _valid_ws_token(self, req: HttpRequest) -> bool:
        cookie_name = self.settings.ws_cookie
        cookies = req.get("cookie")
        token = ""
        for part in cookies.split(";"):
            name, _, value = part.strip().partition("=")
            if name == cookie_name:
                token = value
                break
        if not token:
            return False
        ok, _reason = crypto.verify_ws_token(
            self.settings.psk_bytes, token, ttl=self.settings.ws_token_ttl
        )
        return ok

    async def _handle_tunnel(
        self, stream: Stream, info: TLSInfo, peer: str, initial: bytes = b""
    ) -> None:
        psk = self.settings.psk_bytes
        try:
            if initial:
                (total,) = struct.unpack(">I", initial[:4])
                if total < crypto.NONCE_BYTES + crypto.AEAD_TAG or total > 4096:
                    raise ProtocolError("invalid handshake size")
                wire = initial + await stream.read_exact(total)
            else:
                wire = await read_handshake_message(stream)
            hello = protocol.parse_hello(psk, wire)
            now = time.monotonic()
            for nonce, expiry in list(self._seen_nonces.items()):
                if expiry < now:
                    self._seen_nonces.pop(nonce, None)
            if hello.client_nonce in self._seen_nonces:
                raise ProtocolError("replayed handshake")
            ack_wire, server_nonce = protocol.build_ack(psk, hello)
        except (ProtocolError, StreamClosed, asyncio.TimeoutError, ConnectionError, OSError):
            self.counters.handshakes_failed += 1
            if not isinstance(stream, WSStream):
                # Answer junk with the same 400 a web server would send.
                with contextlib.suppress(Exception):
                    await stream.write(decoy_response("/", status=400, server=self.settings.decoy_server))
            stream.close()
            return

        try:
            await stream.write(ack_wire)
        except (StreamClosed, ConnectionError, OSError):
            stream.close()
            return
        c2s, s2c = crypto.derive_session_keys(psk, hello.client_nonce, server_nonce)
        self._seen_nonces[hello.client_nonce] = time.monotonic() + protocol.HANDSHAKE_SKEW
        self.counters.handshakes_ok += 1
        self.counters.sessions += 1
        session = RelaySession(self, stream, info, send_key=s2c, recv_key=c2s, peer=peer)
        self.sessions.add(session)
        self.counters.active_sessions = len(self.sessions)
        self.log(
            f"session {session.session_id} from {peer} · {info.description or 'tls'}"
            f" · mode={'websocket' if isinstance(stream, WSStream) else 'tls'}"
        )
        self.recent.appendleft(
            {
                "at": time.time(),
                "peer": peer,
                "kind": "session",
                "detail": "websocket" if isinstance(stream, WSStream) else "native tls",
            }
        )
        try:
            await session.run()
        finally:
            self.sessions.discard(session)
            self.counters.active_sessions = len(self.sessions)
            self.counters.active_streams = sum(len(s.streams) for s in self.sessions)
            self.log(f"session {session.session_id} closed")

    # -- outbound policy ---------------------------------------------------
    async def authorize(self, host: str, port: int) -> list[str]:
        cfg = self.settings
        if port <= 0 or port > 65535:
            raise protocol.PolicyError("invalid port")
        if cfg.allow_ports:
            if port not in cfg.allow_ports:
                raise protocol.PolicyError(f"port {port} not allowed")
        elif port in cfg.block_ports:
            raise protocol.PolicyError(f"port {port} is blocked")
        host_lower = host.rstrip(".").lower()
        for blocked in cfg.block_hosts:
            blocked = blocked.lower().lstrip(".")
            if host_lower == blocked or host_lower.endswith("." + blocked):
                raise protocol.PolicyError("host blocked")
        try:
            ip = ipaddress.ip_address(host)
            self._check_ip(ip)
            return [host]
        except ValueError:
            pass
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                8.0,
            )
        except (socket.gaierror, asyncio.TimeoutError, OSError) as exc:
            raise protocol.PolicyError(f"cannot resolve {host}") from exc
        addresses: list[str] = []
        for family, _type, _proto, _canon, sockaddr in infos:
            addr = sockaddr[0]
            try:
                self._check_ip(ipaddress.ip_address(addr))
            except protocol.PolicyError:
                continue
            if addr not in addresses:
                addresses.append(addr)
        if not addresses:
            raise protocol.PolicyError("destination resolves only to blocked addresses")
        return addresses

    def _check_ip(self, ip: Any) -> None:
        if self.settings.allow_private:
            return
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise protocol.PolicyError("private/loopback destinations are disabled")

    # -- stats -------------------------------------------------------------
    async def _sampler(self) -> None:
        try:
            while True:
                await asyncio.sleep(1.0)
                now = time.monotonic()
                t0, i0, o0 = self._last_sample
                dt = max(now - t0, 0.001)
                self._last_sample = (now, self.counters.wire_in, self.counters.wire_out)
                self.bytes_history.append(
                    (
                        (self.counters.wire_in - i0) / dt,
                        (self.counters.wire_out - o0) / dt,
                    )
                )
        except asyncio.CancelledError:
            raise

    def snapshot(self) -> dict[str, Any]:
        return {
            "uptime": time.time() - self.started_at,
            "listen": f"{self.settings.listen_host}:{self.settings.listen_port}",
            "tls": self.settings.tls,
            "cert_cn": self.cert_cn,
            "cert_pin": self.cert_pin,
            "alpn": list(self.settings.alpn),
            "ws_path": self.settings.ws_path,
            "sessions": len(self.sessions),
            "streams": sum(len(s.streams) for s in self.sessions),
            "counters": self.counters.as_dict(),
            "top_destinations": self.destinations.most_common(8),
            "history": list(self.bytes_history),
            "recent": list(self.recent)[:12],
        }


# ---------------------------------------------------------------------------
# Relay configuration files
# ---------------------------------------------------------------------------


def relay_settings_to_dict(settings: RelaySettings) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(settings)


def relay_settings_from_dict(data: dict[str, Any]) -> RelaySettings:
    known = {f for f in RelaySettings.__dataclass_fields__}
    if not isinstance(data, dict):
        raise RelayError("relay config must be a JSON object")
    unknown = set(data) - known
    if unknown:
        raise RelayError(f"unknown relay config keys: {', '.join(sorted(unknown))}")
    data = dict(data)
    for key in ("alpn", "allow_ports", "block_ports", "block_hosts"):
        if key in data and data[key] is not None:
            data[key] = tuple(data[key])
    settings = RelaySettings(**data)
    settings.validate()
    return settings


def save_relay_config(settings: RelaySettings, path: str) -> None:
    import json

    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(relay_settings_to_dict(settings), fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def load_relay_config(path: str) -> RelaySettings:
    import json

    with open(path, encoding="utf-8") as fh:
        return relay_settings_from_dict(json.load(fh))
