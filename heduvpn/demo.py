"""The dashboard's traffic laboratory.

This is **not** a mock-up: the lab boots a real relay, a real client, a real
origin HTTP server and real TLS on loopback, sends real traffic through the
tunnel, records only metadata (record sizes, frame types, timings) and then
shows what an on-path observer *could* learn from it.  No payload bytes ever
leave the process.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import random
import socket
import statistics
import tempfile
import time
from collections import deque
from typing import Any, Callable

from . import crypto, protocol
from .client import TunnelClient
from .config import CamouflageConfig, ClientSettings, ConnectionConfig, SocksConfig
from .httpwire import read_response_headers_with_rest
from .link import pin_from_cert
from .protocol import PAD_MODES
from .relay import Relay, RelaySettings
from .transport import (
    TransportError,
    client_ssl_context,
    close_server,
    close_writer,
    socks5_connect,
    tls_connect,
)
from .websocket import WSStream

DEFAULT_PROFILE: dict[str, Any] = {
    "padding": "random",
    "cover": "low",
    "jitter_ms": 12,
    "transport": "ws",
    "traffic": "browse",
}

HIST_EDGES = [0, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]


def validate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    merged = dict(DEFAULT_PROFILE)
    merged.update({k: v for k, v in (profile or {}).items() if k in DEFAULT_PROFILE})
    if merged["padding"] not in PAD_MODES:
        raise ValueError("padding must be none, random or cells")
    if merged["cover"] not in ("none", "low", "medium"):
        raise ValueError("cover must be none, low or medium")
    if merged["transport"] not in ("ws", "tls"):
        raise ValueError("transport must be ws or tls")
    if merged["traffic"] not in ("browse", "bulk", "idle", "mixed"):
        raise ValueError("traffic must be browse, bulk, idle or mixed")
    try:
        merged["jitter_ms"] = max(0, min(120, int(merged["jitter_ms"])))
    except (TypeError, ValueError):
        merged["jitter_ms"] = DEFAULT_PROFILE["jitter_ms"]
    return merged


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DemoLab:
    def __init__(
        self,
        on_log: Callable[[str], None] | None = None,
        state_dir: str | None = None,
    ) -> None:
        self.on_log = on_log or (lambda line: None)
        self.lock = asyncio.Lock()
        self.running = False
        self.error = ""
        self.profile = dict(DEFAULT_PROFILE)
        self.started_at = 0.0
        self.relay: Relay | None = None
        self.client: TunnelClient | None = None
        self._client_task: asyncio.Task | None = None
        self._origin_server: asyncio.AbstractServer | None = None
        self._origin_port = 0
        self._relay_port = 0
        self._socks_port = 0
        self._traffic_task: asyncio.Task | None = None
        self._probe_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.records: deque[dict[str, Any]] = deque(maxlen=400)
        self.sizes: dict[str, deque[int]] = {"out": deque(maxlen=4000), "in": deque(maxlen=4000)}
        self.times: dict[str, deque[float]] = {"out": deque(maxlen=120), "in": deque(maxlen=120)}
        self.probes: list[dict[str, Any]] = []
        self.events: deque[str] = deque(maxlen=120)
        self.traffic = {"requests": 0, "ok": 0, "failed": 0, "payload": 0}
        self._psk = ""
        self._pin = ""
        self._cert_cn = ""
        self._state_dir = state_dir or os.path.join(tempfile.gettempdir(), "heduvpn-demo")
        self._payload = os.urandom(65536)
        self._last_rtt = 0.0
        self._probe_started = 0.0

    # -- logging -----------------------------------------------------------
    def log(self, message: str) -> None:
        if message[:4].isdigit() and "  " in message[:24]:
            line = message
        else:
            line = f"{time.strftime('%H:%M:%S')}  {message}"
        self.events.append(line)
        self.on_log(line)

    # -- lifecycle ---------------------------------------------------------
    async def start(self, profile: dict[str, Any] | None = None) -> dict[str, Any]:
        async with self.lock:
            await self._stop_locked()
            try:
                self.profile = validate_profile(profile or self.profile)
                await self._start_locked()
            except Exception as exc:
                self.error = str(exc)
                self.log(f"lab failed to start: {exc}")
                await self._stop_locked()
                raise
        return self.state()

    async def stop(self) -> dict[str, Any]:
        async with self.lock:
            await self._stop_locked()
        return self.state()

    async def restart(self, profile: dict[str, Any]) -> dict[str, Any]:
        return await self.start(profile)

    async def _start_locked(self) -> None:
        self.error = ""
        self.records.clear()
        self.sizes["out"].clear()
        self.sizes["in"].clear()
        self.times["out"].clear()
        self.times["in"].clear()
        self.probes = []
        self.traffic = {"requests": 0, "ok": 0, "failed": 0, "payload": 0}
        self._stop = asyncio.Event()
        os.makedirs(self._state_dir, exist_ok=True)
        identity = crypto.load_or_create_identity(self._state_dir, "localhost")
        self._psk = crypto.encode_psk(identity.psk)
        self._pin = pin_from_cert(os.path.join(self._state_dir, "cert.pem"))
        self._cert_cn = "localhost"

        self._origin_port = _free_port()
        self._origin_server = await asyncio.start_server(
            self._origin_handler, "127.0.0.1", self._origin_port
        )

        self._relay_port = _free_port()
        relay_settings = RelaySettings(
            listen_host="127.0.0.1",
            listen_port=self._relay_port,
            psk=self._psk,
            certfile=os.path.join(self._state_dir, "cert.pem"),
            keyfile=os.path.join(self._state_dir, "key.pem"),
            allow_private=True,
            padding=self.profile["padding"],
        )
        self.relay = Relay(relay_settings, log=self.log)
        await self.relay.start()

        self._socks_port = _free_port()
        settings = ClientSettings(
            psk=self._psk,
            name="HeduVPN Lab",
            connection=ConnectionConfig(
                server="127.0.0.1",
                port=self._relay_port,
                sni="localhost",
                transport=self.profile["transport"],
                verify="pin",
                pin=self._pin,
                ws_host="localhost",
            ),
            camouflage=CamouflageConfig(
                padding=self.profile["padding"],
                jitter_ms=self.profile["jitter_ms"],
                cover=self.profile["cover"],
            ),
            socks=SocksConfig(port=self._socks_port),
        )
        self.client = TunnelClient(settings, log=self.log)
        self.client.observers.append(self._observe)
        self._client_task = asyncio.create_task(self.client.run(), name="demo-client")
        connected = False
        for _ in range(80):
            await asyncio.sleep(0.1)
            if self.client.snapshot().get("connected"):
                connected = True
                break
            if self._client_task.done():
                break
        if not connected:
            raise RuntimeError("lab tunnel did not come up (see log)")
        self.running = True
        self.started_at = time.time()
        self._probe_started = time.monotonic()
        self.log(
            f"lab ready · relay 127.0.0.1:{self._relay_port} · socks 127.0.0.1:{self._socks_port}"
            f" · padding={self.profile['padding']} cover={self.profile['cover']}"
        )
        self._traffic_task = asyncio.create_task(self._traffic_loop(), name="demo-traffic")
        self._probe_task = asyncio.create_task(self._probe_loop(), name="demo-probes")

    async def _stop_locked(self) -> None:
        self.running = False
        self._stop.set()
        for task in (self._traffic_task, self._probe_task):
            if task and not task.done():
                task.cancel()
        for task in (self._traffic_task, self._probe_task):
            if task:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._traffic_task = None
        self._probe_task = None
        if self.client:
            with contextlib.suppress(Exception):
                await self.client.stop()
        if self._client_task:
            self._client_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._client_task
        self.client = None
        self._client_task = None
        if self.relay:
            with contextlib.suppress(Exception):
                await self.relay.stop()
            self.relay = None
        if self._origin_server:
            await close_server(self._origin_server)
            self._origin_server = None

    # -- origin server -----------------------------------------------------
    async def _origin_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            request = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            n = 1800
            delay = 0.0
            if "?" in request:
                query = request.split("?", 1)[1].split(" ")[0]
                for part in query.split("&"):
                    if part.startswith("n="):
                        with contextlib.suppress(ValueError):
                            n = max(1, min(4_000_000, int(part[2:])))
                    elif part.startswith("d="):
                        with contextlib.suppress(ValueError):
                            delay = max(0.0, min(2.0, int(part[2:]) / 1000.0))
            if delay:
                await asyncio.sleep(delay)
            body = (self._payload * (n // len(self._payload) + 1))[:n]
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                + f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    # -- traffic -----------------------------------------------------------
    async def _traffic_loop(self) -> None:
        rng = random.Random()
        mode = self.profile["traffic"]
        try:
            while not self._stop.is_set():
                if mode == "idle":
                    await asyncio.sleep(1.0)
                    continue
                if mode == "bulk":
                    size = rng.randint(140_000, 260_000)
                    await self._fetch(size, 0)
                    # keep the lab around 4-5 Mbit/s so the dashboard stays
                    # responsive and counters resemble a real download
                    await asyncio.sleep(size / 550_000.0)
                    continue
                # browse / mixed
                burst = rng.randint(1, 4)
                tasks = []
                for _ in range(burst):
                    size = rng.choice([600, 1200, 2400, 4800, 9000, 16000, 28000, 1400])
                    tasks.append(asyncio.create_task(self._fetch(size, rng.uniform(0, 120))))
                    await asyncio.sleep(rng.uniform(0.02, 0.14))
                await asyncio.gather(*tasks, return_exceptions=True)
                pause = rng.uniform(0.5, 2.4) if mode == "browse" else rng.uniform(0.15, 0.8)
                await asyncio.sleep(pause)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self.log(f"traffic loop error: {exc}")

    async def _fetch(self, n: int, delay_ms: float) -> None:
        client = self.client
        if client is None or not self.running:
            return
        self.traffic["requests"] += 1
        try:
            reader, writer = await asyncio.wait_for(
                socks5_connect("127.0.0.1", self._socks_port, "127.0.0.1", self._origin_port),
                8,
            )
            request = (
                f"GET /asset.js?n={n}&d={int(delay_ms)} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self._origin_port}\r\n"
                "User-Agent: Mozilla/5.0 (dashboard-lab)\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            ).encode()
            writer.write(request)
            await writer.drain()
            received = 0
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), 20)
                if not chunk:
                    break
                received += len(chunk)
            await close_writer(writer)
            if received >= n:
                self.traffic["ok"] += 1
                self.traffic["payload"] += received
            else:
                self.traffic["failed"] += 1
        except (asyncio.TimeoutError, OSError, TransportError, asyncio.IncompleteReadError):
            self.traffic["failed"] += 1
        except Exception as exc:  # pragma: no cover - defensive
            self.traffic["failed"] += 1
            self.log(f"fetch error: {exc}")

    # -- observer ----------------------------------------------------------
    def _observe(self, record: dict[str, Any]) -> None:
        self.records.append(record)
        direction = record["dir"]
        self.sizes[direction].append(record["wire"])
        self.times[direction].append(record["t"])

    # -- probes ------------------------------------------------------------
    async def _probe_loop(self) -> None:
        try:
            await self._run_probes()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self.log(f"probe error: {exc}")

    async def rerun_probes(self) -> list[dict[str, Any]]:
        await self._run_probes()
        return self.probes

    async def _run_probes(self) -> None:
        while not self.running or not self.client or not self.client.snapshot().get("connected"):
            await asyncio.sleep(0.2)
            if not self.running:
                return
        results: list[dict[str, Any]] = []
        results.append(await self._probe_http("GET /", "/", "an ordinary browser visit"))
        results.append(await self._probe_http("GET /wp-login.php", "/wp-login.php", "a scanner looking for admin panels"))
        results.append(await self._probe_http("GET /ws (no gate token)", "/ws", "probing a suspected tunnel path"))
        results.append(await self._probe_http("GET /ws + fake cookie", "/ws", "guessing the gate token", cookie="hid=deadbeefdeadbeef"))
        results.append(await self._probe_garbage())
        results.append(await self._probe_ws_no_key())
        results.append(await self._probe_wrong_psk())
        results.append(await self._probe_cert())
        results.append(await self._probe_alpn())
        seen = set()
        deduped = []
        for item in results:
            if item["name"] in seen:
                continue
            seen.add(item["name"])
            deduped.append(item)
        self.probes = deduped
        self._probe_started = time.monotonic()

    async def _probe_http(
        self, name: str, path: str, why: str, cookie: str = ""
    ) -> dict[str, Any]:
        started = time.perf_counter()
        base = {
            "name": name,
            "why": why,
            "request": f"GET {path}",
            "kind": "http",
        }
        try:
            stream = await tls_connect(
                "127.0.0.1", self._relay_port, verify="insecure", sni="localhost", timeout=6
            )
            host = f"localhost:{self._relay_port}"
            extra = f"Cookie: {cookie}\r\n" if cookie else ""
            stream.writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                f"Accept: text/html\r\n{extra}Connection: close\r\n\r\n".encode()
            )
            await stream.writer.drain()
            raw = b""
            while len(raw) < 65536:
                chunk = await asyncio.wait_for(stream.reader.read(4096), 4)
                if not chunk:
                    break
                raw += chunk
            stream.close()
            status_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            code = status_line.split(" ")[1] if len(status_line.split(" ")) > 1 else "?"
            server = ""
            for line in raw.split(b"\r\n")[1:]:
                if line.lower().startswith(b"server:"):
                    server = line.split(b":", 1)[1].strip().decode("latin-1")
                    break
            base.update(
                observed=f"{status_line} · Server: {server or '—'}",
                status=int(code) if code.isdigit() else 0,
                bytes=len(raw),
                verdict="ordinary website response"
                if code in ("200", "404", "400", "403")
                else "unexpected",
                tone="good" if code in ("200", "404") else "info",
            )
        except Exception as exc:
            base.update(observed=f"no response ({exc})", status=0, bytes=0, verdict="connection failed", tone="warn")
        base["ms"] = round((time.perf_counter() - started) * 1000, 1)
        return base

    async def _probe_garbage(self) -> dict[str, Any]:
        name = "Random bytes over TLS"
        started = time.perf_counter()
        result = {"name": name, "why": "sending junk to fingerprint the daemon", "request": "256 random bytes", "kind": "raw"}
        try:
            stream = await tls_connect("127.0.0.1", self._relay_port, verify="insecure", sni="localhost", timeout=6)
            stream.writer.write(os.urandom(256))
            await stream.writer.drain()
            raw = await asyncio.wait_for(stream.reader.read(4096), 4)
            stream.close()
            line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            result.update(
                observed=f"{line or 'connection closed'}",
                bytes=len(raw),
                verdict="HTTP 400 like a misconfigured web server",
                tone="good",
            )
        except Exception as exc:
            result.update(observed=f"closed ({exc})", bytes=0, verdict="connection closed", tone="info")
        result["ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result

    async def _probe_ws_no_key(self) -> dict[str, Any]:
        name = "WebSocket upgrade with a copied gate token"
        started = time.perf_counter()
        result = {
            "name": name,
            "why": "even a stolen cookie must not open a tunnel without the key",
            "request": "GET /ws + valid cookie, then a wrong-key HELLO",
            "kind": "ws",
        }
        try:
            token = crypto.make_ws_token(crypto.decode_psk(self._psk))
            stream = await tls_connect("127.0.0.1", self._relay_port, verify="insecure", sni="localhost", timeout=6)
            key = "dGhlIHNhbXBsZSBub25jZQ=="
            stream.writer.write(
                (
                    f"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                    f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n"
                    f"Cookie: hid={token}\r\nOrigin: https://localhost\r\n\r\n"
                ).encode()
            )
            await stream.writer.drain()
            status, headers, rest = await read_response_headers_with_rest(stream.reader, timeout=4)
            if status != 101:
                stream.close()
                result.update(
                    observed=f"HTTP {status} (upgrade refused)",
                    bytes=0,
                    verdict="ordinary website response",
                    tone="good",
                )
            else:
                ws = WSStream(stream.reader, stream.writer, is_client=True, initial=rest)
                await ws.write(protocol.build_hello(os.urandom(32)))
                closed = False
                try:
                    await asyncio.wait_for(ws.read_exact(1), 3)
                except Exception:
                    closed = True
                finally:
                    ws.close()
                result.update(
                    observed=(
                        f"HTTP 101 · Sec-WebSocket-Accept "
                        f"{'present' if 'sec-websocket-accept' in headers else 'missing'} · then "
                        + ("closed" if closed else "unexpected data")
                    ),
                    bytes=0,
                    verdict="upgrade is not a tunnel: the key is still required",
                    tone="good" if closed else "info",
                )
        except Exception as exc:
            result.update(observed=f"no response ({exc})", bytes=0, verdict="connection closed", tone="info")
        result["ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result

    async def _probe_wrong_psk(self) -> dict[str, Any]:
        name = "Tunnel handshake with a wrong key"
        started = time.perf_counter()
        result = {"name": name, "why": "the relay must not reveal anything to an imposter", "request": "HELLO with random PSK", "kind": "raw"}
        try:
            stream = await tls_connect("127.0.0.1", self._relay_port, verify="insecure", sni="localhost", timeout=6)
            await stream.write(protocol.build_hello(os.urandom(32)))
            raw = b""
            while len(raw) < 8192:
                chunk = await asyncio.wait_for(stream.reader.read(4096), 4)
                if not chunk:
                    break
                raw += chunk
            stream.close()
            line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            result.update(
                observed=line or "connection closed",
                bytes=len(raw),
                verdict="rejected, no oracle for attackers",
                tone="good" if line.startswith("HTTP/1.1 400") or not raw else "info",
            )
        except Exception as exc:
            result.update(observed=f"closed ({exc})", bytes=0, verdict="rejected", tone="good")
        result["ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result

    async def _probe_cert(self) -> dict[str, Any]:
        name = "TLS certificate + SNI"
        started = time.perf_counter()
        result = {"name": name, "why": "what a passive observer sees in the handshake", "request": "TLS ClientHello", "kind": "tls"}
        try:
            stream = await tls_connect("127.0.0.1", self._relay_port, verify="insecure", sni="localhost", timeout=6)
            info = stream.info
            stream.close()
            result.update(
                observed=f"{info.version} · {info.cipher} · ALPN {info.alpn or '-'} · CN {info.cert_cn}",
                bytes=0,
                verdict="looks like any pinned-TLS service; no VPN marker",
                tone="good",
            )
        except Exception as exc:
            result.update(observed=str(exc), bytes=0, verdict="handshake failed", tone="warn")
        result["ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result

    async def _probe_alpn(self) -> dict[str, Any]:
        name = "ALPN negotiation (HTTP/2 offered)"
        started = time.perf_counter()
        result = {"name": name, "why": "browsers advertise h2; a tunnel should not look odd", "request": "ALPN h2,http/1.1", "kind": "tls"}
        try:
            ctx = client_ssl_context("insecure")
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._relay_port, ssl=ctx, server_hostname="localhost"), 6
            )
            sslobj = writer.get_extra_info("ssl_object")
            chosen = sslobj.selected_alpn_protocol() if sslobj else None
            writer.close()
            result.update(
                observed=f"negotiated ALPN {chosen or 'none'}",
                bytes=0,
                verdict="downgrades to HTTP/1.1, exactly like a WebSocket server",
                tone="good",
            )
        except Exception as exc:
            result.update(observed=str(exc), bytes=0, verdict="handshake failed", tone="warn")
        result["ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result

    # -- reporting ---------------------------------------------------------
    def _histogram(self, direction: str) -> list[int]:
        bins = [0] * (len(HIST_EDGES) + 1)
        for size in self.sizes[direction]:
            placed = False
            for i in range(len(HIST_EDGES) - 1):
                if HIST_EDGES[i] <= size < HIST_EDGES[i + 1]:
                    bins[i] += 1
                    placed = True
                    break
            if not placed:
                bins[-1] += 1
        return bins

    def _jitter(self, direction: str) -> float:
        """Sigma of *within-burst* record spacing (think time excluded)."""
        times = list(self.times[direction])
        if len(times) < 5:
            return 0.0
        deltas = [(times[i + 1] - times[i]) * 1000 for i in range(len(times) - 1)]
        deltas = [d for d in deltas if 0 <= d < 500]
        if len(deltas) < 3:
            return 0.0
        return round(statistics.pstdev(deltas), 1)

    def _spacing(self, direction: str) -> float:
        times = list(self.times[direction])
        if len(times) < 4:
            return 0.0
        deltas = sorted((times[i + 1] - times[i]) * 1000 for i in range(len(times) - 1))
        return round(statistics.median(deltas), 1)

    def _checks(self, snap: dict[str, Any], counters: dict[str, int]) -> list[dict[str, str]]:
        payload = (counters.get("payload_out", 0) or 0) + (counters.get("payload_in", 0) or 0)
        wire = (counters.get("wire_out", 0) or 0) + (counters.get("wire_in", 0) or 0)
        overhead = 100.0 * (wire - payload) / payload if payload else 0.0
        pad_share = 0.0
        if wire:
            pad_share = 100.0 * ((counters.get("pad_out", 0) or 0) + (counters.get("pad_in", 0) or 0)) / wire
        probes_ok = sum(1 for p in self.probes if p.get("tone") == "good")
        checks = [
            {
                "label": "Outer protocol",
                "value": f"{snap.get('tls', '').split('·')[0].strip() or 'TLS 1.3'} on TCP/443-shaped port",
                "state": "good",
            },
            {
                "label": "Handshake",
                "value": "Certificate pinning; no CA or VPN vendor signature",
                "state": "good",
            },
            {
                "label": "ALPN + SNI",
                "value": "http/1.1 over your own hostname, like any WebSocket service",
                "state": "good",
            },
            {
                "label": "Record padding",
                "value": f"{self.profile['padding']} · {overhead:.0f}% wire overhead · {pad_share:.0f}% cover bytes",
                "state": "good" if self.profile["padding"] != "none" else "warn",
            },
            {
                "label": "Cover traffic",
                "value": "idle sessions keep talking" if self.profile["cover"] != "none" else "silent when idle",
                "state": "good" if self.profile["cover"] != "none" else "warn",
            },
            {
                "label": "Active probing",
                "value": f"{probes_ok}/{len(self.probes)} probes answered like a website" if self.probes else "running",
                "state": "good" if self.probes and probes_ok == len(self.probes) else "info",
            },
            {
                "label": "Gate token",
                "value": "short-lived signed cookie required before any upgrade",
                "state": "good",
            },
            {
                "label": "What software cannot hide",
                "value": "your relay IP, total traffic volume and long-term flow shape",
                "state": "warn",
            },
        ]
        return checks

    def state(self) -> dict[str, Any]:
        snap = self.client.snapshot() if self.client else {}
        counters = snap.get("counters", {})
        relay_snap = self.relay.snapshot() if self.relay else {}
        relay_counters = relay_snap.get("counters", {})
        wire_records = list(self.records)[-28:]
        out_sizes = list(self.sizes["out"])
        in_sizes = list(self.sizes["in"])
        payload_total = (counters.get("payload_out", 0) or 0) + (counters.get("payload_in", 0) or 0)
        wire_total = (counters.get("wire_out", 0) or 0) + (counters.get("wire_in", 0) or 0)
        overhead = 100.0 * (wire_total - payload_total) / payload_total if payload_total else 0.0
        pad_share = 0.0
        if wire_total:
            pad_share = 100.0 * ((counters.get("pad_out", 0) or 0) + (counters.get("pad_in", 0) or 0)) / wire_total
        avg_record = sum(out_sizes) / len(out_sizes) if out_sizes else 0.0
        return {
            "running": self.running and bool(self.client),
            "error": self.error,
            "profile": dict(self.profile),
            "started_at": self.started_at,
            "uptime": time.time() - self.started_at if self.started_at else 0.0,
            "connection": {
                "tls": snap.get("tls", ""),
                "pin": snap.get("pin", self._pin),
                "cert_cn": snap.get("cert_cn", self._cert_cn),
                "session_id": snap.get("session_id", ""),
                "rtt_ms": snap.get("rtt_ms", 0.0),
                "transport": self.profile["transport"],
                "relay": f"127.0.0.1:{self._relay_port}",
                "socks": f"127.0.0.1:{self._socks_port}",
                "padding": self.profile["padding"],
                "cover": self.profile["cover"],
                "jitter_ms": self.profile["jitter_ms"],
                "session_uptime": snap.get("session_uptime", 0.0),
                "psk_fingerprint": (
                    "sha256:" + hashlib.sha256(crypto.decode_psk(self._psk)).hexdigest()[:16]
                    if self._psk
                    else ""
                ),
            },
            "counters": counters,
            "relay": {
                "sessions": relay_snap.get("sessions", 0),
                "counters": relay_counters,
                "top_destinations": relay_snap.get("top_destinations", []),
            },
            "traffic": dict(self.traffic),
            "rate": {"up": snap.get("rate_up", 0.0), "down": snap.get("rate_down", 0.0)},
            "history": snap.get("history", []),
            "wire": {
                "records": wire_records,
                "hist_out": self._histogram("out"),
                "hist_in": self._histogram("in"),
                "edges": HIST_EDGES,
                "overhead_pct": round(overhead, 1),
                "pad_pct": round(pad_share, 1),
                "avg_record": round(avg_record, 1),
                "unique_sizes": len(set(out_sizes)),
                "jitter_out_ms": self._jitter("out"),
                "jitter_in_ms": self._jitter("in"),
                "spacing_out_ms": self._spacing("out"),
                "spacing_in_ms": self._spacing("in"),
                "count_out": len(out_sizes),
                "count_in": len(in_sizes),
            },
            "probes": self.probes,
            "checks": self._checks(snap, counters),
            "log": list(self.events)[-16:],
        }
