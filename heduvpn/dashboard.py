"""Zero-dependency web dashboard.

Serves a single-page UI from ``heduvpn/web`` plus a small JSON API.  The
dashboard is also a real control panel: it can host the loopback traffic
laboratory, a live relay (``--relay-config``) and a live client (after a
connection link is imported).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import platform
import time
from collections import deque
from pathlib import Path
from typing import Any

from . import __version__
from .client import TunnelClient
from .config import ClientSettings, ConfigError
from .demo import DemoLab
from .httpwire import HttpError, read_request
from .link import LinkError, decode_link, encode_link, summarize_link
from .relay import Relay, RelayError, load_relay_config
from .systemproxy import SystemProxy
from .transport import close_server

WEB_ROOT = Path(__file__).resolve().parent / "web"
MAX_BODY = 512 * 1024


class Dashboard:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        relay_config: str = "",
        client_config: str = "",
        client_link: str = "",
        start_lab: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.relay_config = relay_config
        self.logs: deque[str] = deque(maxlen=500)
        self.lab = DemoLab(on_log=self.record_log)
        self.relay: Relay | None = None
        self.client: TunnelClient | None = None
        self.client_task: asyncio.Task | None = None
        self.client_settings: ClientSettings | None = None
        self.client_config_path = client_config
        self.client_link = client_link
        self.proxy = SystemProxy(log=self.record_log)
        self._proxy_owned = False
        self._proxy_supported, self._proxy_note = self.proxy.support()
        self._server: asyncio.AbstractServer | None = None
        self._start_lab = start_lab
        self._error = ""
        self.startup = time.time()

    # -- logging -----------------------------------------------------------
    def record_log(self, line: str) -> None:
        self.logs.append(line)

    def log(self, message: str) -> None:
        line = f"{time.strftime('%H:%M:%S')}  {message}"
        self.logs.append(line)
        print(line, flush=True)

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        if self.proxy.pending_snapshot():
            if self._proxy_supported:
                self.log("restoring system proxy settings left over from an earlier run")
                result = self.proxy.disable()
                if not result.ok:
                    self.log(f"could not restore the system proxy: {result.message}")
            else:
                self.log(
                    "a system proxy snapshot is saved but cannot be restored here; "
                    "run `heduvpn system-proxy off` on the machine that set it"
                )
        if self.relay_config:
            try:
                cfg = load_relay_config(self.relay_config)
                self.relay = Relay(cfg, log=self.record_log)
                await self.relay.start()
                self.log(f"live relay started from {self.relay_config}")
            except (RelayError, OSError) as exc:
                self._error = f"relay: {exc}"
                self.log(f"could not start relay: {exc}")
        if self.client_config_path or self.client_link:
            try:
                if self.client_link:
                    settings = decode_link(self.client_link)
                else:
                    settings = ClientSettings.load(self.client_config_path)
                self.client_settings = settings
                self.log(f"loaded client settings for {settings.connection.server}")
            except (LinkError, ConfigError, OSError) as exc:
                self._error = f"client config: {exc}"
                self.log(f"could not load client settings: {exc}")
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sockets = ", ".join(str(s.getsockname()) for s in self._server.sockets or [])
        self.log(f"dashboard listening on {sockets}")
        if self._start_lab:
            try:
                await self.lab.start()
            except Exception as exc:  # keep the dashboard usable even if the lab fails
                self.log(f"demo lab failed to start: {exc}")

    async def stop(self) -> None:
        if self._server:
            await close_server(self._server)
            self._server = None
        await self.stop_client()
        await self._stop_lab_quietly()
        if self.relay:
            await self.relay.stop()
            self.relay = None

    async def _stop_lab_quietly(self) -> None:
        with contextlib.suppress(Exception):
            await self.lab.stop()

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

    # -- client control ----------------------------------------------------
    async def start_client(self) -> dict[str, Any]:
        if self.client and self.client.snapshot()["connected"]:
            return self.client.snapshot()
        if not self.client_settings:
            raise ValueError("import a connection link first")
        if self.client_task:
            await self.stop_client()
        self.client = TunnelClient(self.client_settings, log=self.log)
        self.client_task = asyncio.create_task(self.client.run(), name="dashboard-client")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            await asyncio.sleep(0.2)
            snap = self.client.snapshot()
            if snap["connected"]:
                return snap
            if snap["state"] == "reconnecting" and time.monotonic() > deadline - 15:
                break
        snap = self.client.snapshot()
        await self.stop_client()
        raise ValueError(snap.get("last_error") or "could not establish the tunnel")

    async def stop_client(self) -> None:
        if self._proxy_owned:
            result = self.proxy.disable()
            self.log(f"system proxy: {result.message}")
            self._proxy_owned = False
        if self.client:
            with contextlib.suppress(Exception):
                await self.client.stop()
        if self.client_task:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self.client_task
        self.client_task = None
        self.client = None

    def import_link(self, link: str) -> dict[str, Any]:
        settings = decode_link(link)
        if self.client_settings:
            # keep local proxy preferences from the previous import
            settings.socks = self.client_settings.socks
        self.client_settings = settings
        summary = summarize_link(encode_link(settings))
        summary["socks_port"] = str(settings.socks.port)
        summary["name"] = settings.name
        self.log(f"imported connection link for {settings.connection.server}")
        return summary

    # -- HTTP --------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await read_request(reader, timeout=15)
            body = b""
            length = int(request.get("content-length") or 0)
            if length:
                if length > MAX_BODY:
                    await self._json(writer, {"error": "body too large"}, 413)
                    return
                body = request.rest[:length]
                if len(body) < length:
                    body += await asyncio.wait_for(reader.readexactly(length - len(body)), 15)
                body = body[:length]
            await self._route(request, body, writer)
        except (HttpError, asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            with contextlib.suppress(Exception):
                writer.close()
        except Exception as exc:  # pragma: no cover - defensive
            self.log(f"dashboard handler error: {exc}")
            with contextlib.suppress(Exception):
                await self._json(writer, {"error": str(exc)}, 500)

    async def _route(self, request, body: bytes, writer: asyncio.StreamWriter) -> None:
        path = request.path
        method = request.method
        if method == "GET" and path == "/":
            await self._file(writer, "index.html", "text/html; charset=utf-8")
            return
        if method == "GET" and path.startswith("/static/"):
            name = path[len("/static/") :]
            if "/" in name or ".." in name:
                await self._json(writer, {"error": "not found"}, 404)
                return
            content_type = {
                ".js": "application/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".svg": "image/svg+xml",
                ".png": "image/png",
                ".ico": "image/x-icon",
            }.get(Path(name).suffix, "application/octet-stream")
            await self._file(writer, name, content_type)
            return
        if method == "GET" and path == "/api/health":
            await self._json(writer, {"ok": True, "version": __version__})
            return
        if method == "GET" and path == "/api/state":
            await self._json(writer, self.state())
            return
        if method == "GET" and path == "/api/logs":
            await self._json(writer, {"logs": list(self.logs)[-200:]})
            return
        if method == "GET" and path == "/api/proxy":
            settings = self.client_settings
            status = self.proxy.status()
            status.update(
                {
                    "owned": self._proxy_owned,
                    "supported": self._proxy_supported,
                    "note": self._proxy_note,
                    "socks": (
                        f"{settings.socks.host}:{settings.socks.port}" if settings else ""
                    ),
                }
            )
            await self._json(writer, status)
            return
        if method == "GET" and path == "/api/config/export":
            if not self.client_settings:
                await self._json(writer, {"error": "no client configuration imported"}, 404)
                return
            payload = self.client_settings.to_json()
            headers = {
                "Content-Type": "application/json",
                "Content-Disposition": 'attachment; filename="heduvpn-client.json"',
            }
            await self._respond(writer, payload.encode(), headers=headers)
            return
        if method == "POST":
            data = await self._parse_json(body, writer)
            if data is None:
                return
            if path == "/api/lab/start":
                try:
                    state = await self.lab.start(data)
                except Exception as exc:
                    await self._json(writer, {"error": str(exc)}, 400)
                    return
                await self._json(writer, {"ok": True, "lab": state})
                return
            if path == "/api/lab/stop":
                await self._json(writer, {"ok": True, "lab": await self.lab.stop()})
                return
            if path == "/api/lab/probe":
                probes = await self.lab.rerun_probes()
                await self._json(writer, {"ok": True, "probes": probes})
                return
            if path == "/api/link":
                link = str(data.get("link", ""))
                try:
                    summary = self.import_link(link)
                except (LinkError, ConfigError) as exc:
                    await self._json(writer, {"error": str(exc)}, 400)
                    return
                await self._json(writer, {"ok": True, "summary": summary})
                return
            if path == "/api/client/start":
                try:
                    snap = await self.start_client()
                except ValueError as exc:
                    await self._json(writer, {"error": str(exc)}, 400)
                    return
                await self._json(writer, {"ok": True, "client": snap})
                return
            if path == "/api/client/stop":
                await self.stop_client()
                await self._json(writer, {"ok": True})
                return
            if path == "/api/proxy/enable":
                if not self.client_settings:
                    await self._json(writer, {"error": "import a connection link first"}, 400)
                    return
                if not (self.client and self.client.snapshot()["connected"]):
                    await self._json(writer, {"error": "connect the tunnel first"}, 400)
                    return
                host = self.client_settings.socks.host
                if host in ("0.0.0.0", "::"):
                    host = "127.0.0.1"
                if host not in ("127.0.0.1", "localhost", "::1"):
                    await self._json(writer, {"error": "the system proxy needs a loopback SOCKS listener"}, 400)
                    return
                result = self.proxy.enable(host, self.client_settings.socks.port)
                if result.ok:
                    self._proxy_owned = True
                await self._json(
                    writer,
                    {"ok": result.ok, "message": result.message, "status": self.proxy.status()},
                    200 if result.ok else 400,
                )
                return
            if path == "/api/proxy/disable":
                result = self.proxy.disable()
                if result.ok:
                    self._proxy_owned = False
                await self._json(
                    writer,
                    {"ok": result.ok, "message": result.message, "status": self.proxy.status()},
                    200 if result.ok else 400,
                )
                return
        await self._json(writer, {"error": "not found"}, 404)

    async def _parse_json(self, body: bytes, writer: asyncio.StreamWriter) -> dict[str, Any] | None:
        if not body:
            return {}
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            await self._json(writer, {"error": "invalid JSON body"}, 400)
            return None
        if not isinstance(data, dict):
            await self._json(writer, {"error": "expected a JSON object"}, 400)
            return None
        return data

    # -- responses ---------------------------------------------------------
    async def _json(self, writer: asyncio.StreamWriter, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, separators=(",", ":"), default=str).encode()
        await self._respond(
            writer,
            payload,
            status=status,
            headers={"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"},
        )

    async def _file(self, writer: asyncio.StreamWriter, name: str, content_type: str) -> None:
        path = WEB_ROOT / name
        if not path.is_file():
            await self._json(writer, {"error": "asset missing", "name": name}, 404)
            return
        payload = path.read_bytes()
        await self._respond(
            writer,
            payload,
            headers={"Content-Type": content_type, "Cache-Control": "no-cache"},
        )

    async def _respond(
        self,
        writer: asyncio.StreamWriter,
        payload: bytes,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 413: "Payload Too Large", 500: "Internal Server Error"}.get(status, "OK")
        lines = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Length: {len(payload)}",
            "Connection: close",
            "X-Content-Type-Options: nosniff",
            "Referrer-Policy: no-referrer",
        ]
        for key, value in (headers or {}).items():
            lines.append(f"{key}: {value}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        writer.write(head + payload)
        await writer.drain()
        with contextlib.suppress(Exception):
            writer.close()

    # -- state -------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        lab = self.lab.state()
        relay_snap = self.relay.snapshot() if self.relay else None
        client_snap = self.client.snapshot() if self.client else None
        return {
            "lab": lab,
            "live": {
                "relay": relay_snap,
                "relay_config": self.relay_config,
                "client": client_snap,
                "client_ready": self.client_settings is not None,
                "system_proxy": {
                    "supported": self._proxy_supported,
                    "enabled": self._proxy_owned,
                    "restore_pending": self.proxy.pending_snapshot(),
                    "note": self._proxy_note,
                },
                "client_config": (
                    {
                        "name": self.client_settings.name,
                        "server": self.client_settings.connection.server,
                        "port": self.client_settings.connection.port,
                        "socks": f"{self.client_settings.socks.host}:{self.client_settings.socks.port}",
                        "http_proxy": (
                            f"{self.client_settings.socks.host}:{self.client_settings.socks.proxy_port}"
                            if self.client_settings.socks.proxy_port
                            else ""
                        ),
                    }
                    if self.client_settings
                    else None
                ),
            },
            "meta": {
                "version": __version__,
                "python": platform.python_version(),
                "system": f"{platform.system()} {platform.release()}",
                "listen": f"{self.host}:{self.port}",
                "uptime": time.time() - self.startup,
                "error": self._error,
            },
        }


async def run_dashboard(args) -> int:
    dashboard = Dashboard(
        host=args.host,
        port=args.port,
        relay_config=args.relay_config or "",
        client_config=args.client_config or "",
        client_link=args.link or "",
        start_lab=not args.no_lab,
    )
    print(f"HeduVPN dashboard → http://{args.host}:{args.port}", flush=True)
    try:
        await dashboard.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        await dashboard.stop()
    return 0
