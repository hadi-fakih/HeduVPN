"""Shared helpers for the HeduVPN test suite."""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from dataclasses import dataclass

from heduvpn import crypto
from heduvpn.client import TunnelClient
from heduvpn.config import CamouflageConfig, ClientSettings, ConnectionConfig, SocksConfig
from heduvpn.link import pin_from_cert
from heduvpn.relay import Relay, RelaySettings
from heduvpn.transport import close_server, close_writer, socks5_connect


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(coro):
    return asyncio.run(coro)


async def wait_connected(client: TunnelClient, timeout: float = 15.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if client.snapshot().get("connected"):
            return True
        await asyncio.sleep(0.05)
    return False


@dataclass
class Env:
    relay: Relay
    client: TunnelClient
    settings: ClientSettings
    origin_port: int
    workdir: str
    client_task: asyncio.Task
    origin_server: asyncio.AbstractServer
    origin_payload: bytes

    async def fetch(self, size: int = 1024, path: str = "/") -> bytes:
        reader, writer = await asyncio.wait_for(
            socks5_connect(self.settings.socks.host, self.settings.socks.port, "127.0.0.1", self.origin_port),
            10,
        )
        writer.write(
            f"GET {path}?n={size} HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 20)
        await close_writer(writer)
        return data.split(b"\r\n\r\n", 1)[1]


def _origin_handler(payload: bytes):
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            size = 1024
            line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if "n=" in line:
                with contextlib.suppress(ValueError):
                    size = max(1, min(2_000_000, int(line.split("n=")[1].split(" ")[0].split("&")[0])))
            body = (payload * (size // len(payload) + 1))[:size]
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    return handler


@contextlib.asynccontextmanager
async def lab_env(
    tmp_path,
    transport: str = "ws",
    padding: str = "random",
    allow_private: bool = True,
    rotate_minutes: float = 0,
    cover: str = "none",
    relay_port: int | None = None,
    http_proxy: bool = False,
):
    workdir = str(tmp_path)
    identity = crypto.load_or_create_identity(workdir, "localhost")
    psk = crypto.encode_psk(identity.psk)
    pin = pin_from_cert(os.path.join(workdir, "cert.pem"))
    origin_port = free_port()
    payload = os.urandom(4096)
    origin = await asyncio.start_server(_origin_handler(payload), "127.0.0.1", origin_port)
    port = relay_port or free_port()
    relay = Relay(
        RelaySettings(
            listen_host="127.0.0.1",
            listen_port=port,
            psk=psk,
            certfile=os.path.join(workdir, "cert.pem"),
            keyfile=os.path.join(workdir, "key.pem"),
            allow_private=allow_private,
            padding="random",
        )
    )
    await relay.start()
    settings = ClientSettings(
        psk=psk,
        connection=ConnectionConfig(
            server="127.0.0.1",
            port=port,
            sni="localhost",
            transport=transport,
            verify="pin",
            pin=pin,
            ws_host="localhost",
        ),
        camouflage=CamouflageConfig(
            padding=padding, jitter_ms=0, cover=cover, rotate_minutes=rotate_minutes
        ),
        socks=SocksConfig(port=free_port(), proxy_port=free_port() if http_proxy else 0),
    )
    client = TunnelClient(settings)
    task = asyncio.create_task(client.run())
    try:
        if not await wait_connected(client):
            detail = client.snapshot().get("last_error", "")
            raise AssertionError(f"tunnel did not connect: {detail}")
        yield Env(relay, client, settings, origin_port, workdir, task, origin, payload)
    finally:
        with contextlib.suppress(Exception):
            await client.stop()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, 10)
        with contextlib.suppress(Exception):
            if not task.done():
                task.cancel()
        with contextlib.suppress(Exception):
            await relay.stop()
        await close_server(origin)
