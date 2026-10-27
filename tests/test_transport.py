"""STARTTLS must work on every supported Python.

``StreamWriter.start_tls()`` only exists from 3.11 on, so ``tls_upgrade()`` has
a fallback that performs the same steps on 3.10.  Both paths are exercised
here: the native one, and the fallback with ``start_tls`` removed from the
class (which is exactly what a 3.10 interpreter looks like).
"""

import asyncio
import contextlib

import pytest

from heduvpn import crypto
from heduvpn.link import pin_from_cert
from heduvpn.transport import (
    TransportError,
    close_server,
    close_writer,
    server_ssl_context,
    tls_upgrade,
)
from tests.util import run


async def _start_tls_server(tmp_path):
    target = "docs.example.test"
    crypto.load_or_create_identity(str(tmp_path), target)
    certfile = str(tmp_path / "cert.pem")
    keyfile = str(tmp_path / "key.pem")
    ctx = server_ssl_context(certfile, keyfile)

    async def handler(reader, writer):
        try:
            data = await asyncio.wait_for(reader.readexactly(4), 5)
            writer.write(b"pong:" + data)
            await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port, pin_from_cert(certfile)


async def _upgrade_and_ping(port: int, pin: str, verify: str = "pin") -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = await tls_upgrade(
        reader, writer, verify=verify, pin=pin, sni="docs.example.test", timeout=8
    )
    await stream.write(b"ping")
    reply = await asyncio.wait_for(stream.reader.readexactly(9), 5)
    await close_writer(stream.writer)
    return reply


def test_tls_upgrade_native_path(tmp_path):
    """Upgrade a plain TCP stream to TLS on whichever path the runtime has."""

    async def scenario():
        server, port, pin = await _start_tls_server(tmp_path)
        try:
            assert await _upgrade_and_ping(port, pin) == b"pong:ping"
        finally:
            await close_server(server)

    run(scenario())


def test_tls_upgrade_fallback_without_start_tls(tmp_path, monkeypatch):
    """Exercise the shim.

    On 3.11+ ``StreamWriter.start_tls`` is removed to emulate a 3.10 interpreter;
    on a genuine 3.10 the shim is already the only path, so there is nothing to
    remove and the test simply covers it as-is.
    """

    async def scenario():
        server, port, pin = await _start_tls_server(tmp_path)
        try:
            monkeypatch.delattr(asyncio.StreamWriter, "start_tls", raising=False)
            try:
                assert await _upgrade_and_ping(port, pin) == b"pong:ping"
            finally:
                monkeypatch.undo()
        finally:
            await close_server(server)

    run(scenario())


def test_pin_mismatch_fails_closed_on_both_paths(tmp_path, monkeypatch):
    async def scenario():
        server, port, pin = await _start_tls_server(tmp_path)
        wrong = "sha256:" + "00" * 32
        try:
            with pytest.raises(TransportError, match="pin mismatch"):
                await _upgrade_and_ping(port, wrong)

            monkeypatch.delattr(asyncio.StreamWriter, "start_tls", raising=False)
            try:
                with pytest.raises(TransportError, match="pin mismatch"):
                    await _upgrade_and_ping(port, wrong)
            finally:
                monkeypatch.undo()
        finally:
            await close_server(server)

    run(scenario())


def test_insecure_upgrade_still_negotiates_tls(tmp_path):
    async def scenario():
        server, port, _pin = await _start_tls_server(tmp_path)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            stream = await tls_upgrade(
                reader, writer, verify="insecure", sni="docs.example.test", timeout=8
            )
            assert stream.info.version.startswith("TLSv1")
            assert stream.info.alpn == "http/1.1"
            await stream.write(b"abcd")
            assert await asyncio.wait_for(stream.reader.readexactly(9), 5) == b"pong:abcd"
            await close_writer(stream.writer)
        finally:
            await close_server(server)

    run(scenario())
