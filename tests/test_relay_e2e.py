import asyncio
import os

import pytest

from heduvpn import crypto, protocol
from heduvpn.relay import Relay, RelaySettings
from heduvpn.httpwire import read_response_headers_with_rest
from heduvpn.transport import Socks5Error, close_writer, socks5_connect, tls_connect
from heduvpn.websocket import client_handshake
from tests.util import free_port, lab_env, run


async def https_exchange(port: int, request: bytes, timeout: float = 6.0) -> bytes:
    stream = await tls_connect("127.0.0.1", port, verify="insecure", sni="localhost", timeout=8)
    try:
        stream.writer.write(request)
        await stream.writer.drain()
        data = b""
        while len(data) < 200_000:
            chunk = await asyncio.wait_for(stream.reader.read(4096), timeout)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        stream.close()


async def https_headers(port: int, request: bytes, timeout: float = 6.0) -> tuple[int, dict]:
    stream = await tls_connect("127.0.0.1", port, verify="insecure", sni="localhost", timeout=8)
    try:
        stream.writer.write(request)
        await stream.writer.drain()
        status, headers, _rest = await read_response_headers_with_rest(stream.reader, timeout=timeout)
        return status, headers
    finally:
        stream.close()


@pytest.mark.parametrize("transport", ["ws", "tls"])
def test_tunnel_transfers(transport, tmp_path):
    async def scenario():
        async with lab_env(tmp_path, transport=transport) as env:
            body = await env.fetch(4096)
            assert body == env.origin_payload
            bigger = await env.fetch(1_000_000)
            assert len(bigger) == 1_000_000
            assert bigger == (env.origin_payload * 245)[:1_000_000]
            assert env.client.snapshot()["connected"]

    run(scenario())


def test_decoys_look_like_a_website(tmp_path):
    async def scenario():
        async with lab_env(tmp_path) as env:
            port = env.settings.connection.port
            home = await https_exchange(
                port, b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n"
            )
            assert home.startswith(b"HTTP/1.1 200 OK\r\n")
            assert b"Server: nginx/" in home
            assert b"HeduVPN" not in home and b"VPN" not in home.split(b"\r\n\r\n")[0]
            missing = await https_exchange(
                port, b"GET /wp-admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            assert missing.startswith(b"HTTP/1.1 404 Not Found\r\n")
            junk = await https_exchange(port, os.urandom(256))
            assert junk.startswith(b"HTTP/1.1 400 Bad Request\r\n")
            ws_probe = await https_exchange(
                port,
                b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n\r\n",
            )
            assert ws_probe.startswith(b"HTTP/1.1 404 Not Found\r\n")

    run(scenario())


def test_ws_gate_token_required(tmp_path):
    async def scenario():
        async with lab_env(tmp_path) as env:
            port = env.settings.connection.port
            with_fake = await https_exchange(
                port,
                b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\nCookie: hid=deadbeef\r\n\r\n",
            )
            assert with_fake.startswith(b"HTTP/1.1 404")
            token = crypto.make_ws_token(env.settings.psk_bytes)
            status, headers = await https_headers(
                port,
                b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\nCookie: hid=" + token.encode() + b"\r\n\r\n",
            )
            assert status == 101
            assert "sec-websocket-accept" in headers

    run(scenario())


def test_wrong_psk_is_rejected(tmp_path):
    async def scenario():
        async with lab_env(tmp_path) as env:
            port = env.settings.connection.port
            wrong = await https_exchange(port, protocol.build_hello(crypto.generate_psk()))
            assert wrong.startswith(b"HTTP/1.1 400 Bad Request")
            assert env.relay.counters.handshakes_failed >= 1

    run(scenario())


def test_policy_blocks_private_targets(tmp_path):
    async def scenario():
        async with lab_env(tmp_path, allow_private=False) as env:
            with pytest.raises(Socks5Error):
                await socks5_connect(
                    env.settings.socks.host, env.settings.socks.port, "127.0.0.1", env.origin_port
                )
            assert env.relay.counters.policy_blocks >= 1
            with pytest.raises(protocol.PolicyError):
                await env.relay.authorize("10.0.0.5", 443)

    run(scenario())


def test_http_connect_proxy(tmp_path):
    async def scenario():
        async with lab_env(tmp_path, http_proxy=True) as env:
            proxy_port = env.settings.socks.proxy_port
            assert proxy_port
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            request = (
                f"CONNECT 127.0.0.1:{env.origin_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{env.origin_port}\r\n\r\n"
            ).encode()
            writer.write(request)
            await writer.drain()
            head = b""
            while b"\r\n\r\n" not in head:
                head += await asyncio.wait_for(reader.read(1), 5)
            assert head.startswith(b"HTTP/1.1 200")
            writer.write(b"GET /x?n=2048 HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(), 10)
            body = data.split(b"\r\n\r\n", 1)[1]
            assert len(body) == 2048
            await close_writer(writer)

    run(scenario())


def test_plaintext_relay_behind_proxy(tmp_path):
    async def scenario():
        psk = crypto.encode_psk(crypto.generate_psk())
        port = free_port()
        relay = Relay(
            RelaySettings(
                listen_host="127.0.0.1",
                listen_port=port,
                psk=psk,
                tls=False,
                allow_private=True,
            )
        )
        await relay.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            token = crypto.make_ws_token(protocol_psk(psk))
            ws = await client_handshake(
                reader,
                writer,
                host="localhost",
                path="/ws",
                extra_headers=[("Cookie", f"hid={token}")],
            )
            nonce = os.urandom(16)
            hello_wire = protocol.build_hello(protocol_psk(psk), nonce)
            hello = protocol.Hello(protocol.VERSION, 0, nonce, 0, hello_wire)
            await ws.write(hello_wire)
            ack_wire = await protocol.read_handshake_message(ws)
            ack = protocol.parse_ack(protocol_psk(psk), ack_wire, hello)
            assert len(ack.server_nonce) == 16
            c2s, s2c = crypto.derive_session_keys(protocol_psk(psk), nonce, ack.server_nonce)
            assert c2s != s2c
            ws.close()
        finally:
            await relay.stop()

    run(scenario())


def test_replayed_handshake_is_refused(tmp_path):
    async def scenario():
        async with lab_env(tmp_path) as env:
            port = env.settings.connection.port
            psk = crypto.decode_psk(env.settings.psk)
            nonce = os.urandom(16)
            wire = protocol.build_hello(psk, nonce)
            hello = protocol.Hello(protocol.VERSION, 0, nonce, 0, wire)
            ok_before = env.relay.counters.handshakes_ok
            first = await tls_connect("127.0.0.1", port, verify="insecure", sni="localhost", timeout=8)
            first.writer.write(wire)
            await first.writer.drain()
            ack = await protocol.read_handshake_message(first)
            assert protocol.parse_ack(psk, ack, hello).server_nonce
            second = await tls_connect("127.0.0.1", port, verify="insecure", sni="localhost", timeout=8)
            second.writer.write(wire)
            await second.writer.drain()
            reply = await asyncio.wait_for(second.reader.read(4096), 6)
            assert reply.startswith(b"HTTP/1.1 400 Bad Request")
            assert env.relay.counters.handshakes_failed >= 1
            assert env.relay.counters.handshakes_ok == ok_before + 1
            first.close()
            second.close()

    run(scenario())


def test_rotation_starts_a_fresh_session(tmp_path):
    async def scenario():
        async with lab_env(tmp_path, rotate_minutes=0.02) as env:
            first = env.client.snapshot()["session_id"]
            deadline = asyncio.get_running_loop().time() + 12
            second = first
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.2)
                snap = env.client.snapshot()
                if snap["connected"] and snap["session_id"] != first:
                    second = snap["session_id"]
                    break
            assert second != first
            body = await env.fetch(2048)
            assert len(body) == 2048

    run(scenario())


def protocol_psk(text: str) -> bytes:
    return crypto.decode_psk(text)
