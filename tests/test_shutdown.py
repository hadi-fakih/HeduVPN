"""Shutdown must stay bounded even with live tunnel sessions.

Python 3.12 changed ``Server.wait_closed()`` to wait for in-flight connection
handlers.  A relay handler runs a whole tunnel session, so waiting on the
listener before asking sessions to stop deadlocks until the idle timeout --
which hung the test suite (and would hang a real ``relay.stop()``).
"""

import asyncio
import time

from heduvpn.transport import close_server, close_writer
from tests.util import lab_env, run


def test_relay_stop_is_prompt_with_live_sessions(tmp_path):
    async def scenario():
        async with lab_env(tmp_path) as env:
            assert env.client.snapshot()["connected"]
            assert env.relay.sessions, "expected a live session"
            started = time.monotonic()
            await asyncio.wait_for(env.relay.stop(), 10)
            elapsed = time.monotonic() - started
            assert elapsed < 5, f"relay.stop() took {elapsed:.1f}s"
            assert not env.relay.sessions

    run(scenario())


def test_close_helpers_never_raise_or_hang():
    async def scenario():
        # Closing an already-closed server twice must be quiet and fast.
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        await close_server(server)
        await close_server(server)  # idempotent
        await close_server(None)

        # A writer whose peer is gone must not block for long.
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)
        started = time.monotonic()
        await close_writer(writer, timeout=2)
        assert time.monotonic() - started < 3
        await close_server(server)

    run(scenario())


def test_client_stop_tears_down_listeners(tmp_path):
    async def scenario():
        async with lab_env(tmp_path) as env:
            socks = (env.settings.socks.host, env.settings.socks.port)
            started = time.monotonic()
            await asyncio.wait_for(env.client.stop(), 10)
            assert time.monotonic() - started < 5
            # the SOCKS port must be free again
            try:
                asyncio.get_running_loop()
                probe = await asyncio.start_server(lambda r, w: None, *socks)
            except OSError as exc:  # pragma: no cover - would be a real bug
                raise AssertionError(f"SOCKS port still bound: {exc}") from exc
            await close_server(probe)

    run(scenario())


def test_relay_stop_orders_session_shutdown_before_listener(tmp_path, monkeypatch):
    """Emulate Python 3.12's ``Server.wait_closed()``, which waits for handlers.

    The relay must tell its sessions to stop *before* waiting on the listener;
    with the old ordering this test blocks until the ``wait_for`` gives up.
    """

    async def scenario():
        async with lab_env(tmp_path) as env:
            assert env.relay.sessions, "expected a live session"
            original = asyncio.base_events.Server.wait_closed

            async def strict_wait_closed(server):
                while getattr(server, "_active_count", 0) > 0:
                    await asyncio.sleep(0.01)
                return await original(server)

            monkeypatch.setattr(
                asyncio.base_events.Server, "wait_closed", strict_wait_closed
            )
            try:
                started = time.monotonic()
                await asyncio.wait_for(env.relay.stop(), 10)
                assert time.monotonic() - started < 5
                assert not env.relay.sessions
            finally:
                monkeypatch.undo()

    run(scenario())
