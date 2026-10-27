"""Regression tests for idle-tunnel liveness.

Cover traffic used to refresh ``last_tx`` continuously, which suppressed the
keepalive ping; the client then declared a healthy relay dead after 75 seconds
of silence from the relay.
"""

import asyncio


from heduvpn import client as client_mod
from heduvpn import protocol
from tests.util import lab_env, run


def test_idle_tunnel_survives_cover_traffic(tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod, "KEEPALIVE_INTERVAL", 0.2)
    monkeypatch.setattr(client_mod, "KEEPALIVE_TIMEOUT", 1.0)

    async def fast_cover(self) -> None:  # noqa: ANN001 - test double
        try:
            while True:
                await asyncio.sleep(0.05)
                await self.send(protocol.F_PAD, b"cover")
        except asyncio.CancelledError:
            raise

    monkeypatch.setattr(client_mod.Session, "_cover", fast_cover)

    async def scenario():
        async with lab_env(tmp_path, cover="low") as env:
            await asyncio.sleep(2.5)
            snap = env.client.snapshot()
            assert snap["connected"], snap["last_error"]
            assert env.relay.counters.sessions >= 1

    run(scenario())


def test_keepalive_measures_rtt(tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod, "KEEPALIVE_INTERVAL", 0.15)
    monkeypatch.setattr(client_mod, "KEEPALIVE_TIMEOUT", 2.0)

    async def scenario():
        async with lab_env(tmp_path, cover="none") as env:
            await asyncio.sleep(1.2)
            snap = env.client.snapshot()
            assert snap["connected"], snap["last_error"]
            assert snap["rtt_ms"] >= 0.0
            assert env.client.counters.frames_in > 0

    run(scenario())
