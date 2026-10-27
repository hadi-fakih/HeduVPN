import asyncio

from heduvpn.demo import DemoLab


def test_demo_lab_produces_real_metadata(tmp_path):
    async def scenario():
        lab = DemoLab(state_dir=str(tmp_path / "identity"))
        try:
            state = await lab.start(
                {
                    "padding": "random",
                    "cover": "low",
                    "jitter_ms": 4,
                    "transport": "ws",
                    "traffic": "browse",
                }
            )
            assert state["running"], state.get("error")
            deadline = asyncio.get_running_loop().time() + 25
            latest = state
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.25)
                latest = lab.state()
                if (
                    latest["connection"].get("session_id")
                    and latest["wire"]["count_out"] > 2
                    and len(latest["probes"]) >= 8
                ):
                    break
            assert latest["connection"]["session_id"], latest.get("error")
            assert latest["connection"]["pin"].startswith("sha256:")
            assert latest["wire"]["count_out"] > 0
            assert latest["probes"]
            assert all("observed" in probe for probe in latest["probes"])
            assert latest["checks"]
            assert latest["traffic"]["ok"] >= 1

            restarted = await lab.start(
                {
                    "padding": "none",
                    "cover": "none",
                    "jitter_ms": 0,
                    "transport": "tls",
                    "traffic": "idle",
                }
            )
            assert restarted["running"]
            assert restarted["profile"]["padding"] == "none"
            assert restarted["profile"]["transport"] == "tls"
        finally:
            await lab.stop()

    asyncio.run(scenario())
