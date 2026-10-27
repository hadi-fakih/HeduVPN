from heduvpn.systemproxy import SystemProxy


def test_support_and_status_do_not_crash():
    proxy = SystemProxy(snapshot_path="/tmp/heduvpn-test-systemproxy-does-not-exist.json")
    supported, note = proxy.support()
    assert isinstance(supported, bool)
    assert isinstance(note, str) and note
    status = proxy.status()
    assert "supported" in status
    assert "platform" in status
    assert not proxy.pending_snapshot()
    # Disabling with no snapshot must be a no-op, never destructive.
    result = proxy.disable()
    assert result.ok


def test_snapshot_roundtrip(tmp_path):
    path = tmp_path / "systemproxy.json"
    proxy = SystemProxy(snapshot_path=str(path))
    assert not proxy.pending_snapshot()
    proxy._save({"platform": "Darwin", "service": "Wi-Fi", "socks": {"enabled": "No", "server": "", "port": 0}})
    assert proxy.pending_snapshot()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    import json

    data = json.loads(path.read_text())
    assert data["platform"] == "Darwin"
    assert data["service"] == "Wi-Fi"


def test_corrupt_snapshot_is_reported(tmp_path):
    path = tmp_path / "systemproxy.json"
    path.write_text("{not json")
    proxy = SystemProxy(snapshot_path=str(path))
    result = proxy.disable()
    assert not result.ok
    assert path.exists()


def test_foreign_snapshot_is_left_alone(tmp_path):
    import json

    path = tmp_path / "systemproxy.json"
    path.write_text(json.dumps({"platform": "Plan9", "mode": "none"}))
    result = SystemProxy(snapshot_path=str(path)).disable()
    assert not result.ok
    assert "Plan9" in result.message
    assert path.exists()
