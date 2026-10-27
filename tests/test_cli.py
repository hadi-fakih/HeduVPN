import json

import pytest

from heduvpn.cli import main
from heduvpn.config import ClientSettings
from heduvpn.link import extract_link


def test_version():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_help_runs():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_relay_link_only_and_import(tmp_path, capsys):
    state = tmp_path / "relay"
    code = main(
        [
            "relay",
            "--domain",
            "localhost",
            "--port",
            "9443",
            "--state-dir",
            str(state),
            "--link-only",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    link = extract_link(out)
    assert link.startswith("hedu1://127.0.0.1:9443#")
    for name in ("cert.pem", "key.pem", "psk", "relay.json", "client-link.txt", "client.json"):
        assert (state / name).exists(), name
    relay_json = json.loads((state / "relay.json").read_text())
    assert relay_json["domain"] == "localhost"
    assert relay_json["tls"] is True
    assert relay_json["allow_private"] is False

    code = main(["link", link])
    assert code == 0
    assert "Connection link" in capsys.readouterr().out

    outfile = tmp_path / "client.json"
    code = main(["import", link, "--out", str(outfile), "--socks-port", "1099"])
    assert code == 0
    capsys.readouterr()
    settings = ClientSettings.load(str(outfile))
    assert settings.socks.port == 1099
    assert settings.connection.server == "127.0.0.1"
    assert settings.connection.pin.startswith("sha256:")


def test_import_rejects_garbage(tmp_path, capsys):
    code = main(["import", "definitely-not-a-link", "--out", str(tmp_path / "x.json")])
    assert code == 1
    assert "hedu1://" in capsys.readouterr().err


def test_doctor_runs(capsys):
    code = main(["doctor"])
    assert code == 0
    out = capsys.readouterr().out
    assert "HeduVPN doctor" in out
    assert "python" in out


def test_check_requires_a_target_and_uses_default_socks(capsys):
    assert main(["check"]) == 1
    assert "--relay" in capsys.readouterr().err
    code = main(["check", "--url", "http://127.0.0.1:1/", "--socks", "127.0.0.1:1"])
    assert code == 1
    assert "proxy check failed" in capsys.readouterr().err
