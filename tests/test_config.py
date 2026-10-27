import json
import os
import stat

import pytest

from heduvpn import crypto
from heduvpn.config import (
    CamouflageConfig,
    ClientSettings,
    ConfigError,
    ConnectionConfig,
    SocksConfig,
)


def valid_settings(**kwargs) -> ClientSettings:
    psk = crypto.encode_psk(crypto.generate_psk())
    defaults = dict(
        psk=psk,
        connection=ConnectionConfig(
            server="vpn.example.com", port=443, sni="vpn.example.com",
            verify="pin", pin="sha256:" + "ab" * 32,
        ),
        socks=SocksConfig(),
    )
    defaults.update(kwargs)
    return ClientSettings(**defaults)


def test_valid_settings_roundtrip():
    settings = valid_settings()
    settings.validate()
    parsed = ClientSettings.from_json(settings.to_json())
    assert parsed.psk == settings.psk
    assert parsed.connection.pin == settings.connection.pin
    assert parsed.camouflage.padding == settings.camouflage.padding


def test_missing_psk_is_rejected():
    settings = valid_settings()
    settings.psk = ""
    with pytest.raises(ConfigError):
        settings.validate()


def test_pin_mode_requires_pin():
    settings = valid_settings()
    settings.connection.pin = ""
    with pytest.raises(ConfigError):
        settings.validate()


def test_invalid_transport_and_padding():
    settings = valid_settings()
    settings.connection.transport = "quic"
    with pytest.raises(ConfigError):
        settings.validate()
    settings = valid_settings()
    settings.camouflage.padding = "wat"
    with pytest.raises(ConfigError):
        settings.validate()


def test_unknown_keys_rejected():
    data = json.loads(valid_settings().to_json())
    data["connection"]["surprise"] = True
    with pytest.raises(ConfigError):
        ClientSettings.from_dict(data)


def test_public_socks_bind_requires_allow_lan():
    settings = valid_settings(socks=SocksConfig(host="0.0.0.0"))
    with pytest.raises(ConfigError):
        settings.validate()
    settings.socks.allow_lan = True
    settings.validate()


def test_save_permissions(tmp_path):
    settings = valid_settings()
    path = tmp_path / "client.json"
    settings.save(str(path))
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode & 0o077 == 0
    loaded = ClientSettings.load(str(path))
    assert loaded.psk == settings.psk


def test_camouflage_bounds():
    with pytest.raises(ConfigError):
        CamouflageConfig(jitter_ms=900).validate()
    with pytest.raises(ConfigError):
        CamouflageConfig(cover="extreme").validate()
