import os

import pytest

from heduvpn import crypto
from heduvpn.config import ClientSettings, ConnectionConfig
from heduvpn.link import (
    LinkError,
    decode_link,
    encode_link,
    extract_link,
    link_for_relay,
    pin_from_cert,
    summarize_link,
)


def make_settings(tmp_path) -> ClientSettings:
    identity = crypto.load_or_create_identity(str(tmp_path), "vpn.example.com")
    return ClientSettings(
        psk=crypto.encode_psk(identity.psk),
        name="Test relay",
        connection=ConnectionConfig(
            server="vpn.example.com",
            port=443,
            sni="vpn.example.com",
            pin=identity.pin,
        ),
    )


def test_link_roundtrip(tmp_path):
    settings = make_settings(tmp_path)
    link = encode_link(settings)
    assert link.startswith("hedu1://vpn.example.com:443#")
    decoded = decode_link(link)
    assert decoded.connection.server == "vpn.example.com"
    assert decoded.connection.port == 443
    assert decoded.connection.pin == settings.connection.pin
    assert decoded.connection.sni == "vpn.example.com"
    assert decoded.psk == settings.psk
    assert decoded.camouflage.padding == settings.camouflage.padding


def test_link_carries_custom_preferences(tmp_path):
    settings = make_settings(tmp_path)
    settings.camouflage.padding = "cells"
    settings.camouflage.cover = "medium"
    settings.camouflage.jitter_ms = 30
    settings.connection.transport = "tls"
    decoded = decode_link(encode_link(settings))
    assert decoded.camouflage.padding == "cells"
    assert decoded.camouflage.cover == "medium"
    assert decoded.camouflage.jitter_ms == 30
    assert decoded.connection.transport == "tls"


def test_link_rejects_tampering(tmp_path):
    link = encode_link(make_settings(tmp_path))
    with pytest.raises(LinkError):
        decode_link(link[: -2] + "AA")
    with pytest.raises(LinkError):
        decode_link("https://example.com")
    with pytest.raises(LinkError):
        decode_link("hedu1://example.com:443")


def test_extract_from_text_and_file(tmp_path):
    link = encode_link(make_settings(tmp_path))
    assert extract_link(f"hello {link} bye") == link
    path = tmp_path / "link.txt"
    path.write_text("Server link:\n" + link + "\n")
    assert extract_link(str(path)) == link


def test_relay_link_needs_certificate_for_pin(tmp_path):
    with pytest.raises(LinkError):
        link_for_relay(psk=crypto.encode_psk(crypto.generate_psk()), host="vpn.example.com", port=443)


def test_relay_link_from_certificate(tmp_path):
    identity = crypto.load_or_create_identity(str(tmp_path), "vpn.example.com")
    link = link_for_relay(
        psk=crypto.encode_psk(identity.psk),
        host="vpn.example.com",
        port=443,
        sni="vpn.example.com",
        certfile=os.path.join(str(tmp_path), "cert.pem"),
    )
    settings = decode_link(link)
    assert settings.connection.pin == pin_from_cert(os.path.join(str(tmp_path), "cert.pem"))
    assert settings.connection.verify == "pin"


def test_summary_does_not_leak_psk(tmp_path):
    settings = make_settings(tmp_path)
    summary = summarize_link(encode_link(settings))
    assert settings.psk not in str(summary)
    assert summary["psk_fingerprint"].startswith("sha256:")
    assert summary["server"] == "vpn.example.com"
