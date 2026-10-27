import time

import pytest

from heduvpn import crypto, protocol


def test_psk_roundtrip():
    psk = crypto.generate_psk()
    assert len(psk) == 32
    text = crypto.encode_psk(psk)
    assert text.startswith("hdu1_")
    assert crypto.decode_psk(text) == psk
    assert crypto.decode_psk(psk.hex()) == psk


@pytest.mark.parametrize("bad", ["", "hdu1_", "hdu1_AAAA", "zzzz"])
def test_psk_rejects_bad_input(bad):
    with pytest.raises((crypto.CryptoError, Exception)):
        crypto.decode_psk(bad)


def test_ws_token():
    psk = crypto.generate_psk()
    token = crypto.make_ws_token(psk, ttl=120)
    ok, reason = crypto.verify_ws_token(psk, token)
    assert ok and reason == "ok"
    assert crypto.verify_ws_token(psk, token, ttl=1, now=time.time() + 500)[0] is False
    other = crypto.generate_psk()
    assert crypto.verify_ws_token(other, token)[1] == "bad_mac"
    assert crypto.verify_ws_token(psk, "not-base64!!")[1] == "malformed"


def test_handshake_happy_path():
    psk = crypto.generate_psk()
    wire = protocol.build_hello(psk, pad_max=24)
    hello = protocol.parse_hello(psk, wire)
    assert hello.version == protocol.VERSION
    ack_wire, server_nonce = protocol.build_ack(psk, hello, pad_max=24)
    ack = protocol.parse_ack(psk, ack_wire, hello)
    assert ack.server_nonce == server_nonce
    c2s, s2c = crypto.derive_session_keys(psk, hello.client_nonce, server_nonce)
    assert len(c2s) == len(s2c) == 32
    assert c2s != s2c


def test_handshake_rejects_tampering_and_stale_time():
    psk = crypto.generate_psk()
    wire = bytearray(protocol.build_hello(psk))
    wire[-1] ^= 0x01
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_hello(psk, bytes(wire))
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_hello(crypto.generate_psk(), protocol.build_hello(psk))
    stale = protocol.build_hello(psk, now=time.time() - 600)
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_hello(psk, stale)


def test_ack_binds_to_client_nonce():
    psk = crypto.generate_psk()
    hello = protocol.parse_hello(psk, protocol.build_hello(psk))
    other = protocol.parse_hello(psk, protocol.build_hello(psk))
    ack_wire, _ = protocol.build_ack(psk, hello)
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_ack(psk, ack_wire, other)


def test_self_signed_certificate(tmp_path):
    cert_pem, key_pem = crypto.generate_self_signed("vpn.example.com", days=10)
    assert b"BEGIN CERTIFICATE" in cert_pem
    assert b"PRIVATE KEY" in key_pem
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem)
    assert "vpn.example.com" in cert.subject.rfc4514_string()
    pin = crypto.cert_fingerprint(cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER))
    assert pin.startswith("sha256:")
    assert crypto.fingerprint_matches(pin, cert.public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
    ))


def test_identity_reuse(tmp_path):
    first = crypto.load_or_create_identity(str(tmp_path), "localhost")
    second = crypto.load_or_create_identity(str(tmp_path), "localhost")
    assert first.psk == second.psk
    assert first.cert_pem == second.cert_pem
    assert first.pin == second.pin
