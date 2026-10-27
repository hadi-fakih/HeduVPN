"""Cryptographic primitives for HeduVPN.

Everything in the tunnel is protected with a pre-shared key (PSK) and
ChaCha20-Poly1305.  TLS on the wire is an *outer* layer that only exists to
look like ordinary HTTPS to a passive observer; the PSK is what actually
authenticates peers and protects the payload (so a TLS-terminating CDN or a
compromised CA still cannot read or forge tunnel traffic).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import struct
import time
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

PSK_BYTES = 32
AEAD_TAG = 16
NONCE_BYTES = 12


class CryptoError(Exception):
    """Raised when a key, token or ciphertext fails validation."""


# ---------------------------------------------------------------------------
# Pre-shared keys
# ---------------------------------------------------------------------------


def generate_psk() -> bytes:
    """Return a fresh 256-bit pre-shared key."""
    return secrets.token_bytes(PSK_BYTES)


def encode_psk(psk: bytes) -> str:
    """Encode a PSK as ``hdu1_<base64url>`` (safe for config files / QR codes)."""
    if len(psk) != PSK_BYTES:
        raise CryptoError(f"PSK must be {PSK_BYTES} bytes, got {len(psk)}")
    body = base64.urlsafe_b64encode(psk).rstrip(b"=").decode("ascii")
    return f"hdu1_{body}"


def decode_psk(text: str) -> bytes:
    """Parse a PSK produced by :func:`encode_psk` (raw base64/hex also works)."""
    text = text.strip()
    if text.startswith("hdu1_"):
        text = text[len("hdu1_"):]
        padded = text + "=" * (-len(text) % 4)
        try:
            psk = base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception as exc:  # pragma: no cover - defensive
            raise CryptoError("malformed PSK") from exc
    elif len(text) == 64:
        psk = bytes.fromhex(text)
    else:
        padded = text + "=" * (-len(text) % 4)
        psk = base64.urlsafe_b64decode(padded.encode("ascii"))
    if len(psk) != PSK_BYTES:
        raise CryptoError(f"PSK must be {PSK_BYTES} bytes, got {len(psk)}")
    return psk


# ---------------------------------------------------------------------------
# Key derivation + AEAD
# ---------------------------------------------------------------------------


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def handshake_key(psk: bytes) -> bytes:
    return hkdf(psk, salt=b"heduvpn/v1", info=b"handshake", length=32)


def derive_session_keys(psk: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    """Return ``(client_to_server_key, server_to_client_key)``."""
    okm = hkdf(
        psk,
        salt=client_nonce + server_nonce,
        info=b"heduvpn/v1/session",
        length=64,
    )
    return okm[:32], okm[32:]


def nonce_from_counter(counter: int) -> bytes:
    if not 0 <= counter < 2**64:
        raise CryptoError("nonce counter exhausted")
    return b"\x00\x00\x00\x00" + struct.pack(">Q", counter)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise CryptoError("authentication failed") from exc


# ---------------------------------------------------------------------------
# WebSocket gate token
# ---------------------------------------------------------------------------
#
# The WebSocket transport validates a short-lived token in a cookie *before*
# upgrading the connection.  That lets a relay answer active probes with an
# ordinary 404 instead of opening a tunnel that then goes quiet.


def make_ws_token(psk: bytes, ttl: int = 120, now: float | None = None) -> str:
    ts = int(now if now is not None else time.time())
    nonce = secrets.token_bytes(8)
    mac = hmac.new(psk, b"ws1|" + str(ts).encode() + b"|" + nonce, hashlib.sha256).digest()[:16]
    raw = struct.pack(">Q", ts) + nonce + mac
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify_ws_token(psk: bytes, token: str, ttl: int = 120, now: float | None = None) -> tuple[bool, str]:
    """Return ``(ok, reason)`` where reason is machine-readable."""
    try:
        padded = token.strip() + "=" * (-len(token.strip()) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return False, "malformed"
    if len(raw) != 8 + 8 + 16:
        return False, "malformed"
    ts = struct.unpack(">Q", raw[:8])[0]
    nonce = raw[8:16]
    mac = raw[16:]
    current = int(now if now is not None else time.time())
    if abs(current - ts) > ttl:
        return False, "expired"
    expected = hmac.new(psk, b"ws1|" + str(ts).encode() + b"|" + nonce, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expected):
        return False, "bad_mac"
    return True, "ok"


# ---------------------------------------------------------------------------
# TLS certificates
# ---------------------------------------------------------------------------


def cert_fingerprint(cert_der: bytes) -> str:
    """Return ``sha256:<hex>`` pin for a DER certificate."""
    return "sha256:" + hashlib.sha256(cert_der).hexdigest()


def fingerprint_matches(pin: str, cert_der: bytes) -> bool:
    return hmac.compare_digest(pin.strip().lower(), cert_fingerprint(cert_der))


def generate_self_signed(
    common_name: str = "localhost",
    days: int = 365,
    extra_names: list[str] | None = None,
) -> tuple[bytes, bytes]:
    """Create a self-signed ECDSA P-256 certificate.

    Returns ``(cert_pem, key_pem)``.  Clients pin the certificate fingerprint,
    so no public CA is required -- but you can also drop in a Let's Encrypt
    certificate for maximum "looks completely ordinary" value.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HeduVPN"),
        ]
    )
    alt: list[x509.GeneralName] = [x509.DNSName(common_name), x509.DNSName("localhost")]
    for name in extra_names or []:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt.append(x509.DNSName(name))
    alt.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = time.time()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_as_utc(now - 86400))
        .not_valid_after(_as_utc(now + days * 86400))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _as_utc(ts: float):
    import datetime as _dt

    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)


@dataclass(frozen=True)
class Identity:
    """Convenience bundle used by servers/tests."""

    psk: bytes
    cert_pem: bytes
    key_pem: bytes

    @property
    def pin(self) -> str:
        cert = x509.load_pem_x509_certificate(self.cert_pem)
        return cert_fingerprint(cert.public_bytes(serialization.Encoding.DER))


def load_or_create_identity(directory: str, common_name: str = "localhost") -> Identity:
    """Load ``cert.pem``/``key.pem``/``psk`` from *directory*, creating them if absent."""
    os.makedirs(directory, exist_ok=True)
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    psk_path = os.path.join(directory, "psk")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        with open(cert_path, "rb") as fh:
            cert_pem = fh.read()
        with open(key_path, "rb") as fh:
            key_pem = fh.read()
    else:
        cert_pem, key_pem = generate_self_signed(common_name)
        with open(cert_path, "wb") as fh:
            fh.write(cert_pem)
        with open(key_path, "wb") as fh:
            fh.write(key_pem)
        os.chmod(key_path, 0o600)

    if os.path.exists(psk_path):
        with open(psk_path, encoding="utf-8") as fh:
            psk = decode_psk(fh.read())
    else:
        psk = generate_psk()
        with open(psk_path, "w", encoding="utf-8") as fh:
            fh.write(encode_psk(psk) + "\n")
        os.chmod(psk_path, 0o600)

    return Identity(psk=psk, cert_pem=cert_pem, key_pem=key_pem)
