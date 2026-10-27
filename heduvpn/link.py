"""Connection links (``hedu1://...``).

A connection link carries everything a client needs except its local proxy
preferences.  The secret half lives in the URL *fragment*: browsers never
send fragments to servers, and the format is plain enough to paste into a
chat, a password manager or a QR code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crypto
from .config import ClientSettings, ConfigError, ConnectionConfig, CamouflageConfig, SocksConfig

LINK_SCHEME = "hedu1"
LINK_RE = re.compile(r"hedu1://\S+")


class LinkError(Exception):
    pass


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise LinkError("corrupt link payload") from exc


def encode_link(settings: ClientSettings) -> str:
    settings.validate()
    conn = settings.connection
    camo = settings.camouflage
    payload = {
        "k": settings.psk,
        "s": conn.sni,
        "p": conn.pin,
        "t": conn.transport,
        "w": conn.ws_path,
        "h": conn.ws_host,
        "c": conn.ws_cookie,
        "v": conn.verify,
        "d": camo.padding,
        "j": camo.jitter_ms,
        "o": camo.cover,
        "n": settings.name,
    }
    frag = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    host = f"[{conn.server}]" if ":" in conn.server and not conn.server.startswith("[") else conn.server
    return f"{LINK_SCHEME}://{host}:{conn.port}#{frag}"


def decode_link(text: str, base: ClientSettings | None = None) -> ClientSettings:
    text = extract_link(text)
    parts = urlsplit(text)
    if parts.scheme != LINK_SCHEME:
        raise LinkError("not a HeduVPN link (expected hedu1://)")
    if not parts.hostname:
        raise LinkError("link is missing a server hostname")
    if not parts.fragment:
        raise LinkError("link is missing its payload fragment")
    try:
        data = json.loads(_b64d(parts.fragment))
    except json.JSONDecodeError as exc:
        raise LinkError("link payload is not valid JSON") from exc
    if not isinstance(data, dict):
        raise LinkError("link payload must be an object")
    base = base or ClientSettings()
    port = parts.port or 443
    conn = ConnectionConfig(
        server=parts.hostname,
        port=port,
        sni=data.get("s") or parts.hostname,
        transport=data.get("t", "ws"),
        ws_path=data.get("w", "/ws"),
        ws_host=data.get("h", ""),
        ws_cookie=data.get("c", "hid"),
        verify=data.get("v", "pin"),
        pin=data.get("p", ""),
    )
    camo = CamouflageConfig(
        padding=data.get("d", base.camouflage.padding),
        jitter_ms=int(data.get("j", base.camouflage.jitter_ms)),
        cover=data.get("o", base.camouflage.cover),
        rotate_minutes=base.camouflage.rotate_minutes,
    )
    socks = base.socks
    settings = ClientSettings(
        psk=data.get("k", ""),
        name=data.get("n") or base.name,
        connection=conn,
        camouflage=camo,
        socks=socks,
    )
    try:
        settings.validate()
    except ConfigError as exc:
        raise LinkError(str(exc)) from exc
    return settings


def extract_link(text: str) -> str:
    """Accept a bare link, a file path, or text that contains a link."""
    text = text.strip()
    match = LINK_RE.search(text)
    if match:
        return match.group(0)
    try:
        with open(text, encoding="utf-8") as fh:
            content = fh.read()
        match = LINK_RE.search(content)
        if match:
            return match.group(0)
    except OSError:
        pass
    raise LinkError("no hedu1:// link found")


def pin_from_cert(path: str) -> str:
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        if b"BEGIN CERTIFICATE" in data:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except Exception as exc:
        raise LinkError(f"could not read certificate {path}: {exc}") from exc
    return crypto.cert_fingerprint(cert.public_bytes(serialization.Encoding.DER))


def link_for_relay(
    psk: str,
    host: str,
    port: int,
    sni: str = "",
    certfile: str = "",
    transport: str = "ws",
    verify: str = "pin",
    ws_path: str = "/ws",
    ws_cookie: str = "hid",
    name: str = "HeduVPN",
) -> str:
    pin = pin_from_cert(certfile) if certfile else ""
    settings = ClientSettings(
        psk=psk,
        name=name,
        connection=ConnectionConfig(
            server=host,
            port=port,
            sni=sni or host,
            transport=transport,
            ws_path=ws_path,
            ws_host=sni or host,
            ws_cookie=ws_cookie,
            verify=verify,
            pin=pin,
        ),
        camouflage=CamouflageConfig(padding="random", jitter_ms=12, cover="low"),
        socks=SocksConfig(),
    )
    if verify == "pin" and not pin:
        raise LinkError("a pinned link needs the relay certificate to compute the pin")
    return encode_link(settings)


def summarize_link(link: str) -> dict[str, str]:
    """Human-readable, safe-to-share summary (no PSK, just a fingerprint)."""
    s = decode_link(link)
    c = s.connection
    return {
        "name": s.name,
        "server": c.server,
        "port": str(c.port),
        "sni": c.sni,
        "transport": c.transport,
        "path": c.ws_path,
        "verify": c.verify,
        "pin": c.pin,
        "psk_fingerprint": "sha256:" + hashlib.sha256(s.psk_bytes).hexdigest()[:16],
        "padding": s.camouflage.padding,
        "cover": s.camouflage.cover,
    }
