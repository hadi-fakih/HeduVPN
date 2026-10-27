"""Transport building blocks: TLS streams, fingerprint pinning and SOCKS5."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import ssl
import struct
from dataclasses import dataclass

from . import crypto
from .protocol import Stream, StreamClosed


class TransportError(Exception):
    """Network-level failure (DNS, TCP, TLS, pin mismatch...)."""


# ---------------------------------------------------------------------------
# TLS stream
# ---------------------------------------------------------------------------


@dataclass
class TLSInfo:
    version: str = ""
    cipher: str = ""
    alpn: str = ""
    sni: str = ""
    cert_cn: str = ""
    pin: str = ""
    description: str = ""


class TLSStream(Stream):
    """A ``Stream`` backed by an asyncio TLS socket."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, info: TLSInfo) -> None:
        self.reader = reader
        self.writer = writer
        self.info = info

    async def read_exact(self, n: int) -> bytes:
        try:
            return await self.reader.readexactly(n)
        except (asyncio.IncompleteReadError, ConnectionError) as exc:
            raise StreamClosed("tls connection lost") from exc

    async def write(self, data: bytes) -> None:
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, ssl.SSLError) as exc:
            raise StreamClosed("tls write failed") from exc

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass

    async def wait_closed(self) -> None:
        try:
            await self.writer.wait_closed()
        except Exception:
            pass

    @property
    def peer(self) -> str:
        peer = self.writer.get_extra_info("peername")
        if isinstance(peer, tuple) and len(peer) >= 2:
            return f"{peer[0]}:{peer[1]}"
        return str(peer)


def normalize_pin(pin: str) -> str:
    pin = pin.strip()
    if not pin:
        return ""
    low = pin.lower()
    if low.startswith("sha256:"):
        return low
    raw = pin
    if raw.startswith("sha256/"):
        raw = raw[len("sha256/"):]
    try:
        padded = raw + "=" * (-len(raw) % 4)
        der = base64.b64decode(padded, validate=True)
        return "sha256:" + hashlib.sha256(der).hexdigest()
    except Exception:
        # A bare 64-char hex digest is already a SHA-256 fingerprint.
        if len(raw) == 64:
            try:
                int(raw, 16)
                return "sha256:" + raw.lower()
            except ValueError:
                pass
    raise TransportError("invalid certificate pin (expected sha256:<hex>)")


def client_ssl_context(verify: str) -> ssl.SSLContext:
    if verify in ("pin", "insecure"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif verify == "system":
        ctx = ssl.create_default_context()
    else:
        raise TransportError(f"unknown verify mode {verify!r}")
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:  # pragma: no cover
        pass
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def server_ssl_context(certfile: str, keyfile: str, alpn: list[str] | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    try:
        ctx.set_alpn_protocols(alpn or ["http/1.1"])
    except NotImplementedError:  # pragma: no cover
        pass
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    return ctx


def _cert_common_name(der: bytes) -> str:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


async def tls_upgrade(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    verify: str = "insecure",
    pin: str = "",
    sni: str = "",
    timeout: float = 15.0,
) -> TLSStream:
    """Upgrade an existing TCP stream to TLS and (optionally) enforce a pin."""
    sni = sni or ""
    if verify == "pin" and not pin:
        raise TransportError("verify=pin requires a certificate pin")
    ctx = client_ssl_context(verify)
    try:
        await asyncio.wait_for(
            writer.start_tls(ctx, server_hostname=sni or None, ssl_handshake_timeout=timeout),
            timeout,
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
        try:
            writer.close()
        except Exception:
            pass
        raise TransportError(f"TLS handshake with {sni or 'server'} failed: {exc}") from exc

    sslobj = writer.get_extra_info("ssl_object")
    der = b""
    if sslobj is not None:
        try:
            der = sslobj.getpeercert(binary_form=True) or b""
        except Exception:
            der = b""

    info = TLSInfo(sni=sni)
    if sslobj is not None:
        info.version = sslobj.version() or ""
        cipher = sslobj.cipher()
        info.cipher = cipher[0] if cipher else ""
        try:
            info.alpn = sslobj.selected_alpn_protocol() or ""
        except Exception:
            info.alpn = ""
        info.cert_cn = _cert_common_name(der) if der else ""
        info.pin = crypto.cert_fingerprint(der) if der else ""
    info.description = (
        f"TLS {info.version} · {info.cipher} · ALPN {info.alpn or '-'} · SNI {sni or '-'}"
    )

    if verify == "pin":
        if not der:
            raise TransportError("server presented no certificate to verify")  # pragma: no cover
        expected = normalize_pin(pin)
        if not crypto.fingerprint_matches(expected, der):
            try:
                writer.close()
            except Exception:
                pass
            raise TransportError(
                f"certificate pin mismatch (server presented {info.pin}). "
                "If you rotated the relay certificate, import the new connection link."
            )
    # verify == "insecure": no PKI check. The PSK handshake inside still
    # authenticates the relay, and all tunnel payload stays encrypted.

    return TLSStream(reader, writer, info)


async def tls_connect(
    host: str,
    port: int,
    verify: str = "insecure",
    pin: str = "",
    sni: str = "",
    timeout: float = 15.0,
) -> TLSStream:
    reader, writer = await tcp_connect(host, port, timeout)
    return await tls_upgrade(reader, writer, verify, pin, sni, timeout)


# ---------------------------------------------------------------------------
# Plain TCP + SOCKS5 (used for relay -> target and optional upstream proxies)
# ---------------------------------------------------------------------------


class Socks5Error(Exception):
    pass


async def tcp_connect(host: str, port: int, timeout: float = 15.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        raise TransportError(f"connect to {host}:{port} failed: {exc}") from exc


async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    username: str = "",
    password: str = "",
    timeout: float = 20.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP stream to *dest* through a SOCKS5 proxy (CONNECT only)."""
    reader, writer = await tcp_connect(proxy_host, proxy_port, timeout)
    try:
        methods = b"\x00"
        if username:
            methods = b"\x00\x02"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout)
        if resp[0] != 5:
            raise Socks5Error("not a SOCKS5 proxy")
        method = resp[1]
        if method == 0x02:
            u = username.encode()[:255]
            p = password.encode()[:255]
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            auth = await asyncio.wait_for(reader.readexactly(2), timeout)
            if auth[1] != 0:
                raise Socks5Error("SOCKS5 authentication failed")
        elif method != 0x00:
            raise Socks5Error("SOCKS5 proxy requires unsupported authentication")

        try:
            ip = ipaddress.ip_address(dest_host)
            if ip.version == 4:
                addr = b"\x01" + ip.packed
            else:
                addr = b"\x04" + ip.packed
        except ValueError:
            name = dest_host.encode("idna")
            addr = b"\x03" + bytes([len(name)]) + name
        writer.write(b"\x05\x01\x00" + addr + struct.pack(">H", dest_port))
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(4), timeout)
        if head[0] != 5 or head[1] != 0:
            raise Socks5Error(f"SOCKS5 connect failed (code {head[1]})")
        atyp = head[3]
        if atyp == 1:
            await reader.readexactly(4)
        elif atyp == 4:
            await reader.readexactly(16)
        elif atyp == 3:
            (n,) = await reader.readexactly(1)
            await reader.readexactly(n)
        await reader.readexactly(2)
        return reader, writer
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        raise
