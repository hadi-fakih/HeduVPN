"""Tiny HTTP/1.1 helpers: request parsing, response headers and decoys.

HeduVPN does not use an HTTP framework.  The WebSocket transport and the
HTTP CONNECT proxy need just enough parsing to be useful, and the relay needs
believable responses for active probes.
"""

from __future__ import annotations

import asyncio
import email.utils
import html
import os
import random
from dataclasses import dataclass, field


class HttpError(Exception):
    pass


MAX_HEADER = 16 * 1024


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes = b""
    rest: bytes = b""

    def get(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def header_list(self, name: str) -> list[str]:
        return [v.strip() for v in self.get(name).split(",") if v.strip()]

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def host(self) -> str:
        return self.get("host")


async def read_request(
    reader: asyncio.StreamReader,
    initial: bytes = b"",
    limit: int = MAX_HEADER,
    timeout: float = 10.0,
) -> HttpRequest:
    async def _read() -> bytes:
        buf = bytearray(initial)
        while b"\r\n\r\n" not in buf:
            if len(buf) > limit:
                raise HttpError("request header too large")
            chunk = await reader.read(1024)
            if not chunk:
                raise HttpError("connection closed before request completed")
            buf.extend(chunk)
        return bytes(buf)

    try:
        raw = await asyncio.wait_for(_read(), timeout)
    except asyncio.TimeoutError as exc:
        raise HttpError("request timeout") from exc

    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError as exc:
        raise HttpError("malformed request line") from exc
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise HttpError("malformed header")
        name = name.strip().lower()
        value = value.strip()
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return HttpRequest(
        method=method.upper(),
        target=target,
        version=version,
        headers=headers,
        raw=head + b"\r\n\r\n",
        rest=rest,
    )


def build_request(method: str, target: str, headers: list[tuple[str, str]]) -> bytes:
    lines = [f"{method} {target} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


async def read_response_headers(
    reader: asyncio.StreamReader, limit: int = MAX_HEADER, timeout: float = 10.0
) -> tuple[int, dict[str, str]]:
    status, headers, _rest = await read_response_headers_with_rest(reader, limit, timeout)
    return status, headers


async def read_response_headers_with_rest(
    reader: asyncio.StreamReader, limit: int = MAX_HEADER, timeout: float = 10.0
) -> tuple[int, dict[str, str], bytes]:
    async def _read() -> bytes:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            if len(buf) > limit:
                raise HttpError("response header too large")
            chunk = await reader.read(1024)
            if not chunk:
                raise HttpError("connection closed before response")
            buf.extend(chunk)
        return bytes(buf)

    try:
        raw = await asyncio.wait_for(_read(), timeout)
    except asyncio.TimeoutError as exc:
        raise HttpError("response timeout") from exc
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise HttpError("malformed status line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return int(parts[1]), headers, rest


# ---------------------------------------------------------------------------
# Decoy responses
# ---------------------------------------------------------------------------

_NGINX_BODIES = (
    "<html>\r\n<head><title>400 Bad Request</title></head>\r\n"
    "<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n"
    "<hr><center>{server}</center>\r\n</body>\r\n</html>\r\n",
    "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
    "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
    "<hr><center>{server}</center>\r\n</body>\r\n</html>\r\n",
)

def _site_page(title: str) -> str:
    safe = html.escape(title)
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{safe}</title>\n"
        "<style>body{max-width:46rem;margin:4rem auto;padding:0 1.25rem;line-height:1.65;"
        "font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#223}"
        "h1{font-size:1.6rem;margin-bottom:.5rem}"
        "p{color:#556}footer{margin-top:3rem;font-size:.8rem;color:#889}"
        "@media(prefers-color-scheme:dark){body{background:#0e1216;color:#e6edf3}"
        "p{color:#9fb0bf}footer{color:#6b7c8b}}</style>\n"
        "</head>\n<body>\n"
        f"<h1>{safe}</h1>\n"
        "<p>This site is being prepared. Please check back soon.</p>\n"
        "<p>If you are the operator of this domain, the web server is running and ready.</p>\n"
        f"<footer>{safe}</footer>\n"
        "</body>\n</html>\n"
    )

def _date_header() -> str:
    return email.utils.formatdate(usegmt=True)


def decoy_response(
    path: str = "/",
    method: str = "GET",
    status: int | None = None,
    server: str = "nginx/1.24.0",
    site_title: str = "Hedu Labs",
    rng: random.Random | None = None,
) -> bytes:
    """Return a byte-for-byte ordinary-looking HTTP response.

    ``status`` forces a code; otherwise ``/`` serves a small welcome page and
    everything else is a 404 -- exactly what a default web server does.
    """
    rng = rng or random.Random()
    if status is not None:
        code = status
    elif path in ("/", "/index.html") and method in ("GET", "HEAD"):
        code = 200
    else:
        code = 404

    if code == 200:
        body = _site_page(site_title)
        content_type = "text/html; charset=utf-8"
    elif code == 400:
        body = _NGINX_BODIES[0].format(server=server)
        content_type = "text/html"
    else:
        body = _NGINX_BODIES[1].format(server=server)
        content_type = "text/html"

    payload = body.encode("utf-8")
    headers = [
        ("Server", server),
        ("Date", _date_header()),
        ("Content-Type", content_type),
        ("Content-Length", str(len(payload))),
        ("Connection", "close"),
    ]
    if code == 200:
        headers.append(("ETag", f'"{rng.getrandbits(48):012x}"'))
        headers.append(("Last-Modified", _date_header()))
    reason = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found"}.get(code, "OK")
    head = f"HTTP/1.1 {code} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + payload


def response_101(accept: str, protocol: str | None = None) -> bytes:
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept}",
        f"Date: {_date_header()}",
    ]
    if protocol:
        lines.append(f"Sec-WebSocket-Protocol: {protocol}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def connect_established() -> bytes:
    return b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: heduvpn\r\n\r\n"


def random_chrome_ua(rng: random.Random | None = None) -> str:
    rng = rng or random.Random(os.urandom(4))
    versions = ("124.0.0.0", "125.0.0.0", "126.0.0.0", "127.0.0.0")
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{rng.choice(versions)} Safari/537.36"
    )
