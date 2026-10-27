"""HeduVPN command line interface."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import os
import platform
import socket
import sys
import time

from . import __version__, crypto
from .config import ClientSettings, ConfigError
from .link import LinkError, decode_link, encode_link, extract_link, link_for_relay, summarize_link
from .protocol import PAD_MODES
from .relay import Relay, RelayError, RelaySettings, load_relay_config, save_relay_config

STATE_DIR = os.path.expanduser("~/.heduvpn")


# ---------------------------------------------------------------------------
# Pretty output
# ---------------------------------------------------------------------------


class Style:
    enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    @classmethod
    def wrap(cls, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.wrap(text, "1")

    @classmethod
    def dim(cls, text: str) -> str:
        return cls.wrap(text, "2")

    @classmethod
    def mint(cls, text: str) -> str:
        return cls.wrap(text, "38;5;79")

    @classmethod
    def blue(cls, text: str) -> str:
        return cls.wrap(text, "38;5;111")

    @classmethod
    def amber(cls, text: str) -> str:
        return cls.wrap(text, "38;5;215")

    @classmethod
    def red(cls, text: str) -> str:
        return cls.wrap(text, "38;5;203")


def info(message: str) -> None:
    print(message, flush=True)


def ok(message: str) -> None:
    print(f"{Style.mint('✓')} {message}", flush=True)


def warn(message: str) -> None:
    print(f"{Style.amber('!')} {message}", flush=True)


def fail(message: str, code: int = 1) -> int:
    print(f"{Style.red('✗')} {message}", file=sys.stderr, flush=True)
    return code


def banner() -> None:
    print()
    print(Style.bold("  HeduVPN ") + Style.dim(f"v{__version__} · an HTTPS-shaped tunnel"))
    print()


def psk_fingerprint(psk: str) -> str:
    return "sha256:" + hashlib.sha256(crypto.decode_psk(psk)).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_or_create_psk(path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    psk = crypto.encode_psk(crypto.generate_psk())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(psk + "\n")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return psk


def _print_link_card(link: str, settings: RelaySettings) -> None:
    summary = summarize_link(link)
    print()
    print(Style.bold("  Client connection link") + Style.dim("  (contains the key — share privately)"))
    print()
    print("  " + Style.mint(link))
    print()
    rows = [
        ("server", f"{summary['server']}:{summary['port']}"),
        ("SNI", summary["sni"]),
        ("transport", f"{summary['transport']} · {summary['path']}"),
        ("verify", summary["verify"] + (" · " + summary["pin"][:23] + "…" if summary["pin"] else "")),
        ("PSK", psk_fingerprint(settings.psk)),
        ("decoy site", settings.decoy_site),
    ]
    width = max(len(k) for k, _ in rows) + 2
    for key, value in rows:
        print(f"  {Style.dim(key.ljust(width))}{value}")
    print()


async def _serve_relay(settings: RelaySettings, link: str, state_dir: str) -> int:
    relay = Relay(settings, log=lambda line: print(line, flush=True))
    try:
        await relay.start()
    except OSError as exc:
        if getattr(exc, "errno", None) in (1, 13):
            return fail(
                f"cannot bind {settings.listen_host}:{settings.listen_port} ({exc}). "
                "Ports below 1024 need root or CAP_NET_BIND_SERVICE; try --port 8443."
            )
        return fail(f"cannot start relay: {exc}")
    print()
    ok(f"relay is up on {settings.listen_host}:{settings.listen_port}")
    print(Style.dim("  press Ctrl+C to stop. Decoy website and tunnel share this one port."))
    print()
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await relay.stop()
    return 0


def _prepare_relay(args) -> tuple[RelaySettings, str, str]:
    default_state = os.path.join(STATE_DIR, "relay")
    if args.config and not args.state_dir:
        default_state = os.path.dirname(os.path.abspath(os.path.expanduser(args.config)))
    state_dir = os.path.abspath(os.path.expanduser(args.state_dir or default_state))
    os.makedirs(state_dir, exist_ok=True)
    psk_path = os.path.join(state_dir, "psk")

    if args.config:
        settings = load_relay_config(args.config)
    else:
        settings = RelaySettings()

    domain = args.domain or settings.domain or "localhost"
    if args.port:
        settings.listen_port = int(args.port)
    if args.listen_host:
        settings.listen_host = args.listen_host
    if args.decoy_site:
        settings.decoy_site = args.decoy_site
    if args.padding:
        settings.padding = args.padding
    if args.log:
        settings.log_path = args.log
    if args.allow_private:
        settings.allow_private = True
    if args.allow_ports:
        settings.allow_ports = tuple(int(p.strip()) for p in args.allow_ports.split(",") if p.strip())
    if args.block_hosts:
        settings.block_hosts = tuple(h.strip() for h in args.block_hosts.split(",") if h.strip())
    settings.domain = domain
    if not settings.psk:
        settings.psk = args.psk or _load_or_create_psk(psk_path)
    elif args.psk:
        settings.psk = args.psk

    if args.plaintext:
        settings.tls = False
        settings.behind_proxy = True
        settings.certfile = ""
        settings.keyfile = ""
    elif args.cert or args.key:
        if not (args.cert and args.key):
            raise RelayError("--cert and --key must be used together")
        settings.tls = True
        settings.certfile = os.path.abspath(os.path.expanduser(args.cert))
        settings.keyfile = os.path.abspath(os.path.expanduser(args.key))
    else:
        identity = crypto.load_or_create_identity(state_dir, domain)
        settings.tls = True
        settings.certfile = os.path.join(state_dir, "cert.pem")
        settings.keyfile = os.path.join(state_dir, "key.pem")
        if not settings.psk:
            settings.psk = crypto.encode_psk(identity.psk)
    if args.transport == "tls" and not settings.tls:
        raise RelayError("native TLS transport needs TLS termination on the relay")
    if args.transport == "tls" and settings.behind_proxy:
        raise RelayError("behind a reverse proxy, use the websocket transport")

    settings.validate()
    if not args.config:
        save_relay_config(settings, os.path.join(state_dir, "relay.json"))

    public_host = args.public_host or (("127.0.0.1" if domain == "localhost" else domain))
    if settings.behind_proxy:
        public_port = int(args.public_port or 443)
        verify = "system"
    else:
        public_port = int(args.public_port or settings.listen_port)
        verify = "pin"
    transport = args.transport or "ws"
    link = link_for_relay(
        psk=settings.psk,
        host=public_host,
        port=public_port,
        sni=domain,
        certfile=settings.certfile if settings.tls else "",
        transport=transport,
        verify=verify,
        ws_path=settings.ws_path,
        ws_cookie=settings.ws_cookie,
        name=f"{domain} · HeduVPN",
    )
    link_path = os.path.join(state_dir, "client-link.txt")
    with open(link_path, "w", encoding="utf-8") as fh:
        fh.write(link + "\n")
    with contextlib.suppress(OSError):
        os.chmod(link_path, 0o600)
    try:
        config = decode_link(link)
        config.save(os.path.join(state_dir, "client.json"))
    except LinkError:
        pass
    return settings, link, state_dir


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_relay(args) -> int:
    try:
        settings, link, state_dir = _prepare_relay(args)
    except (RelayError, LinkError, OSError) as exc:
        return fail(str(exc))
    banner()
    print(Style.bold("  Relay"))
    rows = [
        ("listen", f"{settings.listen_host}:{settings.listen_port}"),
        ("TLS", "terminated here" if settings.tls else "terminated by your proxy/CDN"),
        ("public name", settings.domain or "localhost"),
        ("transports", f"websocket {settings.ws_path}" + ("" if settings.behind_proxy else " + native TLS")),
        ("certificate", settings.certfile or "—"),
        ("policy", ("private targets allowed" if settings.allow_private else "private targets blocked")),
    ]
    width = max(len(k) for k, _ in rows) + 2
    for key, value in rows:
        print(f"  {Style.dim(key.ljust(width))}{value}")
    if settings.domain in ("", "localhost"):
        warn("domain is localhost — the link will only work from this machine. Use --domain <your.domain> for a real deployment.")
    _print_link_card(link, settings)
    print(Style.dim(f"  saved: {os.path.join(state_dir, 'client-link.txt')}"))
    print(Style.dim(f"         {os.path.join(state_dir, 'client.json')}"))
    print()
    if args.link_only:
        return 0
    try:
        return asyncio.run(_serve_relay(settings, link, state_dir))
    except KeyboardInterrupt:
        info("")
        info("relay stopped")
        return 0


def cmd_client(args) -> int:
    try:
        settings = _client_settings_from_args(args)
    except (LinkError, ConfigError, OSError) as exc:
        return fail(str(exc))
    banner()
    print(Style.bold("  Client"))
    rows = [
        ("server", f"{settings.connection.server}:{settings.connection.port}"),
        ("transport", f"{settings.connection.transport} · {settings.connection.ws_path}"),
        ("verify", settings.connection.verify + (f" · {settings.connection.pin[:23]}…" if settings.connection.pin else "")),
        ("SOCKS5", f"{settings.socks.host}:{settings.socks.port}"),
        ("HTTP proxy", f"{settings.socks.host}:{settings.socks.proxy_port}" if settings.socks.proxy_port else "off"),
        ("padding / cover", f"{settings.camouflage.padding} / {settings.camouflage.cover}"),
        ("DNS", settings.socks.dns),
        ("system proxy", "point it at the tunnel while connected" if getattr(args, "system_proxy", False) else "off"),
    ]
    width = max(len(k) for k, _ in rows) + 2
    for key, value in rows:
        print(f"  {Style.dim(key.ljust(width))}{value}")
    print()
    try:
        asyncio.run(_run_client(settings, args))
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        return fail(
            f"cannot start the local proxies ({exc}); is port {settings.socks.port} "
            "already in use? Try --socks-port with another port."
        )
    print()
    info(Style.dim("client stopped"))
    return 0


async def _wait_connected(client, timeout: float = 40.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if client.snapshot()["connected"]:
            return True
        if client.snapshot()["state"] in ("stopped", "error"):
            return False
        await asyncio.sleep(0.25)
    return False


async def _run_client(settings: ClientSettings, args) -> None:
    from .client import TunnelClient

    def log(line: str) -> None:
        print(Style.dim(line), flush=True)

    def on_state(state: str, detail: str) -> None:
        labels = {
            "connecting": Style.amber("connecting"),
            "connected": Style.mint("connected"),
            "reconnecting": Style.amber("reconnecting"),
            "stopped": Style.dim("stopped"),
            "error": Style.red("error"),
        }
        text = detail or ""
        lowered = text.lower()
        if state in ("connecting", "connected", "reconnecting") and lowered.startswith(state):
            text = text[len(state):].lstrip(" ·:-")
        print(f"{labels.get(state, state)} {Style.dim(text)}".rstrip(), flush=True)

    client = TunnelClient(settings, log=log, on_state=on_state)
    proxy = None
    if getattr(args, "system_proxy", False):
        from .systemproxy import SystemProxy

        proxy = SystemProxy(log=log)
        supported, note = proxy.support()
        if not supported:
            print(Style.amber(f"  system proxy unavailable: {note}"), flush=True)
            proxy = None
        elif settings.socks.host not in ("127.0.0.1", "localhost", "::1"):
            print(Style.amber("  the system proxy can only point at a loopback SOCKS listener"), flush=True)
            proxy = None
    task = asyncio.create_task(client.run(), name="cli-client")
    proxy_task = None
    if proxy is not None:
        async def arm_system_proxy() -> None:
            while True:
                snap = client.snapshot()
                if snap["connected"]:
                    break
                if snap["state"] in ("stopped", "error"):
                    return
                await asyncio.sleep(0.3)
            result = proxy.enable(settings.socks.host, settings.socks.port)
            if result.ok:
                print(Style.mint("  system proxy"), Style.dim(result.message), flush=True)
            else:
                print(Style.amber(f"  system proxy: {result.message}"), flush=True)

        proxy_task = asyncio.create_task(arm_system_proxy(), name="cli-system-proxy")
    try:
        if args.test or args.duration:
            if not await _wait_connected(client):
                fail("the tunnel did not come up")
                await client.stop()
                return
            if args.test:
                ok("tunnel connected — testing the proxy")
                try:
                    await _http_through_socks(settings.socks.host, settings.socks.port, args.test)
                except Exception as exc:  # noqa: BLE001 - user-facing diagnostics
                    fail(f"proxy test failed: {exc}")
                if args.test_only:
                    await client.stop()
            if args.duration and not args.test_only:
                print(Style.dim(f"  running for {args.duration:g}s — press Ctrl+C to stop early"))
                await asyncio.sleep(args.duration)
                await client.stop()
        await task
    finally:
        await client.stop()
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if proxy_task is not None:
            proxy_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await proxy_task
        if proxy is not None and proxy.pending_snapshot():
            restored = proxy.disable()
            print(Style.dim(f"  system proxy: {restored.message}"), flush=True)


def _client_settings_from_args(args) -> ClientSettings:
    base = ClientSettings()
    if args.config:
        base = ClientSettings.load(args.config)
    if args.link:
        base = decode_link(args.link, base=base)
    if args.server:
        base.connection.server = args.server
        base.connection.sni = args.sni or args.server
        base.connection.ws_host = args.sni or args.server
    if args.port:
        base.connection.port = int(args.port)
    if args.sni:
        base.connection.sni = args.sni
        base.connection.ws_host = args.sni
    if args.pin:
        base.connection.pin = args.pin
    if args.psk:
        base.psk = args.psk
    if args.transport:
        base.connection.transport = args.transport
    if args.verify:
        base.connection.verify = args.verify
    if args.ws_path:
        base.connection.ws_path = args.ws_path
    if args.socks_port:
        base.socks.port = int(args.socks_port)
    if args.socks_host:
        base.socks.host = args.socks_host
    if args.http_proxy:
        base.socks.proxy_port = int(args.http_proxy)
    if args.allow_lan:
        base.socks.allow_lan = True
    if args.dns:
        base.socks.dns = args.dns
    if args.dns_server:
        base.socks.dns_server = args.dns_server
    if args.padding:
        base.camouflage.padding = args.padding
    if args.jitter is not None:
        base.camouflage.jitter_ms = int(args.jitter)
    if args.cover:
        base.camouflage.cover = args.cover
    if args.rotate is not None:
        base.camouflage.rotate_minutes = int(args.rotate)
    base.validate()
    return base


def cmd_system_proxy(args) -> int:
    """Flip the OS proxy settings by hand (normally the GUI/client do this)."""
    from .systemproxy import SystemProxy

    proxy = SystemProxy()
    if args.action == "status":
        status = proxy.status()
        rows = [
            ("platform", str(status.get("platform"))),
            ("supported", "yes" if status.get("supported") else "no"),
            ("note", str(status.get("note"))),
            ("enabled", "yes" if status.get("enabled") else "no"),
            ("snapshot saved", "yes" if status.get("restore_pending") else "no"),
        ]
        width = max(len(key) for key, _ in rows) + 2
        for key, value in rows:
            print(f"  {Style.dim(key.ljust(width))}{value}")
        return 0
    if args.action == "off":
        result = proxy.disable()
    else:
        try:
            settings = ClientSettings.load(args.config) if args.config else ClientSettings()
        except (ConfigError, OSError) as exc:
            return fail(str(exc))
        host = args.host or settings.socks.host
        port = args.port or settings.socks.port
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if host not in ("127.0.0.1", "localhost", "::1"):
            return fail("the system proxy can only point at a loopback SOCKS listener")
        result = proxy.enable(host, port)
    if result.ok:
        ok(result.message)
        return 0
    return fail(result.message)


def cmd_dashboard(args) -> int:
    from .dashboard import Dashboard

    dashboard = Dashboard(
        host=args.host,
        port=args.port,
        relay_config=args.relay_config or "",
        client_config=args.client_config or "",
        client_link=args.link or "",
        start_lab=not args.no_lab,
    )
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        warn("the dashboard exposes your configuration and can start a client — bind it to loopback unless you know what you are doing")
    try:
        asyncio.run(dashboard.serve_forever())
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        return fail(
            f"cannot start the dashboard on {args.host}:{args.port} ({exc}); "
            "try another --port or stop the process that already uses it"
        )
    return 0


def cmd_import(args) -> int:
    try:
        link = extract_link(args.link)
        settings = decode_link(link)
    except (LinkError, ConfigError, OSError) as exc:
        return fail(str(exc))
    if args.socks_port:
        settings.socks.port = int(args.socks_port)
    if args.http_proxy:
        settings.socks.proxy_port = int(args.http_proxy)
    if args.padding:
        settings.camouflage.padding = args.padding
    if args.cover:
        settings.camouflage.cover = args.cover
    if args.rotate is not None:
        settings.camouflage.rotate_minutes = int(args.rotate)
    if args.dns:
        settings.socks.dns = args.dns
    out = os.path.abspath(os.path.expanduser(args.out))
    try:
        settings.save(out)
    except OSError as exc:
        return fail(f"could not write {out}: {exc}")
    ok(f"connection saved to {out}")
    summary = summarize_link(encode_link(settings))
    width = max(len(k) for k in summary) + 2
    for key in ("name", "server", "port", "sni", "transport", "verify", "pin", "psk_fingerprint"):
        print(f"  {Style.dim(key.ljust(width))}{summary[key]}")
    print()
    print(Style.dim(f"  run: heduvpn client --config {out}"))
    return 0


def cmd_link(args) -> int:
    try:
        link = extract_link(args.link)
        summary = summarize_link(link)
        settings = decode_link(link)
    except (LinkError, ConfigError) as exc:
        return fail(str(exc))
    print()
    print(Style.bold("  Connection link"))
    width = max(len(k) for k in summary) + 2
    for key in ("name", "server", "port", "sni", "transport", "path", "verify", "pin", "psk_fingerprint", "padding", "cover"):
        print(f"  {Style.dim(key.ljust(width))}{summary[key]}")
    print()
    print(Style.dim(f"  local proxies: socks {settings.socks.host}:{settings.socks.port}, HTTP {'on' if settings.socks.proxy_port else 'off'}"))
    print()
    return 0


def cmd_check(args) -> int:
    if not args.relay and not args.url:
        return fail("pass --relay host:port and/or --url http://…")
    if args.relay:
        try:
            asyncio.run(_probe_relay(args))
        except Exception as exc:  # noqa: BLE001 - diagnostics should not traceback
            return fail(f"relay probe failed: {exc}")
    if args.url:
        host, port = _parse_hostport(args.socks or "127.0.0.1:1080", 1080)
        try:
            asyncio.run(_http_through_socks(host, port, args.url))
        except Exception as exc:  # noqa: BLE001
            return fail(f"proxy check failed: {exc}")
    return 0


async def _probe_relay(args) -> None:
    from .transport import tls_connect
    from .httpwire import read_response_headers_with_rest

    host, port = _parse_hostport(args.relay, 443)
    sni = args.sni or host
    stream = await tls_connect(host, port, verify="insecure", sni=sni, timeout=8)
    info = stream.info
    print()
    print(Style.bold("  Relay TLS probe"))
    print(f"  {'endpoint'.ljust(14)}{host}:{port} (SNI {sni})")
    print(f"  {'protocol'.ljust(14)}{info.version} · {info.cipher} · ALPN {info.alpn or '-'}")
    print(f"  {'certificate'.ljust(14)}CN {info.cert_cn or '—'}")
    print(f"  {'pin'.ljust(14)}{info.pin or '—'}")
    if args.pin:
        expected = args.pin.strip().lower()
        actual = (info.pin or "").lower()
        if expected == actual:
            ok("pin matches the relay certificate")
        else:
            warn("pin does NOT match the certificate the relay presented")
    stream.writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: heduvpn-check\r\nConnection: close\r\n\r\n")
    await stream.writer.drain()
    status, headers, rest = await read_response_headers_with_rest(stream.reader, timeout=6)
    body = rest
    while len(body) < 4096:
        try:
            chunk = await asyncio.wait_for(stream.reader.read(4096), 2)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        body += chunk
    print(f"  {'decoy'.ljust(14)}HTTP {status} · Server: {headers.get('server', '—')} · {len(body)} bytes")
    stream.close()
    print()


async def _http_through_socks(socks_host: str, socks_port: int, url: str) -> None:
    from urllib.parse import urlsplit

    from .transport import socks5_connect

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("url must start with http:// or https://")
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if not host:
        raise ValueError("url has no hostname")
    reader, writer = await socks5_connect(socks_host, socks_port, host, port, timeout=15)
    if parts.scheme == "https":
        from .transport import tls_upgrade

        await tls_upgrade(reader, writer, verify="system", sni=host)
    host_header = host if port in (80, 443) else f"{host}:{port}"
    writer.write(
        f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: heduvpn-check\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
    body = await asyncio.wait_for(reader.read(4096), 10)
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print()
    print(Style.bold("  Proxy check"))
    print(f"  {'url'.ljust(10)}{url}")
    print(f"  {'status'.ljust(10)}{status_line}")
    if body:
        preview = body.decode("utf-8", "replace").strip().splitlines()
        if preview:
            print(f"  {'body'.ljust(10)}{preview[0][:100]}")
    print()
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    ok("request travelled through the tunnel")


def cmd_doctor(args) -> int:
    from .transport import tls_connect

    print()
    print(Style.bold("  HeduVPN doctor"))
    print()
    checks: list[tuple[str, bool, str]] = []
    py = sys.version_info
    checks.append(("python", py >= (3, 10), platform.python_version()))
    try:
        import cryptography

        checks.append(("cryptography", True, cryptography.__version__))
    except Exception as exc:  # pragma: no cover
        checks.append(("cryptography", False, str(exc)))
    checks.append(("mode", True, "SOCKS5 + HTTP proxy — no TUN device or admin rights required"))
    try:
        from .systemproxy import SystemProxy

        proxy = SystemProxy()
        supported, note = proxy.support()
        pending = proxy.pending_snapshot()
        detail = note + (" · previous settings still saved; run `heduvpn system-proxy off`" if pending else "")
        checks.append(("system proxy", supported, detail))
    except Exception as exc:  # pragma: no cover - platform dependent
        checks.append(("system proxy", False, str(exc)))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 1080))
        checks.append(("socks port 1080", True, "free"))
    except OSError:
        checks.append(("socks port 1080", False, "already in use"))
    client_config = os.path.join(STATE_DIR, "client.json")
    checks.append(("client config", True, client_config if os.path.exists(client_config) else "none yet"))
    relay_config = os.path.join(STATE_DIR, "relay", "relay.json")
    checks.append(("relay config", True, relay_config if os.path.exists(relay_config) else "none yet (this machine is not a relay)"))

    if args.server:
        host, port = _parse_hostport(args.server, 443)
        try:
            stream = asyncio.run(tls_connect(host, port, verify="insecure", sni=args.sni or host, timeout=8))
            checks.append(("relay reachable", True, f"{host}:{port} · {stream.info.version} · ALPN {stream.info.alpn or '-'}"))
            if args.pin and stream.info.pin:
                checks.append(("pin", args.pin.lower() == stream.info.pin.lower(), stream.info.pin))
            stream.close()
        except Exception as exc:  # noqa: BLE001
            checks.append(("relay reachable", False, f"{host}:{port} · {exc}"))

    width = max(len(name) for name, _, _ in checks) + 2
    all_ok = True
    for name, good, detail in checks:
        all_ok = all_ok and good
        mark = Style.mint("✓") if good else Style.amber("!")
        print(f"  {mark} {name.ljust(width)}{Style.dim(detail)}")
    print()
    if all_ok:
        ok("everything needed for a tunnel is present")
    else:
        warn("some checks need attention")
    print(Style.dim("  GUI: python -m heduvpn gui (tkinter; on Debian/Ubuntu: apt install python3-tk)"))
    print()
    return 0


def cmd_wizard(args) -> int:
    banner()
    print(Style.bold("  Setup wizard"))
    print("  1) I want to run a relay (server)")
    print("  2) I want to connect a client")
    print("  3) I want to explore the dashboard")
    print()
    try:
        choice = input("  choose [1/2/3]: ").strip() or "3"
    except EOFError:
        return fail("no input available — use the non-interactive commands instead")
    if choice == "1":
        return _wizard_relay()
    if choice == "2":
        return _wizard_client()
    args.host = "127.0.0.1"
    args.port = 8000
    args.relay_config = ""
    args.client_config = ""
    args.link = ""
    args.no_lab = False
    return cmd_dashboard(args)


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return value or default


def _wizard_relay() -> int:
    domain = _ask("public domain (e.g. vpn.example.com)", "localhost")
    port = int(_ask("local listen port", "443"))
    behind = _ask("is TLS terminated by a reverse proxy/CDN? (y/N)", "n").lower().startswith("y")
    public_port = int(_ask("public port", "443" if behind else str(port)))
    cert = _ask("TLS certificate file (blank = generate a self-signed one)", "")
    key = _ask("TLS private key file", "") if cert else ""
    state_dir = _ask("state directory", os.path.join(STATE_DIR, "relay"))
    args = argparse.Namespace(
        config=None,
        domain=domain,
        public_host=domain,
        public_port=public_port,
        port=port,
        listen_host="0.0.0.0",
        psk=None,
        cert=cert or None,
        key=key or None,
        plaintext=behind,
        transport="ws",
        decoy_site=None,
        padding=None,
        allow_private=False,
        allow_ports=None,
        block_hosts=None,
        log=None,
        state_dir=state_dir,
        link_only=False,
    )
    return cmd_relay(args)


def _wizard_client() -> int:
    link = _ask("paste your hedu1:// link")
    if not link:
        return fail("a connection link is required")
    socks_port = int(_ask("local SOCKS port", "1080"))
    http_port = int(_ask("local HTTP proxy port (0 to disable)", "0"))
    padding = _ask("padding mode (none/random/cells)", "random")
    cover = _ask("cover traffic (none/low/medium)", "low")
    out = os.path.join(STATE_DIR, "client.json")
    args = argparse.Namespace(
        link=link,
        out=out,
        socks_port=socks_port,
        http_proxy=http_port,
        padding=padding,
        cover=cover,
        rotate=None,
        dns=None,
    )
    code = cmd_import(args)
    if code:
        return code
    print()
    print(Style.bold("  Next steps"))
    print(f"  heduvpn client --config {out}")
    print(Style.dim("  or use the desktop app: python -m heduvpn gui"))
    return 0


def cmd_gui(args) -> int:
    try:
        from .gui.app import main as gui_main
    except ImportError as exc:
        return fail(
            "the desktop GUI needs tkinter, which ships with python.org builds; "
            f"on Debian/Ubuntu install python3-tk ({exc})"
        )
    try:
        gui_main(
            connect=getattr(args, "connect", False),
            system_proxy=getattr(args, "system_proxy", False),
        )
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _parse_hostport(text: str, default_port: int) -> tuple[str, int]:
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if text.count(":") == 1:
        host, port_s = text.split(":")
        return host, int(port_s)
    if text.count(":") > 1:
        return text, default_port
    return text, default_port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="heduvpn",
        description="HeduVPN — a censorship-resistant, HTTPS-shaped VPN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  heduvpn relay --domain vpn.example.com --port 443\n"
            "  heduvpn client --link 'hedu1://…'\n"
            "  heduvpn dashboard --port 8000\n"
            "  heduvpn wizard\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"HeduVPN {__version__}")
    sub = parser.add_subparsers(dest="command")

    relay = sub.add_parser("relay", help="run the relay server")
    relay.add_argument("--config", help="load a relay.json configuration")
    relay.add_argument("--domain", help="public hostname (certificate CN and SNI)")
    relay.add_argument("--port", type=int, help="local listen port (default 443)")
    relay.add_argument("--listen-host", dest="listen_host", help="bind address (default 0.0.0.0)")
    relay.add_argument("--public-host", dest="public_host", help="hostname placed in the client link")
    relay.add_argument("--public-port", dest="public_port", type=int, help="port placed in the client link")
    relay.add_argument("--state-dir", dest="state_dir", help="where cert/key/psk/config live")
    relay.add_argument("--cert", help="TLS certificate (PEM, e.g. Let's Encrypt fullchain)")
    relay.add_argument("--key", help="TLS private key (PEM)")
    relay.add_argument("--psk", help="pre-shared key (default: generated in the state dir)")
    relay.add_argument("--plaintext", action="store_true", help="TLS is terminated by a reverse proxy/CDN")
    relay.add_argument("--transport", choices=["ws", "tls"], help="transport advertised in the link (default ws)")
    relay.add_argument("--padding", choices=PAD_MODES, help="padding mode for relay->client records")
    relay.add_argument("--decoy-site", dest="decoy_site", help="title of the decoy website")
    relay.add_argument("--allow-private", dest="allow_private", action="store_true", help="allow private/loopback destinations (dangerous)")
    relay.add_argument("--allow-ports", dest="allow_ports", help="comma separated destination port allowlist")
    relay.add_argument("--block-hosts", dest="block_hosts", help="comma separated hostname denylist")
    relay.add_argument("--log", help="write relay logs to this file")
    relay.add_argument("--link-only", dest="link_only", action="store_true", help="prepare config and print the link, then exit")
    relay.set_defaults(func=cmd_relay)

    client = sub.add_parser("client", help="run the tunnel client with a local SOCKS5 proxy")
    client.add_argument("--link", help="hedu1:// connection link (or a file containing one)")
    client.add_argument("--config", help="client settings JSON")
    client.add_argument("--server", help="relay hostname or IP")
    client.add_argument("--port", type=int, help="relay TCP port")
    client.add_argument("--sni", help="TLS SNI / expected hostname")
    client.add_argument("--pin", help="certificate pin (sha256:…)")
    client.add_argument("--psk", help="pre-shared key")
    client.add_argument("--transport", choices=["ws", "tls"], help="tunnel transport")
    client.add_argument("--verify", choices=["pin", "system", "insecure"], help="certificate validation mode")
    client.add_argument("--ws-path", dest="ws_path", help="WebSocket path")
    client.add_argument("--socks-port", dest="socks_port", type=int, help="local SOCKS5 port (default 1080)")
    client.add_argument("--socks-host", dest="socks_host", help="local SOCKS5 bind address")
    client.add_argument("--http-proxy", dest="http_proxy", type=int, help="also listen with an HTTP CONNECT proxy on this port")
    client.add_argument("--allow-lan", dest="allow_lan", action="store_true", help="allow non-loopback clients to use the proxies")
    client.add_argument("--dns", choices=["system", "dns", "remote"], help="DNS strategy (remote sends hostnames to the relay)")
    client.add_argument("--dns-server", dest="dns_server", help="resolver used when --dns dns")
    client.add_argument("--padding", choices=PAD_MODES, help="record padding")
    client.add_argument("--jitter", type=int, help="timing jitter in milliseconds")
    client.add_argument("--cover", choices=["none", "low", "medium"], help="cover traffic")
    client.add_argument("--rotate", type=int, help="rotate the tunnel session after N minutes (0 = never)")
    client.add_argument("--test", help="after connecting, fetch this URL through the proxy")
    client.add_argument("--test-only", dest="test_only", action="store_true", help="exit after the --test request")
    client.add_argument("--duration", type=float, help="stop automatically after N seconds")
    client.add_argument("--system-proxy", dest="system_proxy", action="store_true",
                        help="point the OS proxy at the tunnel while connected; restore it on exit")
    client.set_defaults(func=cmd_client)

    dash = sub.add_parser("dashboard", help="serve the web dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    dash.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    dash.add_argument("--relay-config", dest="relay_config", help="also run a live relay from this config")
    dash.add_argument("--client-config", dest="client_config", help="preload client settings")
    dash.add_argument("--link", help="preload a connection link")
    dash.add_argument("--no-lab", dest="no_lab", action="store_true", help="do not start the loopback laboratory")
    dash.set_defaults(func=cmd_dashboard)

    imp = sub.add_parser("import", help="import a connection link into a settings file")
    imp.add_argument("link", help="hedu1:// link or a file containing one")
    imp.add_argument("--out", default=os.path.join(STATE_DIR, "client.json"), help="output settings path")
    imp.add_argument("--socks-port", dest="socks_port", type=int, help="local SOCKS port to store")
    imp.add_argument("--http-proxy", dest="http_proxy", type=int, help="local HTTP proxy port to store")
    imp.add_argument("--padding", choices=PAD_MODES, help="record padding")
    imp.add_argument("--cover", choices=["none", "low", "medium"], help="cover traffic")
    imp.add_argument("--rotate", type=int, help="session rotation in minutes")
    imp.add_argument("--dns", choices=["system", "dns", "remote"], help="DNS strategy")
    imp.set_defaults(func=cmd_import)

    link = sub.add_parser("link", help="inspect a connection link")
    link.add_argument("link", help="hedu1:// link or a file containing one")
    link.set_defaults(func=cmd_link)

    check = sub.add_parser("check", help="probe a relay or test the local proxy")
    check.add_argument("--relay", help="host:port of a relay to probe")
    check.add_argument("--sni", help="SNI to use for the probe")
    check.add_argument("--pin", help="expected certificate pin")
    check.add_argument("--socks", help="local socks host:port (default 127.0.0.1:1080)")
    check.add_argument("--url", help="fetch this URL through the local proxy")
    check.set_defaults(func=cmd_check)

    doctor = sub.add_parser("doctor", help="check the local environment")
    doctor.add_argument("--server", help="optional relay host:port to test")
    doctor.add_argument("--sni", help="SNI for the relay test")
    doctor.add_argument("--pin", help="expected certificate pin")
    doctor.set_defaults(func=cmd_doctor)

    wiz = sub.add_parser("wizard", help="interactive setup")
    wiz.set_defaults(func=cmd_wizard)

    sysproxy = sub.add_parser("system-proxy", help="point the OS proxy at the local SOCKS port")
    sysproxy.add_argument("action", choices=["on", "off", "status"], help="on, off (restore) or status")
    sysproxy.add_argument("--config", help="client settings used for the SOCKS host/port")
    sysproxy.add_argument("--host", help="SOCKS host override")
    sysproxy.add_argument("--port", type=int, help="SOCKS port override")
    sysproxy.set_defaults(func=cmd_system_proxy)

    gui = sub.add_parser("gui", help="start the desktop GUI (tkinter)")
    gui.add_argument("--connect", action="store_true", help="connect immediately with the saved settings")
    gui.add_argument("--system-proxy", dest="system_proxy", action="store_true",
                     help="also point the OS proxy at the tunnel while connected")
    gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        banner()
        parser.print_help()
        print()
        return 0
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print()
        return 130
    except (ConfigError, LinkError, RelayError) as exc:
        return fail(str(exc))
    except BrokenPipeError:
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
