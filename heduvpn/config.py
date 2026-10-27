"""Configuration objects and (de)serialisation for HeduVPN."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from . import crypto
from .protocol import PAD_MODES


class ConfigError(Exception):
    pass


@dataclass
class ConnectionConfig:
    server: str = "127.0.0.1"
    port: int = 443
    sni: str = ""
    transport: str = "ws"  # "ws" (looks like HTTPS traffic) or "tls"
    ws_path: str = "/ws"
    ws_host: str = ""
    ws_cookie: str = "hid"
    verify: str = "pin"  # pin | system | insecure
    pin: str = ""
    connect_timeout: float = 12.0
    upstream: str = ""  # optional socks5://user:pass@host:port for the TLS leg

    def __post_init__(self) -> None:
        self.sni = self.sni or self.server

    @property
    def ws_host_header(self) -> str:
        return self.ws_host or self.sni

    def validate(self) -> None:
        if self.transport not in ("ws", "tls"):
            raise ConfigError("transport must be 'ws' or 'tls'")
        if self.verify not in ("pin", "system", "insecure"):
            raise ConfigError("verify must be pin, system or insecure")
        if not self.server:
            raise ConfigError("server is required")
        if not 1 <= int(self.port) <= 65535:
            raise ConfigError("port must be between 1 and 65535")
        if self.verify == "pin" and not self.pin:
            raise ConfigError("verify=pin requires a certificate pin from the relay")
        if self.ws_path and not self.ws_path.startswith("/"):
            raise ConfigError("ws_path must start with '/'")
        if self.upstream and not self.upstream.startswith("socks5://"):
            raise ConfigError("upstream must be a socks5:// URL")


@dataclass
class CamouflageConfig:
    padding: str = "random"
    jitter_ms: int = 12
    cover: str = "low"  # none | low | medium
    rotate_minutes: int = 0

    def validate(self) -> None:
        if self.padding not in PAD_MODES:
            raise ConfigError(f"padding must be one of {', '.join(PAD_MODES)}")
        if self.cover not in ("none", "low", "medium"):
            raise ConfigError("cover must be none, low or medium")
        if self.jitter_ms < 0 or self.jitter_ms > 500:
            raise ConfigError("jitter_ms must be between 0 and 500")
        if self.rotate_minutes < 0 or self.rotate_minutes > 1440:
            raise ConfigError("rotate_minutes must be between 0 and 1440")


@dataclass
class SocksConfig:
    host: str = "127.0.0.1"
    port: int = 1080
    proxy_port: int = 0  # optional local HTTP CONNECT proxy, 0 = off
    allow_lan: bool = False
    dns: str = "system"  # system | dns | remote
    dns_server: str = "1.1.1.1"
    username: str = ""
    password: str = ""

    def validate(self) -> None:
        if self.dns not in ("system", "dns", "remote"):
            raise ConfigError("dns must be system, dns or remote")
        for name, value in (("port", self.port), ("proxy_port", self.proxy_port)):
            if not 0 <= int(value) <= 65535:
                raise ConfigError(f"{name} must be between 0 and 65535")
        if self.port == 0:
            raise ConfigError("a local SOCKS port is required")
        if not self.allow_lan and self.host not in ("127.0.0.1", "::1", "localhost"):
            raise ConfigError("non-loopback listen address requires allow_lan")


@dataclass
class ClientSettings:
    psk: str = ""
    name: str = "HeduVPN"
    connection: ConnectionConfig = field(default_factory=ConnectionConfig)
    camouflage: CamouflageConfig = field(default_factory=CamouflageConfig)
    socks: SocksConfig = field(default_factory=SocksConfig)

    def validate(self) -> None:
        if not self.psk:
            raise ConfigError("psk is required")
        try:
            crypto.decode_psk(self.psk)
        except crypto.CryptoError as exc:
            raise ConfigError(str(exc)) from exc
        self.connection.validate()
        self.camouflage.validate()
        self.socks.validate()

    @property
    def psk_bytes(self) -> bytes:
        return crypto.decode_psk(self.psk)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClientSettings":
        try:
            conn = ConnectionConfig(**_known(ConnectionConfig, data.get("connection", {})))
            camo = CamouflageConfig(**_known(CamouflageConfig, data.get("camouflage", {})))
            socks = SocksConfig(**_known(SocksConfig, data.get("socks", {})))
            settings = cls(
                psk=data.get("psk", ""),
                name=data.get("name", "HeduVPN"),
                connection=conn,
                camouflage=camo,
                socks=socks,
            )
        except TypeError as exc:
            raise ConfigError(f"invalid settings: {exc}") from exc
        settings.validate()
        return settings

    @classmethod
    def from_json(cls, text: str) -> "ClientSettings":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError("settings must be a JSON object")
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str) -> "ClientSettings":
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    def save(self, path: str) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(self.to_json() + "\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _known(dc: type, data: Any) -> dict[str, Any]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError("settings sections must be JSON objects")
    names = {f.name for f in fields(dc)}
    unknown = set(data) - names
    if unknown:
        raise ConfigError(f"unknown keys in {dc.__name__}: {', '.join(sorted(unknown))}")
    return data


def build_client_settings(server: str, psk: str, **overrides: Any) -> ClientSettings:
    """Convenience used by the wizard / import flow."""
    connection = ConnectionConfig(server=server)
    connection.__dict__.update({k: v for k, v in overrides.items() if k in {f.name for f in fields(ConnectionConfig)}})
    socks = SocksConfig()
    socks.__dict__.update({k: v for k, v in overrides.items() if k in {f.name for f in fields(SocksConfig)}})
    camo = CamouflageConfig()
    camo.__dict__.update({k: v for k, v in overrides.items() if k in {f.name for f in fields(CamouflageConfig)}})
    return ClientSettings(psk=psk, connection=connection, camouflage=camo, socks=socks)
