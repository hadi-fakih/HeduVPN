"""Optional system-proxy integration for the desktop app.

HeduVPN runs as a local SOCKS5/HTTP proxy rather than installing a kernel
driver.  Most applications (and every browser) will use it if the OS proxy
settings point at it.  This module flips those settings, remembers exactly
what was there before, and puts it back -- including after a crash via the
snapshot file.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any

SNAPSHOT_BACKUP = os.path.join(os.path.expanduser("~/.heduvpn"), "systemproxy.json")


def _run(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


@dataclass
class ProxyResult:
    ok: bool
    message: str
    detail: dict[str, Any] | None = None


class SystemProxy:
    def __init__(self, snapshot_path: str = SNAPSHOT_BACKUP, log=None) -> None:
        self.system = platform.system()
        self.snapshot_path = snapshot_path
        self.log = log or (lambda message: None)

    # -- capability --------------------------------------------------------
    def support(self) -> tuple[bool, str]:
        if self.system == "Windows":
            return True, "Windows per-user proxy (WinINET)"
        if self.system == "Darwin":
            if shutil.which("networksetup"):
                return True, "macOS SOCKS firewall proxy"
            return False, "networksetup not found"
        if shutil.which("gsettings"):
            return True, "GNOME proxy settings"
        return False, "automatic system proxy is supported on Windows, macOS and GNOME"

    def pending_snapshot(self) -> bool:
        return os.path.exists(self.snapshot_path)

    # -- public API --------------------------------------------------------
    def status(self) -> dict[str, Any]:
        supported, note = self.support()
        info: dict[str, Any] = {
            "supported": supported,
            "note": note,
            "platform": self.system,
            "restore_pending": self.pending_snapshot(),
            "enabled": False,
        }
        try:
            if self.system == "Windows":
                values = self._win_read()
                info["enabled"] = bool(values.get("ProxyEnable")) and "socks=" in str(values.get("ProxyServer", "")).lower()
                info["proxy"] = str(values.get("ProxyServer", ""))
            elif self.system == "Darwin":
                service = self._mac_service()
                code, out = _run(["networksetup", "-getsocksfirewallproxy", service])
                info["service"] = service
                info["enabled"] = code == 0 and "Enabled: Yes" in out
                info["detail"] = out.strip()
            elif supported:
                code, out = _run(["gsettings", "get", "org.gnome.system.proxy", "mode"])
                info["enabled"] = code == 0 and "manual" in out
                code, out = _run(["gsettings", "get", "org.gnome.system.proxy.socks", "host"])
                info["proxy"] = out.strip().strip("'")
        except Exception as exc:  # pragma: no cover - platform dependent
            info["error"] = str(exc)
        return info

    def enable(self, host: str = "127.0.0.1", port: int = 1080) -> ProxyResult:
        supported, note = self.support()
        if not supported:
            return ProxyResult(False, note)
        if self.pending_snapshot():
            # Do not overwrite the original state with our own settings.
            self.log("system proxy already has a saved snapshot; restoring it first")
            restored = self.disable()
            if not restored.ok:
                return restored
        try:
            if self.system == "Windows":
                return self._win_enable(host, port)
            if self.system == "Darwin":
                return self._mac_enable(host, port)
            return self._linux_enable(host, port)
        except Exception as exc:
            return ProxyResult(False, f"could not change the system proxy: {exc}")

    def disable(self) -> ProxyResult:
        if not os.path.exists(self.snapshot_path):
            return ProxyResult(True, "nothing to restore")
        try:
            with open(self.snapshot_path, encoding="utf-8") as fh:
                snapshot = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return ProxyResult(False, f"could not read the proxy snapshot: {exc}")
        owner = str(snapshot.get("platform") or "")
        if owner and owner != self.system:
            # A snapshot from another OS (dual boot, shared home) must not be
            # consumed or "restored" with the wrong tools.
            return ProxyResult(
                False,
                f"saved proxy settings belong to {owner}; leaving them untouched",
            )
        try:
            if snapshot.get("platform") == "Windows":
                self._win_restore(snapshot)
            elif snapshot.get("platform") == "Darwin":
                self._mac_restore(snapshot)
            elif snapshot.get("platform") == "Linux":
                self._linux_restore(snapshot)
            os.remove(self.snapshot_path)
            self.log("system proxy restored")
            return ProxyResult(True, "previous proxy settings restored")
        except Exception as exc:
            return ProxyResult(False, f"could not restore the system proxy: {exc}")

    # -- Windows -----------------------------------------------------------
    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def _win_read(self) -> dict[str, Any]:
        import winreg  # type: ignore[import-not-found]

        values: dict[str, Any] = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_PATH) as key:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                    values[name] = value
                except FileNotFoundError:
                    values[name] = None
        return values

    def _win_write(self, name: str, value: Any) -> None:
        import winreg  # type: ignore[import-not-found]

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, self.REG_PATH, 0, winreg.KEY_SET_VALUE
        ) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            elif isinstance(value, int):
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def _win_refresh(self) -> None:
        try:
            import ctypes

            wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
            wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
        except Exception:
            pass

    def _win_enable(self, host: str, port: int) -> ProxyResult:
        snapshot = {"platform": "Windows", "applied_at": time.time(), **self._win_read()}
        self._save(snapshot)
        override = snapshot.get("ProxyOverride") or ""
        bypass = [part for part in override.split(";") if part]
        for needed in ("<local>", "127.*", "10.*", "172.16.*", "192.168.*"):
            if needed not in bypass:
                bypass.append(needed)
        self._win_write("ProxyServer", f"socks={host}:{port}")
        self._win_write("ProxyEnable", 1)
        self._win_write("ProxyOverride", ";".join(bypass))
        self._win_write("AutoConfigURL", None)
        self._win_refresh()
        return ProxyResult(True, f"system SOCKS proxy set to {host}:{port}", snapshot)

    def _win_restore(self, snapshot: dict[str, Any]) -> None:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            self._win_write(name, snapshot.get(name))
        self._win_refresh()

    # -- macOS -------------------------------------------------------------
    def _mac_service(self) -> str:
        code, out = _run(["networksetup", "-listallnetworkservices"])
        services = [
            line.strip()
            for line in out.splitlines()
            if line.strip() and not line.startswith("An asterisk") and not line.startswith("*")
        ]
        for preferred in ("Wi-Fi", "Ethernet", "USB 10/100/1000 LAN", "Thunderbolt Ethernet"):
            if preferred in services:
                return preferred
        return services[0] if services else "Wi-Fi"

    def _mac_settings(self, service: str) -> dict[str, Any]:
        code, out = _run(["networksetup", "-getsocksfirewallproxy", service])
        settings = {"service": service, "enabled": False, "server": "0.0.0.0", "port": 0}
        for line in out.splitlines():
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "enabled":
                settings["enabled"] = value.lower() == "yes"
            elif key == "server":
                settings["server"] = value
            elif key == "port":
                settings["port"] = int(value) if value.isdigit() else 0
        return settings

    def _mac_enable(self, host: str, port: int) -> ProxyResult:
        service = self._mac_service()
        snapshot = {"platform": "Darwin", "applied_at": time.time(), **self._mac_settings(service)}
        self._save(snapshot)
        code, out = _run(["networksetup", "-setsocksfirewallproxy", service, host, str(port)])
        if code != 0:
            os.remove(self.snapshot_path)
            return ProxyResult(False, f"networksetup failed (admin rights may be required): {out.strip()}")
        _run(["networksetup", "-setsocksfirewallproxystate", service, "on"])
        return ProxyResult(True, f"system SOCKS proxy set to {host}:{port} on {service}", snapshot)

    def _mac_restore(self, snapshot: dict[str, Any]) -> None:
        service = snapshot.get("service") or self._mac_service()
        server = snapshot.get("server") or "0.0.0.0"
        port = snapshot.get("port") or 0
        _run(["networksetup", "-setsocksfirewallproxy", service, str(server), str(port)])
        _run([
            "networksetup",
            "-setsocksfirewallproxystate",
            service,
            "on" if snapshot.get("enabled") else "off",
        ])

    # -- GNOME -------------------------------------------------------------
    def _gsettings_get(self, schema: str, key: str) -> str:
        code, out = _run(["gsettings", "get", schema, key])
        return out.strip()

    def _linux_enable(self, host: str, port: int) -> ProxyResult:
        snapshot = {
            "platform": "Linux",
            "applied_at": time.time(),
            "mode": self._gsettings_get("org.gnome.system.proxy", "mode"),
            "host": self._gsettings_get("org.gnome.system.proxy.socks", "host"),
            "port": self._gsettings_get("org.gnome.system.proxy.socks", "port"),
        }
        self._save(snapshot)
        _run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", host])
        _run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)])
        code, out = _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"])
        if code != 0:
            os.remove(self.snapshot_path)
            return ProxyResult(False, f"gsettings failed: {out.strip()}")
        return ProxyResult(True, f"GNOME SOCKS proxy set to {host}:{port}", snapshot)

    def _linux_restore(self, snapshot: dict[str, Any]) -> None:
        if snapshot.get("host") is not None:
            _run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", str(snapshot["host"]).strip("'")])
        if snapshot.get("port") is not None:
            _run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(snapshot["port"])])
        mode = str(snapshot.get("mode") or "none").strip().strip("'")
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", mode])

    # -- snapshot ----------------------------------------------------------
    def _save(self, data: dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.snapshot_path), exist_ok=True)
        tmp = self.snapshot_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.snapshot_path)
        try:
            os.chmod(self.snapshot_path, 0o600)
        except OSError:
            pass
