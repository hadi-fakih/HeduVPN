"""Native (tkinter) desktop client for HeduVPN.

Runs the same engine as the CLI inside a background asyncio loop and shows
live tunnel metadata.  No third-party GUI dependency: tkinter ships with
python.org builds on Windows and macOS.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import os
import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from collections import deque
from tkinter import messagebox, ttk
from typing import Any

from ..client import TunnelClient
from ..config import ClientSettings, ConfigError
from ..link import LinkError, decode_link
from ..systemproxy import SystemProxy

BG = "#080d13"
PANEL = "#0c151e"
PANEL_2 = "#101c27"
LINE = "#1b2c3a"
LINE_SOFT = "#14212c"
TEXT = "#e7f1f8"
MUTED = "#8ba1b3"
MUTED_2 = "#62788a"
MINT = "#3ee0b3"
BLUE = "#6ea8fe"
AMBER = "#ffbf69"
RED = "#ff7285"
STATE_FILE = os.path.join(os.path.expanduser("~/.heduvpn"), "client.json")

PAD_CHOICES = ("random", "cells", "none")
COVER_CHOICES = ("low", "medium", "none")
DNS_CHOICES = ("system", "dns", "remote")
TRANSPORT_CHOICES = ("ws", "tls")


def fmt_bytes(n: float) -> str:
    n = float(n or 0)
    if n < 1:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024.0
        idx += 1
    return f"{n:.0f} {units[idx]}" if (n >= 100 or idx == 0) else f"{n:.1f} {units[idx]}"


def fmt_rate(n: float) -> str:
    return fmt_bytes(n) + "/s"


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds or 0))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m {sec:02d}s"


def short_pin(pin: str) -> str:
    if not pin:
        return "—"
    body = pin.replace("sha256:", "")
    return "sha256:" + body[:10] + "…" + body[-6:]


class Controller:
    """Owns the asyncio loop and the TunnelClient; safe to call from Tk."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.latest: dict[str, Any] = {}
        self.records: deque[dict[str, Any]] = deque(maxlen=240)
        self.client: TunnelClient | None = None
        self.task: asyncio.Task | None = None
        self.sampler: asyncio.Task | None = None
        self.settings: ClientSettings | None = None
        self.system_proxy = SystemProxy(log=lambda line: self.events.put(("log", line)))
        self._thread = threading.Thread(target=self._thread_main, name="heduvpn-engine", daemon=True)
        self._thread.start()

    def _thread_main(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    # -- thread-safe submission -------------------------------------------
    def submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def connect(self, settings: ClientSettings):
        return self.submit(self._connect(settings))

    def stop(self):
        return self.submit(self._stop())

    def shutdown(self) -> None:
        try:
            self.submit(self._stop()).result(timeout=8)
        except Exception:
            pass
        with contextlib.suppress(Exception):
            self.loop.call_soon_threadsafe(self.loop.stop)
        with contextlib.suppress(Exception):
            self._thread.join(timeout=5)

    # -- engine ------------------------------------------------------------
    async def _connect(self, settings: ClientSettings) -> None:
        await self._stop()
        self.settings = settings
        self.records.clear()
        client = TunnelClient(settings, log=lambda line: self.events.put(("log", line)),
                              on_state=lambda state, detail: self.events.put(("state", (state, detail))))
        client.observers.append(self.records.append)
        self.client = client
        self.task = asyncio.create_task(self._run_client(client), name="gui-client")
        self.sampler = asyncio.create_task(self._sample(client), name="gui-sampler")
        self.latest = client.snapshot()

    async def _run_client(self, client: TunnelClient) -> None:
        try:
            await client.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self.events.put(("log", f"engine error: {exc}"))

    async def _sample(self, client: TunnelClient) -> None:
        try:
            while True:
                self.latest = client.snapshot()
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            raise

    async def _stop(self) -> None:
        client, task, sampler = self.client, self.task, self.sampler
        self.client = None
        self.task = None
        self.sampler = None
        if client:
            with contextlib.suppress(Exception):
                await client.stop()
        if sampler:
            sampler.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await sampler
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self.latest = {}


class App:
    def __init__(self, root: tk.Tk, connect: bool = False, system_proxy: bool = False) -> None:
        self.root = root
        self.controller = Controller()
        self.settings: ClientSettings | None = None
        self.proxy = self.controller.system_proxy
        self.proxy_enabled_for_session = False
        self._last_log_index = 0
        self._last_record_t = 0.0
        self._connect_requested = False
        self._state = "idle"
        self._detail = ""

        self._setup_window()
        self._load_settings()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(250, self._poll)
        if system_proxy and self.proxy.support()[0]:
            self.proxy_var.set(True)
        if connect and self.settings:
            self.root.after(600, self._connect)

    # ---------------------------------------------------------------- window
    def _setup_window(self) -> None:
        self.root.title("HeduVPN")
        self.root.configure(bg=BG)
        self.root.minsize(980, 680)
        try:
            self.root.tk.call("tk", "scaling", 1.15)
        except Exception:
            pass
        style = ttk.Style(self.root)
        with contextlib.suppress(Exception):
            style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, fieldbackground=PANEL_2,
                        bordercolor=LINE, lightcolor=LINE, darkcolor=LINE, focuscolor=MINT)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED)
        style.configure("Dim.TLabel", background=PANEL, foreground=MUTED_2)
        style.configure("Title.TLabel", background=PANEL, foreground=TEXT, font=("TkDefaultFont", 11, "bold"))
        style.configure("Value.TLabel", background=PANEL, foreground=TEXT, font=("TkFixedFont", 10))
        style.configure("Big.TLabel", background=PANEL, foreground=TEXT, font=("TkDefaultFont", 20, "bold"))
        style.configure("TButton", background=PANEL_2, foreground=TEXT, borderwidth=0, focusthickness=0,
                        padding=(12, 7))
        style.map("TButton", background=[("active", "#172634")], foreground=[("disabled", MUTED_2)])
        style.configure("Accent.TButton", background=MINT, foreground="#04120e",
                        font=("TkDefaultFont", 10, "bold"), padding=(16, 9))
        style.map("Accent.TButton", background=[("active", "#5ff0c5"), ("disabled", "#174237")],
                  foreground=[("disabled", MUTED)])
        style.configure("Danger.TButton", background="#3a1a20", foreground="#ffb3bd", padding=(16, 9))
        style.map("Danger.TButton", background=[("active", "#4d2028")])
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(16, 8), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", PANEL_2)], foreground=[("selected", TEXT)])
        style.configure("TEntry", fieldbackground=PANEL_2, foreground=TEXT, insertcolor=TEXT, padding=6,
                        bordercolor=LINE)
        style.configure("TCombobox", fieldbackground=PANEL_2, background=PANEL_2, foreground=TEXT,
                        arrowcolor=MUTED, padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL_2)])
        style.configure("TSpinbox", fieldbackground=PANEL_2, foreground=TEXT, arrowcolor=MUTED, padding=5)
        style.configure("TCheckbutton", background=PANEL, foreground=MUTED, focuscolor=PANEL)
        style.map("TCheckbutton", background=[("active", PANEL)])
        style.configure("Wire.Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=21, borderwidth=0, font=("TkFixedFont", 9))
        style.configure("Wire.Treeview.Heading", background=PANEL_2, foreground=MUTED_2,
                        font=("TkDefaultFont", 8, "bold"), borderwidth=0)
        style.map("Wire.Treeview", background=[("selected", "#1a2b38")])
        style.configure("Vertical.TScrollbar", background=PANEL_2, troughcolor=PANEL, borderwidth=0,
                        arrowcolor=MUTED)
        style.configure("Horizontal.TScale", background=PANEL, troughcolor=PANEL_2)

        self.f_title = tkfont.nametofont("TkDefaultFont").copy()
        self.f_title.configure(size=11, weight="bold")
        self.f_big = tkfont.nametofont("TkDefaultFont").copy()
        self.f_big.configure(size=21, weight="bold")
        self.f_mono = tkfont.nametofont("TkFixedFont").copy()
        self.f_mono.configure(size=9)

    # ---------------------------------------------------------------- settings
    def _load_settings(self) -> None:
        try:
            if os.path.exists(STATE_FILE):
                self.settings = ClientSettings.load(STATE_FILE)
        except (ConfigError, OSError) as exc:
            self.settings = None
            self._initial_error = str(exc)
        else:
            self._initial_error = ""

    def _save_settings(self) -> None:
        if not self.settings:
            return
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            self.settings.save(STATE_FILE)
        except OSError:
            pass

    # ---------------------------------------------------------------- ui
    def _card(self, parent, title: str | None = None) -> tk.Frame:
        outer = tk.Frame(parent, bg=PANEL, highlightbackground=LINE, highlightthickness=1, bd=0)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=14, pady=12)
        if title:
            tk.Label(inner, text=title, bg=PANEL, fg=TEXT, font=self.f_title, anchor="w").pack(fill="x", pady=(0, 8))
        outer.inner = inner  # type: ignore[attr-defined]
        return outer

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=20, pady=(16, 6))
        left = tk.Frame(header, bg=BG)
        left.pack(side="left")
        tk.Label(left, text="HeduVPN", bg=BG, fg=TEXT, font=("TkDefaultFont", 15, "bold")).pack(anchor="w")
        tk.Label(left, text="an HTTPS-shaped tunnel", bg=BG, fg=MUTED_2,
                 font=("TkDefaultFont", 9)).pack(anchor="w")

        right = tk.Frame(header, bg=BG)
        right.pack(side="right")
        self.status_pill = tk.Label(right, text="disconnected", bg=PANEL_2, fg=MUTED,
                                    padx=12, pady=6, font=("TkDefaultFont", 9, "bold"))
        self.status_pill.pack(side="left", padx=(0, 12))
        self.connect_btn = ttk.Button(right, text="Connect", style="Accent.TButton", command=self._toggle_connection)
        self.connect_btn.pack(side="left")

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=(8, 18))
        body.columnconfigure(0, weight=0, minsize=330)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left_col = tk.Frame(body, bg=BG)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 16))

        # -- connection card
        card = self._card(left_col, "Connection")
        card.pack(fill="x")
        self.state_label = tk.Label(card.inner, text="Not connected", bg=PANEL, fg=TEXT,
                                    font=("TkDefaultFont", 13, "bold"), anchor="w")
        self.state_label.pack(fill="x")
        self.detail_label = tk.Label(card.inner, text="import a connection link to begin", bg=PANEL,
                                     fg=MUTED_2, font=("TkDefaultFont", 8), anchor="w", wraplength=290,
                                     justify="left")
        self.detail_label.pack(fill="x", pady=(0, 8))
        self.fact_labels: dict[str, tk.Label] = {}
        facts = [
            ("server", "Server"), ("transport", "Transport"), ("tls", "TLS"),
            ("pin", "Certificate pin"), ("session", "Session"), ("rtt", "Round trip"),
        ]
        for key, label in facts:
            row = tk.Frame(card.inner, bg=PANEL)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8),
                     anchor="w", width=15).pack(side="left")
            value = tk.Label(row, text="—", bg=PANEL, fg="#cfe2ec", font=self.f_mono, anchor="w")
            value.pack(side="left", fill="x", expand=True)
            self.fact_labels[key] = value

        # -- proxies card
        card = self._card(left_col, "Local proxies")
        card.pack(fill="x", pady=(14, 0))
        socks_row = tk.Frame(card.inner, bg=PANEL)
        socks_row.pack(fill="x", pady=2)
        tk.Label(socks_row, text="SOCKS5", bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8),
                 width=15, anchor="w").pack(side="left")
        self.socks_value = tk.Label(socks_row, text="127.0.0.1:1080", bg=PANEL, fg="#cfe2ec",
                                    font=self.f_mono, anchor="w")
        self.socks_value.pack(side="left")
        tk.Button(socks_row, text="copy", bg=PANEL_2, fg=MUTED, bd=0, padx=7, pady=1,
                  activebackground=LINE, activeforeground=TEXT,
                  font=("TkDefaultFont", 8), command=self._copy_socks).pack(side="right")
        http_row = tk.Frame(card.inner, bg=PANEL)
        http_row.pack(fill="x", pady=2)
        tk.Label(http_row, text="HTTP proxy", bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8),
                 width=15, anchor="w").pack(side="left")
        self.http_value = tk.Label(http_row, text="off", bg=PANEL, fg="#cfe2ec", font=self.f_mono, anchor="w")
        self.http_value.pack(side="left")
        self.proxy_var = tk.BooleanVar(value=False)
        self.proxy_check = ttk.Checkbutton(card.inner, text="Use as system proxy while connected",
                                           variable=self.proxy_var, command=self._toggle_system_proxy)
        self.proxy_check.pack(anchor="w", pady=(8, 0))
        self.proxy_note = tk.Label(card.inner, text="", bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8),
                                   anchor="w", wraplength=290, justify="left")
        self.proxy_note.pack(fill="x", pady=(2, 0))
        supported, note = self.proxy.support()
        if not supported:
            self.proxy_check.state(["disabled"])
            self.proxy_note.configure(text=note)
        elif self.proxy.pending_snapshot():
            self.proxy_note.configure(text="previous proxy settings are saved; disconnect restores them", fg=AMBER)

        # -- traffic card
        card = self._card(left_col, "Traffic")
        card.pack(fill="both", expand=True, pady=(14, 0))
        rate_row = tk.Frame(card.inner, bg=PANEL)
        rate_row.pack(fill="x")
        self.up_label = tk.Label(rate_row, text="↑ 0 B/s", bg=PANEL, fg=MINT,
                                 font=("TkDefaultFont", 13, "bold"), anchor="w")
        self.up_label.pack(side="left")
        self.down_label = tk.Label(rate_row, text="↓ 0 B/s", bg=PANEL, fg=BLUE,
                                   font=("TkDefaultFont", 13, "bold"), anchor="e")
        self.down_label.pack(side="right")
        self.spark = tk.Canvas(card.inner, height=74, bg=PANEL, highlightthickness=0)
        self.spark.pack(fill="x", pady=6)
        self.totals_label = tk.Label(card.inner, text="0 B sent · 0 B received", bg=PANEL, fg=MUTED,
                                     font=("TkDefaultFont", 8), anchor="w")
        self.totals_label.pack(fill="x")
        self.session_stats = tk.Label(card.inner, text="no active session", bg=PANEL, fg=MUTED_2,
                                      font=self.f_mono, anchor="w", justify="left")
        self.session_stats.pack(fill="x", pady=(4, 0))

        # -- notebook
        notebook = ttk.Notebook(body)
        notebook.grid(row=0, column=1, sticky="nsew")
        self.notebook = notebook
        self._build_wire_tab(notebook)
        self._build_setup_tab(notebook)
        self._build_logs_tab(notebook)
        self._build_help_tab(notebook)
        self._refresh_form()
        self._refresh_static()

    def _build_wire_tab(self, notebook) -> None:
        tab = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab, text="Wire")
        pad = tk.Frame(tab, bg=PANEL)
        pad.pack(fill="both", expand=True, padx=16, pady=14)
        top = tk.Frame(pad, bg=PANEL)
        top.pack(fill="x")
        tk.Label(top, text="What a network observer sees", bg=PANEL, fg=TEXT, font=self.f_title).pack(side="left")
        tk.Label(top, text="metadata only · no payload is logged", bg=PANEL, fg=MUTED_2,
                 font=("TkDefaultFont", 8)).pack(side="right")
        self.hist = tk.Canvas(pad, height=150, bg=PANEL, highlightthickness=0)
        self.hist.pack(fill="x", pady=(10, 4))
        metrics = tk.Frame(pad, bg=PANEL)
        metrics.pack(fill="x", pady=(4, 10))
        self.metric_labels: dict[str, tk.Label] = {}
        for idx, (key, label) in enumerate([
            ("overhead", "wire overhead"), ("pad", "cover bytes"),
            ("avg", "average record"), ("unique", "distinct sizes"),
            ("records", "records seen"), ("spacing", "median spacing"),
        ]):
            cell = tk.Frame(metrics, bg=PANEL)
            cell.grid(row=idx // 3, column=idx % 3, sticky="w", padx=(0, 26), pady=4)
            tk.Label(cell, text=label.upper(), bg=PANEL, fg=MUTED_2,
                     font=("TkDefaultFont", 7, "bold")).pack(anchor="w")
            value = tk.Label(cell, text="—", bg=PANEL, fg="#cfe2ec", font=self.f_mono)
            value.pack(anchor="w")
            self.metric_labels[key] = value

        table_frame = tk.Frame(pad, bg=PANEL)
        table_frame.pack(fill="both", expand=True)
        columns = ("time", "dir", "type", "wire", "pad")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Wire.Treeview", height=9)
        headings = {"time": "time", "dir": "", "type": "frame", "wire": "wire", "pad": "padding"}
        widths = {"time": 76, "dir": 26, "type": 100, "wire": 84, "pad": 74}
        for col in columns:
            self.tree.heading(col, text=headings[col], anchor="w")
            self.tree.column(col, width=widths[col], anchor="w", stretch=(col == "type"))
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.tag_configure("out", foreground=MINT)
        self.tree.tag_configure("in", foreground=BLUE)
        self.tree.tag_configure("pad", foreground=MUTED_2)

        note = ("Records are padded inside the encrypted envelope; the size column is what the "
                "network sees, the padding column is cover traffic. Change padding in Setup.")
        tk.Label(pad, text=note, bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8),
                 wraplength=640, justify="left").pack(fill="x", pady=(8, 0))

    def _build_setup_tab(self, notebook) -> None:
        outer = tk.Frame(notebook, bg=PANEL)
        notebook.add(outer, text="Setup")
        pad = tk.Frame(outer, bg=PANEL)
        pad.pack(fill="both", expand=True, padx=16, pady=14)

        tk.Label(pad, text="Connection link", bg=PANEL, fg=TEXT, font=self.f_title).pack(anchor="w")
        tk.Label(pad, text="Paste the hedu1:// link generated by your relay (includes address, SNI, pin and key).",
                 bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8), wraplength=640,
                 justify="left").pack(anchor="w", pady=(2, 6))
        link_row = tk.Frame(pad, bg=PANEL)
        link_row.pack(fill="x")
        self.link_entry = ttk.Entry(link_row)
        self.link_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(link_row, text="Import", command=self._import_link_from_entry).pack(side="left", padx=(8, 0))
        self.link_summary = tk.Label(pad, text="no link imported", bg=PANEL, fg=MUTED_2,
                                     font=self.f_mono, anchor="w", justify="left", wraplength=650)
        self.link_summary.pack(fill="x", pady=(6, 14))

        form = tk.Frame(pad, bg=PANEL)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        row = 0

        def add_row(label: str, widget) -> None:
            nonlocal row
            tk.Label(form, text=label, bg=PANEL, fg=MUTED, font=("TkDefaultFont", 9),
                     anchor="w").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 14))
            widget.grid(row=row, column=1, sticky="ew", pady=4)
            row += 1

        self.socks_port_var = tk.StringVar(value="1080")
        self.socks_entry = ttk.Entry(form, textvariable=self.socks_port_var, width=12)
        add_row("Local SOCKS port", self.socks_entry)
        self.http_port_var = tk.StringVar(value="0")
        self.http_entry = ttk.Entry(form, textvariable=self.http_port_var, width=12)
        add_row("Local HTTP proxy port (0 = off)", self.http_entry)

        self.transport_var = tk.StringVar(value="ws")
        self.transport_combo = ttk.Combobox(form, textvariable=self.transport_var,
                                            values=TRANSPORT_CHOICES, state="readonly", width=12)
        add_row("Tunnel transport", self.transport_combo)

        self.padding_var = tk.StringVar(value="random")
        self.padding_combo = ttk.Combobox(form, textvariable=self.padding_var,
                                          values=PAD_CHOICES, state="readonly", width=12)
        add_row("Record padding", self.padding_combo)

        self.cover_var = tk.StringVar(value="low")
        self.cover_combo = ttk.Combobox(form, textvariable=self.cover_var,
                                        values=COVER_CHOICES, state="readonly", width=12)
        add_row("Cover traffic", self.cover_combo)

        self.dns_var = tk.StringVar(value="system")
        self.dns_combo = ttk.Combobox(form, textvariable=self.dns_var,
                                      values=DNS_CHOICES, state="readonly", width=12)
        add_row("DNS strategy", self.dns_combo)

        jitter_row = tk.Frame(form, bg=PANEL)
        jitter_row.grid(row=row, column=1, sticky="ew", pady=4)
        self.jitter_var = tk.IntVar(value=12)
        self.jitter_scale = ttk.Scale(jitter_row, from_=0, to=120, orient="horizontal",
                                      variable=self.jitter_var, command=lambda v: self._jitter_changed(v))
        self.jitter_scale.pack(side="left", fill="x", expand=True)
        self.jitter_value = tk.Label(jitter_row, text="12 ms", bg=PANEL, fg=MINT, font=self.f_mono, width=7)
        self.jitter_value.pack(side="left", padx=(8, 0))
        tk.Label(form, text="Timing jitter", bg=PANEL, fg=MUTED, font=("TkDefaultFont", 9),
                 anchor="w").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 14))
        row += 1

        self.rotate_var = tk.StringVar(value="0")
        self.rotate_spin = ttk.Spinbox(form, from_=0, to=1440, textvariable=self.rotate_var, width=10)
        add_row("Rotate session after (minutes)", self.rotate_spin)

        tk.Label(pad, text=("Changes apply to the next connection. The relay must support the chosen "
                            "transport; native TLS is leaner, WebSocket survives CDNs."),
                 bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8), wraplength=650,
                 justify="left").pack(anchor="w", pady=(10, 8))
        actions = tk.Frame(pad, bg=PANEL)
        actions.pack(fill="x")
        ttk.Button(actions, text="Save & reconnect", style="Accent.TButton", command=self._apply_form).pack(side="left")
        ttk.Button(actions, text="Save only", command=self._save_form_only).pack(side="left", padx=(8, 0))
        self.setup_status = tk.Label(actions, text="", bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8))
        self.setup_status.pack(side="left", padx=(12, 0))

    def _build_logs_tab(self, notebook) -> None:
        tab = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab, text="Logs")
        pad = tk.Frame(tab, bg=PANEL)
        pad.pack(fill="both", expand=True, padx=16, pady=14)
        top = tk.Frame(pad, bg=PANEL)
        top.pack(fill="x", pady=(0, 8))
        tk.Label(top, text="Connection log", bg=PANEL, fg=TEXT, font=self.f_title).pack(side="left")
        ttk.Button(top, text="Clear", command=lambda: self.log_text.delete("1.0", "end")).pack(side="right")
        frame = tk.Frame(pad, bg=PANEL)
        frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(frame, bg="#070d13", fg="#9fb4c2", insertbackground=TEXT, bd=0,
                                font=self.f_mono, wrap="word", padx=10, pady=8,
                                highlightbackground=LINE, highlightthickness=1)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set, state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_help_tab(self, notebook) -> None:
        tab = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab, text="Help")
        pad = tk.Frame(tab, bg=PANEL)
        pad.pack(fill="both", expand=True, padx=16, pady=14)
        title = tk.Label(pad, text="How to use it", bg=PANEL, fg=TEXT, font=self.f_title, anchor="w")
        title.pack(fill="x")
        text = tk.Text(pad, bg=PANEL, fg=MUTED, bd=0, font=("TkDefaultFont", 9), wrap="word",
                       padx=0, pady=8, height=10, highlightthickness=0)
        text.pack(fill="both", expand=True)
        text.insert("1.0", HELP_TEXT)
        text.configure(state="disabled")

    # ---------------------------------------------------------------- state
    def _refresh_static(self) -> None:
        if self.settings:
            self.socks_value.configure(text=f"{self.settings.socks.host}:{self.settings.socks.port}")
            self.http_value.configure(
                text=f"{self.settings.socks.host}:{self.settings.socks.proxy_port}"
                if self.settings.socks.proxy_port else "off"
            )
            conn = self.settings.connection
            self.link_summary.configure(
                text=f"{self.settings.name}  ·  {conn.server}:{conn.port}  ·  "
                     f"{conn.transport}  ·  {conn.verify}  ·  {short_pin(conn.pin)}",
                fg=MUTED,
            )
        else:
            self.link_summary.configure(text="no link imported — paste one above and press Import", fg=AMBER)

    def _refresh_form(self) -> None:
        if not self.settings:
            return
        s = self.settings
        self.socks_port_var.set(str(s.socks.port))
        self.http_port_var.set(str(s.socks.proxy_port))
        self.transport_var.set(s.connection.transport)
        self.padding_var.set(s.camouflage.padding)
        self.cover_var.set(s.camouflage.cover)
        self.dns_var.set(s.socks.dns)
        self.jitter_var.set(s.camouflage.jitter_ms)
        self.jitter_value.configure(text=f"{s.camouflage.jitter_ms} ms")
        self.rotate_var.set(str(s.camouflage.rotate_minutes))

    def _jitter_changed(self, value: str) -> None:
        self.jitter_value.configure(text=f"{int(float(value))} ms")

    def _collect_form(self) -> ClientSettings | None:
        if not self.settings:
            return None
        settings = copy.deepcopy(self.settings)
        try:
            settings.socks.port = int(self.socks_port_var.get() or 1080)
            settings.socks.proxy_port = int(self.http_port_var.get() or 0)
            settings.connection.transport = self.transport_var.get()
            settings.camouflage.padding = self.padding_var.get()
            settings.camouflage.cover = self.cover_var.get()
            settings.socks.dns = self.dns_var.get()
            settings.camouflage.jitter_ms = int(float(self.jitter_var.get()))
            settings.camouflage.rotate_minutes = int(self.rotate_var.get() or 0)
            settings.validate()
            return settings
        except (ValueError, ConfigError) as exc:
            self.setup_status.configure(text=str(exc), fg=RED)
            return None

    def _import_link_from_entry(self) -> None:
        link = self.link_entry.get().strip()
        if not link:
            self._open_import_dialog()
            return
        self._import_link(link)

    def _import_link(self, link: str) -> None:
        try:
            base = self.settings or ClientSettings()
            if self.settings:
                base.socks = copy.deepcopy(self.settings.socks)
                base.camouflage = copy.deepcopy(self.settings.camouflage)
            if self.settings and self.socks_port_var.get().isdigit():
                base.socks.port = int(self.socks_port_var.get())
            settings = decode_link(link, base=base)
        except LinkError as exc:
            messagebox.showerror("HeduVPN", f"That link could not be imported:\n\n{exc}")
            return
        self.settings = settings
        self.link_entry.delete(0, "end")
        self._save_settings()
        self._refresh_static()
        self._refresh_form()
        self.setup_status.configure(text="link imported", fg=MINT)
        self.detail_label.configure(text="ready to connect")

    def _open_import_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Import connection link")
        dialog.configure(bg=BG)
        dialog.geometry("660x260")
        dialog.transient(self.root)
        frame = tk.Frame(dialog, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        frame.pack(fill="both", expand=True, padx=16, pady=16)
        tk.Label(frame, text="Paste your hedu1:// link", bg=PANEL, fg=TEXT,
                 font=self.f_title).pack(anchor="w", padx=14, pady=(14, 4))
        tk.Label(frame, text="It contains the relay address, certificate pin and key. Treat it like a password.",
                 bg=PANEL, fg=MUTED_2, font=("TkDefaultFont", 8)).pack(anchor="w", padx=14)
        text = tk.Text(frame, height=5, bg="#070d13", fg=TEXT, insertbackground=TEXT, bd=0,
                       font=self.f_mono, wrap="char", padx=10, pady=8)
        text.pack(fill="both", expand=True, padx=14, pady=10)
        def do_import() -> None:
            value = text.get("1.0", "end").strip()
            dialog.destroy()
            if value:
                self._import_link(value)
        ttk.Button(frame, text="Import link", style="Accent.TButton", command=do_import).pack(
            side="right", padx=14, pady=(0, 12))
        ttk.Button(frame, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0, 8), pady=(0, 12))
        text.focus_set()
        dialog.grab_set()

    def _apply_form(self) -> None:
        settings = self._collect_form()
        if not settings:
            return
        self.settings = settings
        self._save_settings()
        self.setup_status.configure(text="saved", fg=MINT)
        self._refresh_static()
        if self._state in ("connected", "connecting", "reconnecting"):
            self._disconnect()
            self.root.after(350, self._connect)

    def _save_form_only(self) -> None:
        settings = self._collect_form()
        if not settings:
            return
        self.settings = settings
        self._save_settings()
        self._refresh_static()
        self.setup_status.configure(text="saved", fg=MINT)

    def _copy_socks(self) -> None:
        text = self.socks_value.cget("text")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.detail_label.configure(text=f"copied {text}")

    # ---------------------------------------------------------------- engine
    def _toggle_connection(self) -> None:
        if self._state in ("connected", "connecting", "reconnecting"):
            self._disconnect()
        else:
            self._connect()

    def _connect(self) -> None:
        settings = self._collect_form()
        if settings is None:
            if not self.settings:
                messagebox.showinfo(
                    "HeduVPN",
                    "Import a connection link first.\n\n"
                    "On the relay run:\n    heduvpn relay --domain your.domain\n\n"
                    "then paste the printed hedu1:// link here.",
                )
            return
        self.settings = settings
        self._save_settings()
        self._refresh_static()
        self._connect_requested = True
        self.state_label.configure(text="Connecting…")
        self.detail_label.configure(text=f"to {settings.connection.server}:{settings.connection.port}", fg=MUTED_2)
        try:
            self.controller.connect(settings)
        except RuntimeError as exc:
            messagebox.showerror("HeduVPN", f"Could not start the engine: {exc}")
            self._connect_requested = False

    def _disconnect(self) -> None:
        self._connect_requested = False
        self._disable_system_proxy()
        try:
            self.controller.stop()
        except RuntimeError:
            pass

    def _toggle_system_proxy(self) -> None:
        if not self.proxy_var.get():
            self._disable_system_proxy()
            return
        if self._state != "connected" or not self.settings:
            self.proxy_note.configure(text="will be applied when the tunnel is connected", fg=MUTED_2)
            return
        self._enable_system_proxy()

    def _enable_system_proxy(self) -> None:
        if not self.settings or self.proxy_enabled_for_session:
            return
        result = self.proxy.enable(self.settings.socks.host, self.settings.socks.port)
        self.proxy_note.configure(text=result.message, fg=MINT if result.ok else RED)
        if result.ok:
            self.proxy_enabled_for_session = True

    def _disable_system_proxy(self) -> None:
        if not self.proxy_enabled_for_session and not self.proxy.pending_snapshot():
            return
        result = self.proxy.disable()
        if result.ok:
            self.proxy_enabled_for_session = False
            self.proxy_note.configure(text="system proxy restored", fg=MUTED_2)
        else:
            self.proxy_note.configure(text=result.message, fg=AMBER)
            messagebox.showwarning(
                "HeduVPN",
                "The system proxy could not be restored automatically.\n\n"
                + result.message
                + "\n\nCheck your OS proxy settings.",
            )

    # ---------------------------------------------------------------- polling
    def _poll(self) -> None:
        self._drain_events()
        snapshot = self.controller.latest
        if snapshot:
            self._render_snapshot(snapshot)
        else:
            self._render_idle()
        self._render_records()
        self.root.after(400, self._poll)

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.controller.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "state":
                    self._state, self._detail = payload
                    self._apply_state()
        except queue.Empty:
            pass

    def _apply_state(self) -> None:
        state = self._state
        labels = {
            "connecting": ("Connecting…", AMBER),
            "connected": ("Connected", MINT),
            "reconnecting": ("Reconnecting…", AMBER),
            "stopped": ("Disconnected", MUTED),
            "error": ("Error", RED),
            "idle": ("Disconnected", MUTED),
        }
        text, color = labels.get(state, (state.title(), MUTED))
        self.state_label.configure(text=text)
        self.state_pill_style(state)
        self.detail_label.configure(text=self._detail or "", fg=MUTED_2)
        if state in ("connected", "connecting", "reconnecting"):
            self.connect_btn.configure(text="Disconnect", style="Danger.TButton")
        else:
            self.connect_btn.configure(text="Connect", style="Accent.TButton")
        if state == "connected":
            if self.proxy_var.get():
                self._enable_system_proxy()
        elif state in ("stopped", "error"):
            if self.proxy_enabled_for_session:
                self._disable_system_proxy()
            self._connect_requested = False

    def state_pill_style(self, state: str) -> None:
        colors = {
            "connected": ("#0f2a23", MINT),
            "connecting": ("#2a2313", AMBER),
            "reconnecting": ("#2a2313", AMBER),
            "error": ("#2a1418", RED),
        }
        bg, fg = colors.get(state, (PANEL_2, MUTED))
        self.status_pill.configure(bg=bg, fg=fg, text=state.upper())

    def _render_idle(self) -> None:
        state = self._state if self._state not in ("idle",) else "idle"
        if state in ("stopped", "idle"):
            self.status_pill.configure(bg=PANEL_2, fg=MUTED, text="OFFLINE")
            self.connect_btn.configure(text="Connect", style="Accent.TButton")
            if not self._connect_requested:
                self.state_label.configure(text="Not connected")
        if not self.controller.latest:
            for value in self.fact_labels.values():
                value.configure(text="—")
            self.up_label.configure(text="↑ 0 B/s")
            self.down_label.configure(text="↓ 0 B/s")
            self.totals_label.configure(text="0 B sent · 0 B received")
            self.session_stats.configure(text="no active session")

    def _render_snapshot(self, snap: dict[str, Any]) -> None:
        conn = snap
        self.fact_labels["server"].configure(text=f"{conn.get('server', '')}:{conn.get('port', '')}")
        self.fact_labels["transport"].configure(text=str(conn.get("transport", "")).upper())
        tls = str(conn.get("tls", ""))
        self.fact_labels["tls"].configure(text=tls.replace("TLS ", "", 1) if tls else "—")
        self.fact_labels["pin"].configure(text=short_pin(conn.get("pin", "")))
        self.fact_labels["session"].configure(text=conn.get("session_id") or "—")
        rtt = conn.get("rtt_ms") or 0
        self.fact_labels["rtt"].configure(text=f"{rtt:.1f} ms" if rtt else "measuring…")
        self.socks_value.configure(text=conn.get("socks") or "—")
        http = conn.get("proxy") or ""
        self.http_value.configure(text=http or "off")
        counters = conn.get("counters", {})
        self.up_label.configure(text="↑ " + fmt_rate(conn.get("rate_up", 0)))
        self.down_label.configure(text="↓ " + fmt_rate(conn.get("rate_down", 0)))
        self.totals_label.configure(
            text=f"{fmt_bytes(counters.get('wire_out', 0))} sent · "
                 f"{fmt_bytes(counters.get('wire_in', 0))} received"
        )
        self.session_stats.configure(
            text=f"{counters.get('frames_out', 0) + counters.get('frames_in', 0):,} records · "
                 f"{counters.get('active_streams', 0)} streams · up {fmt_duration(conn.get('session_uptime', 0))}"
        )
        self._draw_spark(conn.get("history", []))
        self._draw_hist()

        wire = conn.get("counters", {})
        payload = (wire.get("payload_out", 0) or 0) + (wire.get("payload_in", 0) or 0)
        total_wire = (wire.get("wire_out", 0) or 0) + (wire.get("wire_in", 0) or 0)
        overhead = 100.0 * (total_wire - payload) / payload if payload else 0.0
        pad = (wire.get("pad_out", 0) or 0) + (wire.get("pad_in", 0) or 0)
        pad_pct = 100.0 * pad / total_wire if total_wire else 0.0
        sizes = [r["wire"] for r in list(self.controller.records) if r["dir"] == "out"]
        avg = sum(sizes) / len(sizes) if sizes else 0
        self.metric_labels["overhead"].configure(text=f"{overhead:.1f}%")
        self.metric_labels["pad"].configure(text=f"{pad_pct:.1f}%")
        self.metric_labels["avg"].configure(text=fmt_bytes(avg))
        self.metric_labels["unique"].configure(text=str(len(set(sizes))))
        self.metric_labels["records"].configure(text=f"{len(self.controller.records)}")
        spacing = _median_spacing(self.controller.records)
        self.metric_labels["spacing"].configure(text=f"{spacing:.0f} ms" if spacing else "—")

    # ---------------------------------------------------------------- drawing
    def _draw_spark(self, history: list[list[float]]) -> None:
        canvas = self.spark
        canvas.delete("all")
        w = max(canvas.winfo_width(), 100)
        h = max(canvas.winfo_height(), 40)
        for i in range(1, 4):
            y = h * i / 4
            canvas.create_line(0, y, w, y, fill="#12202b")
        if not history:
            canvas.create_text(6, h / 2, text="collecting samples…", fill=MUTED_2, anchor="w",
                               font=("TkDefaultFont", 8))
            return
        peak = max(1.0, max(max(pair[0], pair[1]) for pair in history))
        step = w / max(1, len(history) - 1)
        for idx, color, fill in ((0, MINT, "#0f2c25"), (1, BLUE, "#101f30")):
            points = []
            for i, pair in enumerate(history):
                x = i * step
                y = h - 4 - (pair[idx] / peak) * (h - 8)
                points.extend([x, y])
            if len(points) >= 4:
                canvas.create_line(*points, fill=color, width=2, smooth=True)
                canvas.create_polygon(
                    *points, w, h, 0, h, fill=fill, outline=""
                )

    def _draw_hist(self) -> None:
        canvas = self.hist
        canvas.delete("all")
        w = max(canvas.winfo_width(), 300)
        h = max(canvas.winfo_height(), 100)
        records = list(self.controller.records)
        if not records:
            canvas.create_text(8, h / 2, text="no records yet — connect to see wire metadata",
                               fill=MUTED_2, anchor="w", font=("TkDefaultFont", 8))
            return
        edges = [0, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        bins = len(edges)
        counts = {"out": [0] * bins, "in": [0] * bins}
        for record in records:
            size = record["wire"]
            placed = False
            for i in range(len(edges) - 1):
                if edges[i] <= size < edges[i + 1]:
                    counts[record["dir"]][i] += 1
                    placed = True
                    break
            if not placed:
                counts[record["dir"]][-1] += 1
        peak = max(1, max(counts["out"]), max(counts["in"]))
        left, right, top, bottom = 4, 4, 10, 20
        plot_h = h - top - bottom
        group = (w - left - right) / bins
        bar = max(2, group * 0.32)
        for i in range(bins):
            x = left + i * group + group * 0.15
            for index, key in enumerate(("out", "in")):
                value = counts[key][i]
                if not value:
                    continue
                bar_h = max(2, value / peak * plot_h)
                color = MINT if key == "out" else BLUE
                canvas.create_rectangle(
                    x + index * (bar + 2), top + plot_h - bar_h,
                    x + index * (bar + 2) + bar, top + plot_h,
                    fill=color, outline="",
                )
        canvas.create_text(left, h - 2, text="0", fill=MUTED_2, anchor="sw", font=("TkDefaultFont", 7))
        canvas.create_text(w - right, h - 2, text="64 KB+", fill=MUTED_2, anchor="se",
                           font=("TkDefaultFont", 7))
        canvas.create_text(w / 2, h - 2, text="record size on the wire", fill=MUTED_2, anchor="s",
                           font=("TkDefaultFont", 7))

    def _render_records(self) -> None:
        records = list(self.controller.records)
        if not records:
            return
        latest = [r for r in records if r["t"] > self._last_record_t]
        if not latest:
            return
        self._last_record_t = max(r["t"] for r in latest)
        labels = {"data": "DATA", "open": "OPEN", "open_ok": "OPEN OK", "close": "CLOSE",
                  "ping": "PING", "pong": "PONG", "pad": "COVER", "error": "ERROR"}
        for record in sorted(latest, key=lambda r: r["t"], reverse=True):
            stamp = time.strftime("%H:%M:%S", time.localtime(time.time() - (time.monotonic() - record["t"])))
            tag = "out" if record["dir"] == "out" else "in"
            if record["type"] == "pad":
                tag = "pad"
            self.tree.insert(
                "", 0,
                values=(stamp, "↑" if record["dir"] == "out" else "↓",
                        labels.get(record["type"], record["type"].upper()),
                        fmt_bytes(record["wire"]), f"+{record['pad']} B" if record["pad"] else "—"),
                tags=(tag,),
            )
        children = self.tree.get_children()
        for item in children[250:]:
            self.tree.delete(item)

    def _append_log(self, line: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        if int(self.log_text.index("end-1c").split(".")[0]) > 800:
            self.log_text.delete("1.0", "200.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ---------------------------------------------------------------- close
    def _on_close(self) -> None:
        self._disable_system_proxy()
        self.controller.shutdown()
        self.root.destroy()


def _median_spacing(records) -> float:
    times = [r["t"] for r in records if r["dir"] == "out"]
    if len(times) < 4:
        return 0.0
    deltas = sorted((times[i + 1] - times[i]) * 1000 for i in range(len(times) - 1))
    deltas = [d for d in deltas if 0 <= d < 5000]
    if not deltas:
        return 0.0
    return deltas[len(deltas) // 2]


HELP_TEXT = """HeduVPN runs a local SOCKS5 proxy (and optionally an HTTP proxy) and carries that traffic through an encrypted tunnel that looks like ordinary HTTPS.

Quick start
1. On the relay:   heduvpn relay --domain vpn.example.com --port 443
2. Copy the hedu1:// link it prints.
3. Paste it in Setup → Import, set your SOCKS port, press Connect.
4. Point apps at the SOCKS address, or tick “Use as system proxy while connected”.

The system proxy switch changes your OS proxy settings and restores them on disconnect or exit. It works on Windows, macOS and GNOME. Applications that ignore system proxies (some games, VPN-aware apps) need to be configured manually with the SOCKS5 address.

Recommended for hostile networks
· padding: random (or cells) — hides exact record sizes
· cover traffic: low or medium — keeps idle sessions unremarkable
· rotate session: 30–120 minutes — limits long-term correlation
· transport: WebSocket — survives CDNs and strict middleboxes

What it cannot hide
· the IP address of your relay
· total traffic volume and long-term flow shape
· malware or a compromised operating system on your device

Files
· settings: %s
· proxy restore snapshot: ~/.heduvpn/systemproxy.json (only while the system proxy is in use)

The tunnel is end-to-end encrypted with a pre-shared key; the relay operator can see destinations and metadata, but never payload bytes.
""" % STATE_FILE


def main(connect: bool = False, system_proxy: bool = False) -> None:
    try:
        import ctypes

        if os.name == "nt":
            with contextlib.suppress(Exception):
                ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:
        pass
    root = tk.Tk()
    App(root, connect=connect, system_proxy=system_proxy)
    root.mainloop()


if __name__ == "__main__":  # pragma: no cover
    main()
