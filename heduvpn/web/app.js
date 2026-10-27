/* HeduVPN dashboard — no frameworks, no external requests. */
"use strict";

const app = {
  data: null,
  logs: [],
  view: "overview",
  controls: { padding: "random", cover: "low", transport: "ws", traffic: "browse", jitter_ms: 12 },
  controlsInit: false,
  imported: null,
  busy: false,
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = Math.floor(Math.log(n) / Math.log(1024));
  i = Math.max(0, Math.min(i, units.length - 1));
  const value = n / Math.pow(1024, i);
  return `${value >= 100 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}
function fmtRate(n) { return `${fmtBytes(n)}/s`; }
function fmtInt(n) { return (Number(n) || 0).toLocaleString("en-US"); }
function fmtMs(n) {
  n = Number(n) || 0;
  if (!n) return "—";
  return n < 10 ? `${n.toFixed(1)} ms` : `${Math.round(n)} ms`;
}
function fmtDuration(seconds) {
  seconds = Math.max(0, Number(seconds) || 0);
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  const m = Math.floor(seconds / 60), h = Math.floor(m / 60);
  if (h) return `${h}h ${m % 60}m`;
  return `${m}m ${Math.floor(seconds % 60)}s`;
}
function shortPin(pin) {
  if (!pin) return "—";
  const body = pin.replace(/^sha256:/, "");
  return `sha256:${body.slice(0, 10)}…${body.slice(-6)}`;
}

function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.add("show");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.remove("show"), 3600);
}

async function api(path, body) {
  const options = { method: body === undefined ? "GET" : "POST", headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch (err) { data = {}; }
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

/* ------------------------------------------------------------------ views */
function showView(name) {
  if (!["overview", "wire", "connect", "guide"].includes(name)) name = "overview";
  app.view = name;
  $$(".view").forEach((section) => section.classList.toggle("active", section.dataset.view === name));
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === name));
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (app.data) requestAnimationFrame(() => renderCharts());
}

$$(".tab").forEach((tab) => tab.addEventListener("click", () => showView(tab.dataset.view)));

/* -------------------------------------------------------------- rendering */
function renderAll() {
  const d = app.data;
  if (!d) return;
  const lab = d.lab || {};
  renderHeader(d, lab);
  renderOverview(d, lab);
  renderWire(d, lab);
  renderConnect(d);
  renderCharts();
  renderActivity();
}

function renderHeader(d, lab) {
  const pill = $("#lab-pill");
  const text = $("#lab-pill-text");
  pill.classList.remove("live", "off");
  if (d.lab && d.lab.error) {
    text.textContent = "lab error";
    pill.classList.add("off");
  } else if (lab.running) {
    text.textContent = "lab live";
    pill.classList.add("live");
  } else {
    text.textContent = d.live && d.live.client ? "live client" : "lab stopped";
    pill.classList.add(d.live && d.live.client ? "live" : "off");
  }
  $("#listen-chip").textContent = d.meta.listen;
  $("#version").textContent = `v${d.meta.version}`;
  $("#footer-env").textContent = `${d.meta.system} · python ${d.meta.python}`;
  if (d.meta.error) $("#footer-env").textContent += ` · ${d.meta.error}`;
}

function renderOverview(d, lab) {
  const conn = lab.connection || {};
  const running = Boolean(lab.running);
  const live = running && conn.session_id;

  $("#state-title").textContent = running
    ? (conn.session_id ? "Tunnel live" : "Tunnel starting…")
    : (lab.error ? "Lab unavailable" : "Lab stopped");
  $("#state-sub").textContent = running
    ? "single multiplexed session · TLS in, metadata only out"
    : (lab.error || "start the laboratory in Wire lab to see live traffic");
  $("#state-dot").className = `state-dot ${running ? "live" : lab.error ? "warn" : ""}`;
  $("#transport-tag").textContent = lab.profile
    ? (lab.profile.transport === "ws" ? "websocket · tls 1.3" : "native tls · 1.3")
    : "—";

  $("#fact-relay").textContent = conn.relay || "—";
  $("#fact-tls").textContent = (conn.tls || "").split("·").slice(0, 2).join("·").trim() || "—";
  $("#fact-cert").textContent = conn.cert_cn ? `CN ${conn.cert_cn}` : "—";
  $("#fact-pin").textContent = shortPin(conn.pin);
  $("#fact-pin").dataset.copy = conn.pin || "";
  $("#fact-session").textContent = conn.session_id || "—";
  $("#fact-psk").textContent = conn.psk_fingerprint || "—";
  $("#fact-rtt").textContent = conn.rtt_ms ? fmtMs(conn.rtt_ms) : "measuring…";
  $("#fact-uptime").textContent = running ? fmtDuration(conn.session_uptime || lab.uptime) : "—";
  $("#fact-socks").textContent = conn.socks || "—";

  const rate = lab.rate || { up: 0, down: 0 };
  $("#rate-up").textContent = fmtRate(rate.up);
  $("#rate-down").textContent = fmtRate(rate.down);
  const counters = lab.counters || {};
  $("#total-sent").textContent = fmtBytes(counters.wire_out);
  $("#total-recv").textContent = fmtBytes(counters.wire_in);
  $("#total-payload").textContent = fmtBytes((counters.payload_out || 0) + (counters.payload_in || 0));

  $("#tile-frames").textContent = fmtInt((counters.frames_out || 0) + (counters.frames_in || 0));
  $("#tile-frames-split").textContent = `↑ ${fmtInt(counters.frames_out)} · ↓ ${fmtInt(counters.frames_in)}`;
  const overhead = (lab.wire && lab.wire.overhead_pct) || 0;
  $("#tile-overhead").textContent = `${overhead.toFixed(overhead >= 10 ? 0 : 1)}%`;
  $("#tile-streams").textContent = fmtInt(counters.active_streams);
  const traffic = lab.traffic || {};
  $("#tile-requests").textContent = `${fmtInt(traffic.ok)} requests served${traffic.failed ? ` · ${fmtInt(traffic.failed)} retried` : ""}`;
  const relayCounters = (lab.relay && lab.relay.counters) || {};
  $("#tile-decoys").textContent = fmtInt(relayCounters.decoys);
  $("#tile-policy").textContent = `${fmtInt(relayCounters.policy_blocks)} policy blocks`;

  renderChecks($("#checks-overview"), lab.checks || []);
  renderWirelog($("#wirelog-overview"), (lab.wire && lab.wire.records) || [], 12);
  $("#sample-tag").textContent = lab.running ? "last 90 s" : "paused";
}

function renderChecks(root, checks) {
  if (!root) return;
  if (!checks.length) {
    root.innerHTML = `<li class="empty-row"><span></span><span class="label">waiting</span><span class="value">start the lab to evaluate the connection</span></li>`;
    return;
  }
  root.innerHTML = checks.map((check) => {
    const mark = check.state === "warn" ? "!" : check.state === "info" ? "i" : "✓";
    return `<li><span class="mark ${esc(check.state)}">${mark}</span><span class="label">${esc(check.label)}</span><span class="value">${esc(check.value)}</span></li>`;
  }).join("");
}

const TYPE_LABEL = {
  data: "DATA", open: "OPEN", open_ok: "OPEN OK", close: "CLOSE",
  ping: "PING", pong: "PONG", pad: "COVER", error: "ERROR", hello: "HELLO", hello_ack: "HELLO OK",
};

function renderWirelog(root, records, limit) {
  if (!root) return;
  if (!records.length) {
    root.innerHTML = `<div class="empty">No records yet. The lab opens a real SOCKS tunnel and fetches files through it — metadata appears here as it moves.</div>`;
    return;
  }
  const rows = records.slice(-limit).reverse().map((record) => {
    const dir = record.dir === "out" ? "↑" : "↓";
    const typeName = TYPE_LABEL[record.type] || record.type;
    const cls = ["type", record.type === "pad" ? "pad" : record.type === "data" ? "data" : ""].join(" ");
    return `<div class="row"><span class="dir ${esc(record.dir)}">${dir}</span><span class="${cls}">${esc(typeName)}</span><span class="size">${fmtBytes(record.wire)}</span><span class="pad">${record.pad ? `+${record.pad} pad` : "—"}</span><span></span></div>`;
  }).join("");
  root.innerHTML = `<div class="row head"><span></span><span>type</span><span class="size">wire</span><span class="pad">cover</span><span></span></div>` + rows;
}

function renderWire(d, lab) {
  const profile = lab.profile || app.controls;
  if (!app.controlsInit && lab.profile) {
    syncControls(profile);
    app.controlsInit = true;
  }
  const running = Boolean(lab.running);
  $("#lab-run-state").textContent = lab.error
    ? `error: ${lab.error}`
    : running
      ? `${fmtInt((lab.traffic || {}).requests)} requests · ${fmtBytes((lab.traffic || {}).payload)} served · ${fmtDuration(lab.uptime)}`
      : "lab is stopped";
  $("#stop-lab").hidden = !running;
  $("#start-lab").hidden = running;
  $("#apply-lab").disabled = false;

  const wire = lab.wire || {};
  $("#hist-foot").textContent = wire.records
    ? `${fmtInt(wire.count_out)} uplink · ${fmtInt(wire.count_in)} downlink records · ${wire.overhead_pct}% overall overhead`
    : "waiting for records…";
  $("#m-avg").textContent = wire.avg_record ? fmtBytes(wire.avg_record) : "—";
  $("#m-unique").textContent = wire.unique_sizes ? fmtInt(wire.unique_sizes) : "—";
  $("#m-jitter-out").textContent = wire.spacing_out_ms ? `${wire.spacing_out_ms} ms` : "—";
  $("#m-jitter-in").textContent = wire.spacing_in_ms ? `${wire.spacing_in_ms} ms` : "—";
  $("#m-pad").textContent = `${wire.pad_pct || 0}% of wire bytes`;
  $("#m-overhead").textContent = `${wire.overhead_pct || 0}%`;
  $("#m-records").textContent = fmtInt((wire.count_out || 0) + (wire.count_in || 0));

  const probes = lab.probes || [];
  const body = $("#probe-body");
  if (!probes.length) {
    body.innerHTML = `<tr><td colspan="5" class="why">Probes run automatically when the lab becomes live…</td></tr>`;
  } else {
    body.innerHTML = probes.map((probe) => `
      <tr>
        <td><div>${esc(probe.name)}</div><div class="why">${esc(probe.why || "")}</div></td>
        <td class="obs">${esc(probe.request || "")}</td>
        <td class="obs">${esc(probe.observed || "")}</td>
        <td><span class="verdict ${esc(probe.tone || "info")}">${esc(probe.verdict || "")}</span></td>
        <td class="right mono">${probe.ms != null ? esc(probe.ms) : "—"}</td>
      </tr>`).join("");
  }
  renderChecks($("#checks-wire"), lab.checks || []);
  renderWirelog($("#wirelog-wire"), wire.records || [], 28);
}

function renderConnect(d) {
  const live = d.live || {};
  const client = live.client;
  const config = live.client_config;
  const dot = $("#client-dot");
  const title = $("#client-title");
  const sub = $("#client-sub");

  const connected = client && client.connected;
  const ready = Boolean(config) || Boolean(app.imported);
  dot.className = `state-dot ${connected ? "live" : ready ? "warn" : ""}`;
  if (connected) {
    title.textContent = "Client connected";
    sub.textContent = `${client.server}:${client.port} · ${client.transport} · since ${fmtDuration(client.session_uptime)}`;
  } else if (client && client.state === "reconnecting") {
    title.textContent = "Reconnecting…";
    sub.textContent = client.last_error || client.detail || "retrying";
  } else if (ready) {
    title.textContent = "Ready to connect";
    sub.textContent = config ? `${config.server}:${config.port}` : "imported link is valid";
  } else {
    title.textContent = "No link imported";
    sub.textContent = "import a connection link to continue";
  }

  const socks = connected ? client.socks : (config ? config.socks : "");
  const http = connected ? client.proxy : (config ? config.http_proxy : "");
  $("#client-socks").textContent = socks || "—";
  $("#client-socks").dataset.copy = socks || "";
  $("#client-http").textContent = http || "off";
  $("#client-http").dataset.copy = http || "";
  $("#client-server").textContent = config ? `${config.server}:${config.port}` : "—";

  $("#start-client").disabled = app.busy || !ready || Boolean(connected);
  $("#stop-client").disabled = app.busy || !client;
  $("#export-config").disabled = !ready;

  const sys = live.system_proxy || {};
  const toggle = $("#sysproxy-toggle");
  const note = $("#sysproxy-note");
  toggle.checked = Boolean(sys.enabled);
  toggle.disabled = app.busy || !sys.supported || (!connected && !sys.enabled);
  if (!sys.supported) {
    note.textContent = sys.note || "not available on this platform";
  } else if (sys.enabled) {
    note.textContent = "OS proxy → tunnel";
  } else if (sys.restore_pending) {
    note.textContent = "saved settings will be restored";
  } else {
    note.textContent = connected ? "point this OS at the SOCKS port" : "connect first";
  }

  const relay = live.relay;
  const card = $("#live-relay-card");
  if (relay) {
    card.hidden = false;
    $("#live-relay-listen").textContent = `${relay.listen} · ${relay.tls ? "TLS" : "behind proxy"}`;
    const counters = relay.counters || {};
    $("#live-relay-tiles").innerHTML = [
      ["Sessions", fmtInt(relay.sessions), `${fmtInt(counters.sessions)} total`],
      ["Streams", fmtInt(relay.streams), `${fmtInt(counters.streams)} total`],
      ["Payload in", fmtBytes(counters.payload_in), `${fmtBytes(counters.wire_in)} on wire`],
      ["Payload out", fmtBytes(counters.payload_out), `${fmtInt(counters.decoys)} decoy hits`],
    ].map(([label, value, foot]) => `
      <article class="card tile">
        <span class="tile-label">${esc(label)}</span>
        <b class="tile-value mono">${esc(value)}</b>
        <span class="tile-foot">${esc(foot)}</span>
      </article>`).join("");
    const dest = relay.top_destinations || [];
    $("#live-relay-dest").innerHTML = dest.length
      ? dest.map(([host, count]) => `<tr><td class="mono">${esc(host)}</td><td class="right mono">${fmtInt(count)}</td></tr>`).join("")
      : `<tr><td colspan="2" class="why">no destinations yet</td></tr>`;
  } else {
    card.hidden = true;
  }

  if (app.imported) {
    renderSummary(app.imported);
  } else if (config) {
    renderSummary({
      server: config.server, port: config.port, name: config.name,
      socks_port: (config.socks || "").split(":")[1] || "",
    }, false);
  }
}

function renderSummary(summary, withPin = true) {
  const box = $("#link-summary");
  box.hidden = false;
  const rows = [
    ["name", summary.name || "HeduVPN"],
    ["server", summary.server],
    ["port", summary.port],
    ["transport", summary.transport || "ws"],
    ["sni", summary.sni || summary.server],
    ["verify", summary.verify || "pin"],
  ];
  if (withPin) rows.push(["pin", shortPin(summary.pin)], ["psk fingerprint", summary.psk_fingerprint || "—"]);
  if (summary.socks_port) rows.push(["local socks", `127.0.0.1:${summary.socks_port}`]);
  box.innerHTML = `<div class="summary-grid">${rows.map(([label, value]) =>
    `<div><span>${esc(label)}</span><b title="${esc(value)}">${esc(value)}</b></div>`).join("")}</div>`;
}

/* ------------------------------------------------------------------ charts */
function fitCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(240, canvas.clientWidth);
  const height = Number(canvas.getAttribute("height")) || 120;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width, height };
}

function renderCharts() {
  if (!app.data) return;
  drawSpark((app.data.lab && app.data.lab.history) || []);
  const wire = (app.data.lab && app.data.lab.wire) || {};
  drawHistogram(wire.hist_out || [], wire.hist_in || [], wire.edges || []);
}

function drawSpark(history) {
  const canvas = $("#spark");
  if (!canvas) return;
  const { ctx, width, height } = fitCanvas(canvas);
  ctx.clearRect(0, 0, width, height);
  const pad = 6;
  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  ctx.lineWidth = 1;
  for (let i = 1; i <= 3; i += 1) {
    const y = pad + ((height - pad * 2) * i) / 4;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
  }
  if (!history.length) {
    ctx.fillStyle = "rgba(139,161,179,0.5)";
    ctx.font = "12px ui-sans-serif, system-ui, sans-serif";
    ctx.fillText("collecting samples…", 8, height / 2);
    return;
  }
  const series = [
    { key: 0, color: "#3ee0b3", fill: "rgba(62,224,179,0.14)" },
    { key: 1, color: "#6ea8fe", fill: "rgba(110,168,254,0.12)" },
  ];
  let max = 1;
  history.forEach((pair) => { max = Math.max(max, pair[0] || 0, pair[1] || 0); });
  const stepX = history.length > 1 ? width / (history.length - 1) : width;
  series.forEach((entry) => {
    const points = history.map((pair, i) => [
      i * stepX,
      height - pad - ((pair[entry.key] || 0) / max) * (height - pad * 2),
    ]);
    ctx.beginPath();
    points.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
    ctx.strokeStyle = entry.color;
    ctx.lineWidth = 1.8;
    ctx.stroke();
    ctx.lineTo(points[points.length - 1][0], height - pad);
    ctx.lineTo(points[0][0], height - pad);
    ctx.closePath();
    ctx.fillStyle = entry.fill;
    ctx.fill();
  });
}

function drawHistogram(outBins, inBins, edges) {
  const canvas = $("#hist");
  if (!canvas) return;
  const { ctx, width, height } = fitCanvas(canvas);
  ctx.clearRect(0, 0, width, height);
  const bins = Math.max(outBins.length, inBins.length, 4);
  const max = Math.max(1, ...outBins, ...inBins);
  const left = 4, right = 4, top = 14, bottom = 26;
  const plotW = width - left - right;
  const plotH = height - top - bottom;
  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  for (let i = 0; i <= 3; i += 1) {
    const y = top + (plotH * i) / 3;
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - right, y); ctx.stroke();
  }
  const groupW = plotW / bins;
  const barW = Math.max(3, groupW * 0.34);
  for (let i = 0; i < bins; i += 1) {
    const x = left + i * groupW + groupW * 0.16;
    const values = [
      { value: outBins[i] || 0, color: "rgba(62,224,179,0.85)" },
      { value: inBins[i] || 0, color: "rgba(110,168,254,0.8)" },
    ];
    values.forEach((entry, index) => {
      const barH = entry.value ? Math.max(2, (entry.value / max) * plotH) : 0;
      const bx = x + index * (barW + 2);
      const by = top + plotH - barH;
      ctx.fillStyle = entry.color;
      if (barH > 0) {
        const r = Math.min(3, barW / 2, barH);
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(bx, by, barW, barH, [r, r, 0, 0]);
        else ctx.rect(bx, by, barW, barH);
        ctx.fill();
      }
    });
  }
  ctx.fillStyle = "rgba(139,161,179,0.7)";
  ctx.font = "9.5px ui-monospace, SFMono-Regular, monospace";
  const labelEvery = bins > 8 ? 2 : 1;
  for (let i = 0; i < bins; i += labelEvery) {
    const label = i === bins - 1 ? `${fmtBytes(edges[edges.length - 1] || 65536)}+` : fmtBytes(edges[i] || 0);
    const x = left + i * groupW + 2;
    ctx.fillText(label, x, height - 8);
  }
  ctx.fillStyle = "rgba(139,161,179,0.55)";
  ctx.fillText(`${fmtInt(max)} max`, width - 62, top - 3);
}

/* ---------------------------------------------------------------- activity */
function renderActivity() {
  const pre = $("#activity");
  if (!pre) return;
  const lines = app.logs.length ? app.logs.slice(-18) : ((app.data && app.data.lab && app.data.lab.log) || []);
  pre.textContent = lines.join("\n") || "waiting for activity…";
  pre.scrollTop = pre.scrollHeight;
}

/* ---------------------------------------------------------------- controls */
function syncControls(profile) {
  app.controls = {
    padding: profile.padding || "random",
    cover: profile.cover || "low",
    transport: profile.transport || "ws",
    traffic: profile.traffic || "browse",
    jitter_ms: Number(profile.jitter_ms != null ? profile.jitter_ms : 12),
  };
  $$(".segmented").forEach((group) => {
    const key = group.dataset.control;
    $$("button", group).forEach((button) => {
      button.classList.toggle("active", button.dataset.value === String(app.controls[key]));
    });
  });
  const slider = $("#jitter");
  if (slider) slider.value = app.controls.jitter_ms;
  $("#jitter-value").textContent = `${app.controls.jitter_ms} ms`;
}

$$(".segmented").forEach((group) => {
  group.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-value]");
    if (!button) return;
    const key = group.dataset.control;
    app.controls[key] = button.dataset.value;
    $$("button", group).forEach((el) => el.classList.toggle("active", el === button));
  });
});
$("#jitter").addEventListener("input", (event) => {
  app.controls.jitter_ms = Number(event.target.value);
  $("#jitter-value").textContent = `${app.controls.jitter_ms} ms`;
});

async function withBusy(button, fn) {
  if (app.busy) return;
  app.busy = true;
  const label = button ? button.textContent : "";
  if (button) { button.disabled = true; button.textContent = "Working…"; }
  try { await fn(); }
  catch (error) {
    toast(error.message || "Something went wrong", true);
    try { await refreshState(); } catch (err) { /* ignore */ }
  }
  finally {
    app.busy = false;
    if (button) { button.disabled = false; button.textContent = label; }
    renderConnect(app.data || { live: {} });
  }
}

$("#apply-lab").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
  const payload = { ...app.controls };
  await api("/api/lab/start", payload);
  toast("Lab restarted with the new profile");
  await refreshState();
}));

$("#stop-lab").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
  await api("/api/lab/stop", {});
  toast("Lab stopped");
  await refreshState();
}));

$("#start-lab").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
  await api("/api/lab/start", { ...app.controls });
  toast("Lab started");
  await refreshState();
}));

async function probeAgain(button) {
  await withBusy(button, async () => {
    await api("/api/lab/probe", {});
    toast("Probes complete");
    await refreshState();
  });
}
$("#probe-again").addEventListener("click", (event) => probeAgain(event.currentTarget));
$("#overview-probe").addEventListener("click", (event) => probeAgain(event.currentTarget));

$("#import-link").addEventListener("click", async (event) => {
  const link = $("#link-input").value.trim();
  if (!link) { toast("Paste a hedu1:// link first", true); return; }
  await withBusy(event.currentTarget, async () => {
    const result = await api("/api/link", { link });
    app.imported = result.summary;
    renderSummary(result.summary);
    toast("Link imported");
    $("#link-input").value = "";
    await refreshState();
  });
});

$("#copy-link").addEventListener("click", async () => {
  const value = $("#link-input").value.trim();
  if (!value) { toast("Nothing to copy", true); return; }
  await copyText(value, "Connection link copied");
});

$("#start-client").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
  toast("Starting local client…");
  await api("/api/client/start", {});
  toast("Local client connected");
  await refreshState();
}));

$("#stop-client").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
  await api("/api/client/stop", {});
  toast("Local client stopped");
  await refreshState();
}));

$("#sysproxy-toggle").addEventListener("change", async (event) => {
  const toggle = event.currentTarget;
  const wanted = toggle.checked;
  if (app.busy) { toggle.checked = !wanted; return; }
  app.busy = true;
  toggle.disabled = true;
  try {
    const result = await api(wanted ? "/api/proxy/enable" : "/api/proxy/disable", {});
    toast(result.message || (wanted ? "System proxy enabled" : "System proxy restored"));
    await refreshState();
  } catch (error) {
    toggle.checked = !wanted;
    toast(error.message || "Could not change the system proxy", true);
  } finally {
    app.busy = false;
    renderConnect(app.data || { live: {} });
  }
});

$("#export-config").addEventListener("click", () => {
  window.location.href = "/api/config/export";
});

$$(".copy-cmd").forEach((button) => {
  button.addEventListener("click", () => {
    const target = $(`#${button.dataset.target}`);
    if (target) copyText(target.textContent, "Command copied");
  });
});

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-copy]");
  if (!target) return;
  const value = target.dataset.copy;
  if (value) copyText(value, "Copied to clipboard");
});

async function copyText(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    toast(message || "Copied");
  } catch (error) {
    const area = document.createElement("textarea");
    area.value = value;
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); toast(message || "Copied"); }
    catch (err) { toast("Copy failed", true); }
    document.body.removeChild(area);
  }
}

/* ------------------------------------------------------------------ polling */
async function refreshState() {
  const response = await fetch("/api/state", { cache: "no-store" });
  if (!response.ok) throw new Error(`state ${response.status}`);
  app.data = await response.json();
  renderAll();
}

async function refreshLogs() {
  try {
    const response = await fetch("/api/logs", { cache: "no-store" });
    if (response.ok) {
      const data = await response.json();
      app.logs = data.logs || [];
      renderActivity();
    }
  } catch (error) { /* keep polling */ }
}

async function pollLoop() {
  try {
    if (!app.busy) await refreshState();
  } catch (error) {
    const pill = $("#lab-pill-text");
    if (pill) pill.textContent = "dashboard offline";
  }
  setTimeout(pollLoop, 1100);
}

(async function boot() {
  const initial = (location.hash || "#overview").slice(1);
  showView(initial);
  try {
    await refreshState();
    await refreshLogs();
  } catch (error) {
    toast("Could not reach the dashboard API", true);
  }
  pollLoop();
  setInterval(refreshLogs, 3200);
})();
