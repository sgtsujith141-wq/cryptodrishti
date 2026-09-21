/* CryptoDrishti. Vanilla JS, no framework, no build step, no external request. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null, scanId: null, findings: [], summary: null, scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  classFilter: null,
  pollTimer: null, qdayTimer: null, clockTimer: null, t0: 0, shown: {},
};

/* Assurance: what a finding's evidence actually establishes. Kept visually
   distinct from the quantum class, because they answer different questions and
   a reader who conflates them will count reachable algorithms as running ones. */
const ASSURANCE_LABEL = {
  capability: "capability",
  declared: "declared",
  used: "used",
  observed: "observed",
};

const ASSURANCE_TIP = {
  capability: "A dependency implements this algorithm. Nothing here shows it is called.",
  declared: "Configuration or a manifest permits it. Stated policy, not an execution.",
  used: "Code invokes it — a resolved call site or a linked binary symbol.",
  observed: "Seen in a real artefact: a parsed certificate, or a completed handshake.",
};

const PURPOSE_LABEL = {
  "key-establishment": "key establishment",
  encryption: "encryption",
  signature: "signature",
  hashing: "hashing",
  authentication: "authentication",
  "key-derivation": "key derivation",
  randomness: "randomness",
  transport: "transport",
  unknown: "purpose unresolved",
};

const CLASS_LABEL = {
  "shor-broken": "Broken by Shor", "grover-weakened": "Weakened by Grover",
  "quantum-safe": "Quantum-safe", "hybrid": "Hybrid", "unknown": "Unresolved",
};
const CLASS_ORDER = ["shor-broken", "grover-weakened", "unknown", "hybrid", "quantum-safe"];
const CLASS_VAR = {
  "shor-broken": "--broken", "grover-weakened": "--weakened",
  "unknown": "--unknown", "hybrid": "--hybrid", "quantum-safe": "--safe",
};
const SEV_VAR = { critical: "--crit", high: "--high", medium: "--med", low: "--low" };
const CLASS_INK = {
  "shor-broken": "--i-broken", "grover-weakened": "--i-weakened",
  "unknown": "--i-unknown", "hybrid": "--i-hybrid", "quantum-safe": "--i-safe",
};

/* The array is also the explanation: what each sensor reads is stated on the
   console before anything runs, so the depth of the tool is visible up front. */
const SENSORS = [
  ["source",      "Source",       "Python AST plus 49 curated rules across ten languages",
                  "files_scanned", "files"],
  ["dependency",  "Dependency",   "Manifests resolved to the crypto each library can perform",
                  null, ""],
  ["certificate", "Certificate",  "X.509 parsed for key type, size, validity and signature",
                  "certificate_files_scanned", "certs"],
  ["config",      "Configuration", "TLS, SSH and IPsec parameters as actually deployed",
                  null, ""],
  ["binary",      "Binary",       "ELF symbol tables and eight verified crypto constants",
                  "binaries_scanned", "binaries"],
  ["network",     "Network",      "Live TLS handshake, including hybrid PQC group support",
                  "endpoints_probed", "endpoints"],
];
const PHASE_OF = { source: "source code", dependency: "dependency", certificate: "certificate",
                   config: "configuration", binary: "binaries", network: "endpoint" };

const SECTIONS = [
  ["s-verdict", "Assessment"], ["s-clock", "Exposure"],
  ["s-plan", "Remediation"], ["s-record", "Inventory"], ["s-out", "Output"],
  ["s-history", "History"],
];
let _dialDrawn = false;
const FIGS = [
  ["total",    "Assets",        "distinct cryptographic assets"],
  ["vuln",     "Vulnerable",    "broken or weakened by quantum attack"],
  ["crit",     "Critical",      "risk score at or above 70"],
  ["exposure", "Peak exposure", "years readable past Q-Day"],
];

const sevOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;

const _tok = new Map();
const tok = (n) => {
  let v = _tok.get(n);
  if (v === undefined) {
    v = getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    _tok.set(n, v);
  }
  return v;
};
const dropTokens = () => _tok.clear();

const _params = new URLSearchParams(location.search);
const stillMode = _params.get("still") === "1";
const reduceMotion = stillMode
  || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
/* Smooth scrolling is a CSS property, so ?still=1 has to turn it off directly —
   the reduced-motion media query does not know about the flag. */
if (reduceMotion) document.documentElement.style.scrollBehavior = "auto";
/* ?compact=1 lets the console size to its content instead of the viewport, so
   the whole document prints — and screenshots — as one continuous page. */
if (_params.get("compact") === "1") document.documentElement.classList.add("compact");

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let d = res.statusText;
    try { d = (await res.json()).detail || d; } catch (_) {}
    throw new Error(d);
  }
  return res.json();
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

/* The only motion that is not decorative: a figure counts to its new value so a
   change caused by the Q-Day control is visible rather than instantaneous. */
const _tweens = new Map();
function animateTo(node, key, value, dec) {
  const running = _tweens.get(key);
  if (running !== undefined) cancelAnimationFrame(running);
  const from = state.shown[key];
  state.shown[key] = value;
  const fmt = (v) => (dec ? v.toFixed(dec) : Math.round(v).toLocaleString());
  if (reduceMotion || from === undefined || from === value) {
    _tweens.delete(key); node.textContent = fmt(value); return;
  }
  const t0 = performance.now(), dur = 520;
  const step = (now) => {
    const t = Math.min(1, (now - t0) / dur);
    node.textContent = fmt(from + (value - from) * (1 - Math.pow(1 - t, 4)));
    if (t < 1) _tweens.set(key, requestAnimationFrame(step)); else _tweens.delete(key);
  };
  _tweens.set(key, requestAnimationFrame(step));
}

/* ═══ boot ══════════════════════════════════════════════════════════ */

async function boot() {
  const pre = window.__PRELOAD__ || null;
  try { state.meta = pre?.meta || await api("/api/meta"); }
  catch (e) { console.error(e); return; }

  $("product-name").textContent = state.meta.product;
  $("foot-meta").textContent = `${state.meta.ps_id} · ${state.meta.ps_org}`;
  document.title = state.meta.product;

  const presets = $("presets");
  for (const t of state.meta.suggested_targets) {
    const b = el("button", "preset", t.label);
    b.type = "button";
    b.addEventListener("click", () => { $("scan-path").value = t.path; $("scan-path").focus(); });
    presets.appendChild(b);
  }
  for (const [k, l] of Object.entries(state.meta.profiles)) {
    const o = document.createElement("option"); o.value = k; o.textContent = l;
    $("profile").appendChild(o);
  }
  for (const [k, y] of Object.entries(state.meta.sensitivities)) {
    const o = document.createElement("option"); o.value = k; o.textContent = `${k} · ${y} yr`;
    $("sensitivity").appendChild(o);
  }
  for (const k of CLASS_ORDER) {
    const o = document.createElement("option"); o.value = k; o.textContent = CLASS_LABEL[k];
    $("filter-class").appendChild(o);
  }

  state.qday = { ...state.meta.qday_default };
  const qp = Number(_params.get("qday"));
  if (qp >= 2028 && qp <= 2050) setQday(qp);
  const sp = _params.get("sensitivity");
  if (sp && state.meta.sensitivities[sp] !== undefined) state.sensitivity = sp;
  $("sensitivity").value = state.sensitivity;
  $("qday-likely").value = state.qday.likely;
  $("qday-out").textContent = state.qday.likely;

  $("sensitivity").addEventListener("change", (e) => {
    state.sensitivity = e.target.value; renderMosca(); scheduleQday(true);
  });
  $("qday-likely").addEventListener("input", (e) => {
    setQday(Number(e.target.value));
    $("qday-out").textContent = e.target.value;
    renderMosca(); scheduleQday(false);
  });
  $("qday-likely").addEventListener("change", () => scheduleQday(true));

  loadAssessmentMeta();
  buildFigures(); buildArray(); buildIndex(); initTheme();
  loadHistory();

  initPicker();
  $("run-scan").addEventListener("click", startScan);
  $("scan-path").addEventListener("keydown", (e) => { if (e.key === "Enter") startScan(); });
  $("scan-path").addEventListener("change", inspectImage);
  for (const radio of document.querySelectorAll('input[name="target-kind"]')) {
    radio.addEventListener("change", () => {
      const image = targetKind() === "image";
      $("scan-path").placeholder = image
        ? "/path/to/image.tar or an OCI layout directory"
        : "/path/to/the/estate";
      $("image-pick").hidden = !image;
      if (image) inspectImage();
    });
  }
  let ft = null;
  $("filter-q").addEventListener("input", () => { clearTimeout(ft); ft = setTimeout(renderLedger, 90); });
  $("filter-class").addEventListener("change", () => {
    state.classFilter = $("filter-class").value || null;
    renderDial(); renderLedger(); renderComposition();
  });
  $("filter-context").addEventListener("change", renderLedger);
  $("btn-cbom").addEventListener("click", () => {
    if (state.scanId) {
      location.href = `/api/scan/${state.scanId}/cbom?download=true`
        + `&spec_version=${encodeURIComponent(cbomVersion())}`;
    }
  });
  $("cbom-version").addEventListener("change", () => {
    const box = $("validate-result");
    if (!box.hidden) validateCbom();      // a stale verdict for the old version
  });
  $("btn-report").addEventListener("click", () => {
    if (state.scanId) window.open(`/api/scan/${state.scanId}/report`, "_blank");
  });
  $("btn-validate").addEventListener("click", validateCbom);
  $("explain-toggle").addEventListener("click", toggleExplain);
  $("drawer-close").addEventListener("click", closeDrawer);
  $("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", onKey);

  let rt = null;
  window.addEventListener("resize", () => {
    clearTimeout(rt); rt = setTimeout(() => { renderMosca(); }, 160);
  });

  let wantExplain = _params.get("explain") === "1";
  if (!wantExplain) { try { wantExplain = localStorage.getItem("cd-explain") === "1"; } catch (_) {} }
  if (wantExplain) toggleExplain();

  renderMosca();
  if (pre?.scan) {
    applyScan(pre.scan.scan.id, pre.scan);
    $("scan-path").value = pre.scan.scan.target_value || "";
    await reconcile();
  } else { await loadLatest(); }
}

/* The slider spans 2028-2050 but the distribution bounds were frozen at the
   server defaults, so anything outside them made /api/qday reject the request
   and the page silently kept stale numbers. Keep the window around `likely`. */
function setQday(likely) {
  const d = state.meta?.qday_default || { earliest: 2030, latest: 2044 };
  state.qday.likely = likely;
  state.qday.earliest = Math.min(d.earliest, likely - 2);
  state.qday.latest = Math.max(d.latest, likely + 2);
}

/* ═══ the console ═══════════════════════════════════════════════════ */

function buildArray() {
  const host = $("sensors"); host.textContent = "";
  SENSORS.forEach(([key, title, desc], i) => {
    const li = el("li", "sn");
    li.dataset.sensor = key; li.dataset.state = "idle";
    li.append(
      el("span", "sn-n", String(i + 1).padStart(2, "0")),
      el("span", "sn-t", title),
      el("span", "sn-s", "idle"),
      el("span", "sn-d", desc),
    );
    host.appendChild(li);
  });
}

const sensorRow = (k) => document.querySelector(`.sn[data-sensor="${k}"]`);

function showProgress(pct, detail, stalled) {
  $("run-bar").hidden = false;
  $("run-fill").style.width = Math.max(2, pct) + "%";
  $("run-pct").textContent = Math.round(pct) + "%";
  $("run-detail").textContent = stalled
    ? `${detail || "working"} — no update for ${stalled}s`
    : (detail || "");
  $("run-detail").classList.toggle("stalled", Boolean(stalled));
}

function armArray() {
  $("run-bar").hidden = false;
  $("run-fill").style.width = "2%";
  $("run-pct").textContent = "0%";
  $("run-detail").textContent = "";
  $("run-detail").classList.remove("stalled");
  for (const [k] of SENSORS) {
    const r = sensorRow(k);
    r.dataset.state = "idle";
    r.querySelector(".sn-s").textContent = "queued";
  }
  $("array-state").textContent = "Scanning";
  $("sensors").parentElement.style.setProperty("--p", "0%");
}

function reflectArray(phase, pct) {
  const t = (phase || "").toLowerCase();
  $("array-state").textContent = `Scanning · ${Math.round(pct)}%`;
  $("sensors").parentElement.style.setProperty("--p", pct + "%");
  let active = -1;
  SENSORS.forEach(([k], i) => {
    if (t.includes(PHASE_OF[k])) { active = i; }
  });
  if (active < 0) return;
  SENSORS.forEach(([k], i) => {
    const r = sensorRow(k), s = r.querySelector(".sn-s");
    if (i < active) { r.dataset.state = "done"; if (s.textContent === "queued") s.textContent = "done"; }
    else if (i === active) { r.dataset.state = "active"; s.textContent = "reading"; }
  });
}

/* Once a scan lands, each sensor reports what it actually read. */
function settleArray() {
  const st = state.scanMeta?.stats || {};
  const ran = new Set(st.sensors_run || []);
  for (const [k, , , statKey, unit] of SENSORS) {
    const r = sensorRow(k), s = r.querySelector(".sn-s");
    if (!ran.size || ran.has(k)) {
      r.dataset.state = "done";
      const v = statKey ? st[statKey] : null;
      s.textContent = v ? `${v.toLocaleString()} ${unit}` : "complete";
    } else { r.dataset.state = "idle"; s.textContent = "not run"; }
  }
  $("array-state").textContent = "Complete";
  $("sensors").parentElement.style.setProperty("--p", "100%");
  const m = state.scanMeta;
  if (m) {
    $("clock").textContent = m.duration ? `${m.duration.toFixed(1)}s` : "—";
    $("con-last").textContent =
      `${m.target_label || m.target_value} · ${state.summary?.total ?? 0} assets · `
      + `${(st.raw_hits || 0).toLocaleString()} detector hits · ${(st.sensors_run || []).length} sensors`;
  }
}

function startClock() {
  state.t0 = performance.now();
  clearInterval(state.clockTimer);
  state.clockTimer = setInterval(() => {
    $("clock").textContent = ((performance.now() - state.t0) / 1000).toFixed(1) + "s";
  }, 100);
}
const stopClock = () => clearInterval(state.clockTimer);

/* ─── container image archives ─────────────────────────────────────── */

const targetKind = () =>
  (document.querySelector('input[name="target-kind"]:checked') || {}).value || "directory";

/* Describe the archive without scanning it, so a multi-image archive offers a
   choice instead of the tool picking one, and an unsupported file says so
   here rather than halfway through a scan. */
async function inspectImage() {
  const path = $("scan-path").value.trim();
  const pick = $("image-pick");
  const select = $("image-select");
  const note = $("image-note");
  if (targetKind() !== "image" || !path) { pick.hidden = true; return; }

  select.textContent = "";
  note.textContent = "Reading archive metadata…";
  note.className = "image-note";
  pick.hidden = false;

  try {
    const info = await api("/api/container/inspect?path=" + encodeURIComponent(path));
    for (const image of info.images) {
      const option = document.createElement("option");
      option.value = image.name;
      option.textContent = image.name + (image.platform ? ` — ${image.platform}` : "");
      select.appendChild(option);
    }
    select.disabled = info.images.length < 2;
    note.textContent = info.images.length > 1
      ? `${info.format_description}. ${info.images.length} images — choose one, `
        + "because each is a different estate."
      : `${info.format_description}.`;
  } catch (e) {
    select.disabled = true;
    note.textContent = e.message;
    note.className = "image-note bad";
  }
}

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) { $("scan-path").focus(); return; }
  const kind = targetKind();
  $("run-scan").disabled = true;
  armArray(); startClock();
  try {
    const body = {
      path, label: "",
      profile: $("profile").value,
      target_kind: kind,
      endpoints: kind === "image" ? []
        : $("scan-endpoints").value.split(",").map((s) => s.trim()).filter(Boolean),
    };
    if (kind === "image") body.image = $("image-select").value || "";

    const { scan_id } = await api("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    poll(scan_id);
  } catch (e) {
    stopClock(); $("run-scan").disabled = false;
    $("array-state").textContent = "Error — " + e.message;
  }
}

function poll(id) {
  clearInterval(state.pollTimer);
  /* A percentage alone cannot tell a slow sensor from a dead one. The server
     increments `tick` on every report, so the console watches that and says
     plainly how long it has been since anything moved. */
  let lastTick = -1, lastMoved = performance.now();
  state.pollTimer = setInterval(async () => {
    let job;
    try { job = await api(`/api/scan/${id}/status`); } catch (_) { return; }
    const tick = job.tick ?? 0;
    if (tick !== lastTick) { lastTick = tick; lastMoved = performance.now(); }
    const idle = Math.floor((performance.now() - lastMoved) / 1000);
    reflectArray(job.phase, job.progress || 0);
    showProgress(job.progress || 0, job.detail || job.phase || "",
                 idle >= 5 ? idle : 0);
    if (job.state === "done") {
      clearInterval(state.pollTimer); stopClock();
      $("run-bar").hidden = true; $("run-pct").textContent = "";
      $("run-detail").textContent = ""; $("run-detail").classList.remove("stalled");
      $("run-scan").disabled = false;
      await loadScan(id);
      loadHistory();
      $("s-verdict").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth" });
    } else if (job.state === "error" || job.state === "refused") {
      clearInterval(state.pollTimer); stopClock();
      $("run-bar").hidden = true; $("run-pct").textContent = "";
      $("run-scan").disabled = false;
      /* The server sends the reason and an 8-character reference; the
         traceback stays in the server log. Show the reason — an operator who
         is told only "failed" cannot act. */
      const reason = job.error || "unknown error";
      $("array-state").textContent =
        (job.state === "refused" ? "Refused — " : "Failed — ") + reason;
      $("run-detail").textContent = job.error_ref
        ? `server log reference ${job.error_ref}` : "";
      $("run-detail").classList.add("stalled");
    }
  }, 400);
}

/* ═══ folder picker ═════════════════════════════════════════════════
   Typing an absolute path from memory is not something to do on stage, and a
   scanner you cannot aim at an arbitrary folder is a demo rather than a tool.
   The walk happens server-side, so this stays entirely offline. */

let _pickPath = null;

function initPicker() {
  const panel = $("picker"), btn = $("browse");
  const close = () => {
    panel.hidden = true;
    btn.setAttribute("aria-expanded", "false");
    btn.focus();
  };
  btn.addEventListener("click", () => {
    if (!panel.hidden) { close(); return; }
    panel.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    loadDir($("scan-path").value.trim() || "");
  });
  $("pick-close").addEventListener("click", close);
  $("pick-up").addEventListener("click", () => { if (_pickUp) loadDir(_pickUp); });
  $("pick-use").addEventListener("click", () => {
    if (!_pickPath) return;
    $("scan-path").value = _pickPath;
    close();
    startScan();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !panel.hidden) { e.stopPropagation(); close(); }
  });
}

let _pickUp = null;
async function loadDir(path) {
  const list = $("pick-list");
  list.textContent = "";
  list.appendChild(el("li", "pick-empty", "Reading…"));
  let d;
  try { d = await api("/api/browse?path=" + encodeURIComponent(path)); }
  catch (e) {
    list.textContent = "";
    list.appendChild(el("li", "pick-empty", e.message));
    return;
  }
  _pickPath = d.path; _pickUp = d.parent;
  $("pick-path").textContent = d.path;
  $("pick-up").disabled = !d.parent;

  const places = $("pick-places");
  if (!places.childElementCount) {
    for (const pl of d.places) {
      const b = el("button", null, pl.name);
      b.type = "button";
      b.addEventListener("click", () => loadDir(pl.path));
      places.appendChild(b);
    }
  }

  list.textContent = "";
  if (!d.entries.length) {
    list.appendChild(el("li", "pick-empty", "No sub-folders here. Scan this folder, or go up."));
    return;
  }
  for (const e of d.entries) {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.append(el("span", "pn", e.name));
    if (e.kind) b.append(el("span", "pk", e.kind));
    b.addEventListener("click", () => loadDir(e.path));
    li.appendChild(b); list.appendChild(li);
  }
}

/* ═══ chrome ════════════════════════════════════════════════════════ */

function buildFigures() {
  const dl = $("figs");
  for (const [key, label, sub] of FIGS) {
    const row = el("div");
    const dt = el("dt", null, label);
    dt.appendChild(el("i", null, sub));
    const dd = el("dd", key === "vuln" ? "bad" : null, "—");
    dd.id = "fig-" + key;
    row.append(dt, dd);
    dl.appendChild(row);
  }
}

function buildIndex() {
  const ol = $("index-list");
  SECTIONS.forEach(([id, name], i) => {
    const a = el("a");
    a.href = "#" + id;
    a.dataset.section = id;
    a.append(el("span", "pip"), el("span", "nm", name));
    a.title = `${String(i + 1).padStart(2, "0")} — ${name}`;
    const li = document.createElement("li");
    li.appendChild(a); ol.appendChild(li);
  });
  const obs = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      for (const a of ol.querySelectorAll("a")) {
        a.setAttribute("aria-current", String(a.dataset.section === e.target.id));
      }
    }
  }, { rootMargin: "-12% 0px -76% 0px" });
  for (const [id] of SECTIONS) obs.observe($(id));

  // The record's chrome only exists once you have left the console.
  const conObs = new IntersectionObserver(
    ([e]) => { $("rail").hidden = e.isIntersecting; },
    { threshold: 0.12 });
  conObs.observe($("console"));
}

function onKey(e) {
  if (e.key === "Escape") { closeDrawer(); return; }
}

const isDark = () => {
  const s = document.documentElement.getAttribute("data-theme");
  return s ? s === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
};

function initTheme() {
  const sync = () => {
    $("theme-toggle").textContent = isDark() ? "Light" : "Dark";
    dropTokens();
    renderDial(); renderMosca(); renderLedger(); renderPlan(); renderComposition();
    if (_open) openDrawer(_open, true);
  };
  sync();
  $("theme-toggle").addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("cd-theme", next); } catch (_) {}
    sync();
  });
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const onSys = () => { if (!document.documentElement.hasAttribute("data-theme")) sync(); };
  mq.addEventListener ? mq.addEventListener("change", onSys) : mq.addListener(onSys);
}

function toggleExplain() {
  const on = document.body.classList.toggle("explaining");
  $("explain-toggle").setAttribute("aria-pressed", String(on));
  try { localStorage.setItem("cd-explain", on ? "1" : "0"); } catch (_) {}
}

/* ═══ data ══════════════════════════════════════════════════════════ */

async function loadLatest() {
  try {
    const { scans } = await api("/api/scans");
    if (scans.length) { $("scan-path").value = scans[0].target_value; await loadScan(scans[0].id); }
  } catch (e) { console.error(e); }
}

function applyScan(id, data) {
  state.scanId = id;
  state.findings = data.findings;
  state.summary = data.summary;
  state.scanMeta = data.scan;
  state.payload = data;
  state.classFilter = null;
  $("filter-class").value = "";
  $("validate-result").hidden = true;
  renderIntegrity(data);
  renderAll();
}

/* The history panel's entry point. Named separately so it reads as what it
   is at the call site: adopting a stored assessment, not starting one. */
const adoptScan = applyScan;

async function reconcile() {
  const m = state.findings[0]?.extra?.mosca;
  if (!m) return;
  const wantZ = state.qday.likely - NOW_YEAR;
  const wantX = state.meta?.sensitivities?.[state.sensitivity];
  if (Math.abs(m.years_to_qday - wantZ) > 0.01
      || (wantX !== undefined && Math.abs(m.shelf_life - wantX) > 0.01)) await recomputeQday(false);
}

async function loadScan(id) { applyScan(id, await api(`/api/scan/${id}`)); await reconcile(); }

function scheduleQday(persist) {
  if (!state.scanId) { renderMosca(); return; }
  clearTimeout(state.qdayTimer);
  state.qdayTimer = setTimeout(() => recomputeQday(persist), 140);
}

let _seq = 0;
async function recomputeQday(persist) {
  if (!state.scanId) return;
  const seq = ++_seq;
  try {
    const data = await api("/api/qday", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: state.scanId, earliest: state.qday.earliest, likely: state.qday.likely,
        latest: state.qday.latest, sensitivity: state.sensitivity, persist: Boolean(persist),
      }),
    });
    if (seq !== _seq) return;          // a slower earlier reply must not win
    const byId = new Map(state.findings.map((f) => [f.id, f]));
    for (const d of data.deltas) {
      const f = byId.get(d.id); if (!f) continue;
      f.risk_score = d.risk_score; f.quantum_class = d.quantum_class;
      f.exposure_years = d.exposure_years; f.extra = f.extra || {};
      /* Assign, never merge. A stale factor block beside a fresh score is
         an audit trail that contradicts the number it explains. */
      if (d.mosca) f.extra.mosca = d.mosca;
      if (d.factors) f.extra.factors = d.factors;
      if (d.risk_inputs) f.extra.risk_inputs = d.risk_inputs;
      if (d.exposure_model) f.extra.exposure_model = d.exposure_model;
      if (d.assessment) f.extra.assessment = d.assessment;
      if (d.asset_key) f.extra.asset_key = d.asset_key;
    }
    setAssessmentState(data.state, data.overrides_applied, data.assessment_date);
    const rank = new Map(data.order.map((id, i) => [id, i]));
    state.findings.sort((a, b) => (rank.get(a.id) ?? 0) - (rank.get(b.id) ?? 0));
    state.summary = data.summary;
    renderAll();
    if (_open) { const f = state.findings.find((x) => x.id === _open.id); if (f) openDrawer(f, true); }
  } catch (e) { console.error("Q-Day recompute failed", e); }
}

/* ═══ render ════════════════════════════════════════════════════════ */

function renderAll() {
  /* Isolated so a fault in one figure cannot take the whole record down with
     it, which is not a failure mode worth carrying into a live demonstration. */
  for (const [name, fn] of [
    ["verdict", renderVerdict], ["composition", renderComposition], ["array", settleArray],
    ["exposure", renderMosca],
    ["plan", renderPlan], ["ledger", renderLedger],
  ]) {
    try { fn(); } catch (e) { console.error(`render ${name} failed`, e); }
  }
}

function renderVerdict() {
  const s = state.summary;
  if (!s) return;
  const broken = s.by_class["shor-broken"] || 0;
  const safe = (s.by_class["quantum-safe"] || 0) + (s.by_class["hybrid"] || 0);
  const line = $("v-line");
  line.textContent = "";
  line.append(
    el("b", "bad", String(broken)),
    document.createTextNode(" assets break outright under Shor's algorithm, and "),
    el("b", null, String(s.quantum_vulnerable - broken)),
    document.createTextNode(" more lose half their strength to Grover."),
  );
  if (safe) line.append(document.createTextNode(" "), el("b", "good", String(safe)),
                        document.createTextNode(" are already quantum-safe."));

  animateTo($("fig-total"), "total", s.total);
  animateTo($("fig-vuln"), "vuln", s.quantum_vulnerable);
  animateTo($("fig-crit"), "crit", s.by_severity?.critical || 0);
  animateTo($("fig-exposure"), "exp", s.max_exposure_years, 1);

  $("x-verdict").textContent = `${s.total} assets · ${s.vulnerable_pct}% at risk`;
  renderDial();
  $("x-record").textContent = `${s.total} assets`;
}

function renderComposition() {
  const bar = $("composition"), key = $("legend");
  bar.textContent = ""; key.textContent = "";
  const s = state.summary;
  if (!s || !s.total) return;

  bar.classList.toggle("filtered", Boolean(state.classFilter));
  const setFilter = (k) => {
    state.classFilter = state.classFilter === k ? null : k;
    $("filter-class").value = state.classFilter || "";
    renderDial(); renderLedger(); renderComposition();
  };

  for (const k of CLASS_ORDER) {
    const n = s.by_class[k] || 0;
    if (!n) continue;
    const share = (n / s.total) * 100;

    const seg = document.createElement("button");
    seg.style.width = share + "%";
    seg.style.background = tok(CLASS_VAR[k]);
    seg.setAttribute("aria-pressed", String(state.classFilter === k));
    seg.setAttribute("aria-label", `${CLASS_LABEL[k]}, ${n} assets, ${share.toFixed(1)} percent`);
    seg.title = `${CLASS_LABEL[k]} — ${n} of ${s.total}`;
    seg.addEventListener("click", () => setFilter(k));
    bar.appendChild(seg);

    const b = document.createElement("button");
    b.setAttribute("aria-pressed", String(state.classFilter === k));
    const sw = document.createElement("i");
    sw.style.background = tok(CLASS_VAR[k]);
    const wrap = el("span");
    wrap.append(el("span", "kl", CLASS_LABEL[k]), document.createTextNode(" "),
                el("span", "ks", `${share.toFixed(1)}%`));
    b.append(sw, el("span", "kn", String(n)), wrap);
    b.addEventListener("click", () => setFilter(k));
    const li = document.createElement("li");
    li.appendChild(b); key.appendChild(li);
  }
}

/* ─── 01 the dial: every asset as a spoke ─────────────────────────
   Length is the risk score, colour is the exposure class, and they run in
   order of urgency — so the work sweeps from the most critical round to the
   assets that need nothing at all. */

function renderDial() {
  const svg = $("radial");
  svg.textContent = "";
  const s = state.summary;
  if (!s || !state.findings.length) return;

  const CX = 210, CY = 210, R0 = 96, R1 = 196;
  const items = [...state.findings].sort((a, b) => b.risk_score - a.risk_score);
  const N = items.length;
  // Sweep clockwise with the gap centred at the bottom, so the arc opens where
  // the eye expects a dial to open.
  const sweep = 2 * Math.PI * 0.86;
  const start = Math.PI / 2 + (2 * Math.PI - sweep) / 2;
  const step = sweep / N;
  const width = Math.max(2.2, Math.min(9, (2 * Math.PI * R0 * 0.86 / N) - 1.6));

  for (const frac of [0.25, 0.5, 0.75, 1]) {
    svg.appendChild(sv("circle", {
      cx: CX, cy: CY, r: R0 + (R1 - R0) * frac, fill: "none",
      stroke: tok("--rule"), "stroke-width": frac === 1 ? 1 : 0.75,
      "stroke-dasharray": frac === 1 ? "none" : "2 5",
    }));
  }

  items.forEach((f, i) => {
    const a = start + step * (i + 0.5);
    const len = R0 + (R1 - R0) * Math.max(0.04, Math.min(1, f.risk_score / 100));
    const dim = state.classFilter && f.quantum_class !== state.classFilter;
    const line = sv("line", {
      x1: CX + R0 * Math.cos(a), y1: CY + R0 * Math.sin(a),
      x2: CX + len * Math.cos(a), y2: CY + len * Math.sin(a),
      stroke: tok(CLASS_VAR[f.quantum_class] || "--unknown"),
      "stroke-width": width, "stroke-linecap": "round",
      opacity: dim ? .16 : 1, tabindex: dim ? "-1" : "0", role: "img",
      "aria-label": `${f.algorithm}, ${CLASS_LABEL[f.quantum_class] || f.quantum_class}, `
        + `risk ${f.risk_score.toFixed(0)}, ${f.occurrences} call sites`,
    });
    line.setAttribute("class", "spoke");
    if (!dim) {
      line.addEventListener("mouseenter", () => state.spokeHub?.(f));
      line.addEventListener("mousemove", (e) => showTip(e, f));
      line.addEventListener("mouseleave", () => { hideTip(); state.restHub?.(); });
      line.addEventListener("click", () => openDrawer(f));
      line.addEventListener("focus", () => { showTipAt(line, f); state.spokeHub?.(f); });
      line.addEventListener("blur", () => { hideTip(); state.restHub?.(); });
      line.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
      });
    }
    /* The spokes are always at final geometry; the reveal is decorative only,
       so a browser that ignores SMIL still draws a complete dial. */
    if (!reduceMotion && !_dialDrawn) {
      line.append(
        sv("animate", { attributeName: "x2", from: CX + R0 * Math.cos(a),
          to: CX + len * Math.cos(a), dur: "0.55s", begin: `${i * 0.006}s`, fill: "freeze",
          calcMode: "spline", keySplines: "0.2 0.7 0.3 1", keyTimes: "0;1" }),
        sv("animate", { attributeName: "y2", from: CY + R0 * Math.sin(a),
          to: CY + len * Math.sin(a), dur: "0.55s", begin: `${i * 0.006}s`, fill: "freeze",
          calcMode: "spline", keySplines: "0.2 0.7 0.3 1", keyTimes: "0;1" }),
      );
    }
    svg.appendChild(line);
  });
  _dialDrawn = true;

  /* The hub is a readout, not a caption: pointing at a spoke reports that
     asset there, so the ring answers questions instead of only illustrating. */
  const hub = sv("g", { id: "dial-hub" });
  svg.appendChild(hub);
  const restHub = () => [
    [CY - 4, 52, 600, tok("--ink"), tok("--mono"), `${Math.round(s.vulnerable_pct)}%`],
    [CY + 22, 12.5, 400, tok("--ink-3"), tok("--ui"), "of the estate is"],
    [CY + 40, 12.5, 400, tok("--ink-3"), tok("--ui"), "quantum vulnerable"],
  ];
  const spokeHub = (f) => [
    [CY - 26, 12, 600, tok("--ink-4"), tok("--mono"), `RISK ${f.risk_score.toFixed(0)}`],
    [CY - 2, 20, 640, tok("--ink"), tok("--mono"), f.algorithm],
    [CY + 20, 11.5, 400, tok(CLASS_INK[f.quantum_class] || "--i-unknown"), tok("--ui"),
     CLASS_LABEL[f.quantum_class] || f.quantum_class],
    [CY + 40, 11.5, 400, tok("--ink-3"), tok("--mono"),
     `${f.occurrences.toLocaleString()} places`],
  ];
  const paintHub = (rows) => {
    hub.textContent = "";
    for (const [y, size, weight, fill, family, text] of rows) {
      hub.appendChild(sv("text", { x: CX, y, "text-anchor": "middle", fill,
        "font-size": size, "font-weight": weight, "font-family": family,
        "letter-spacing": size > 40 ? -2.5 : 0 }, text));
    }
  };
  paintHub(restHub());
  state.paintHub = paintHub;
  state.restHub = () => paintHub(restHub());
  state.spokeHub = (f) => paintHub(spokeHub(f));
}

const NS = "http://www.w3.org/2000/svg";
function sv(n, a, t) {
  const e = document.createElementNS(NS, n);
  for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v);
  if (t !== undefined) e.textContent = t;
  return e;
}

function fillTip(f) {
  const tip = $("tip");
  tip.hidden = false; tip.textContent = "";
  tip.appendChild(el("div", "t", f.algorithm));
  for (const [k, v] of [
    ["Class", CLASS_LABEL[f.quantum_class] || f.quantum_class],
    ["Risk", `${f.risk_score.toFixed(0)} · ${sevOf(f.risk_score)}`],
    ["Call sites", f.occurrences.toLocaleString()],
    ["Migrate to", f.recommendation?.target_name || "—"],
  ]) {
    const r = el("div", "r");
    r.append(el("span", null, k), el("span", null, v));
    tip.appendChild(r);
  }
  return tip;
}
function placeTip(tip, cx, cy) {
  const b = tip.getBoundingClientRect(), pad = 14;
  let X = cx + pad, Y = cy + pad;
  if (X + b.width > innerWidth - 8) X = cx - b.width - pad;
  if (Y + b.height > innerHeight - 8) Y = cy - b.height - pad;
  tip.style.left = Math.max(8, X) + "px";
  tip.style.top = Math.max(8, Y) + "px";
}
function showTip(e, f) { placeTip(fillTip(f), e.clientX, e.clientY); }
function showTipAt(node, f) {
  const b = node.getBoundingClientRect();
  placeTip(fillTip(f), b.left + b.width / 2, b.top + b.height / 2);
}
function hideTip() { $("tip").hidden = true; }

/* ─── 03 exposure window ──────────────────────────────────────────
   Two spans on one ruler: how long the data must stay secret, and when the
   machine that breaks it is expected. Where they overlap, you are exposed. */

function renderMosca() {
  const svg = $("mosca-svg"), plain = $("mosca-plain"), eq = $("mosca-eq");
  svg.textContent = ""; plain.textContent = ""; eq.textContent = "";

  if (!state.findings.length) {
    plain.textContent = "Run a scan to model exposure.";
    return;
  }

  let worst = null;
  for (const f of state.findings) {
    const m = f.extra?.mosca;
    if (m && (!worst || m.exposure_years > worst.exposure_years)) worst = m;
  }
  const X = state.meta?.sensitivities?.[state.sensitivity] ?? 10;
  const Y = worst ? worst.migration_years : 2.0;
  const T = X + Y;                       // secrecy must hold through NOW + T
  const Z = Math.max(0, state.qday.likely - NOW_YEAR);
  const exposure = Math.max(0, T - Z);
  const secureUntil = Math.ceil(NOW_YEAR + T);

  /* The inequality with its terms named and valued. Mosca's formulation is the
     argument, so it is stated rather than only illustrated. */
  const term = (sym, label, value, note, cls) => {
    const d = el("div", cls);
    const dt = el("dt");
    if (sym) { dt.append(el("b", null, sym), document.createTextNode(" · " + label)); }
    else dt.textContent = label;
    d.append(dt, el("dd", null, value));
    if (note) d.append(el("span", "sub2", note));
    return d;
  };
  eq.append(
    term("X", "secrecy", `${X} yr`, "how long it must stay secret"),
    el("div", "op", "+"),
    term("Y", "migration", `${Y} yr`, "how long replacing it takes"),
    el("div", "op", "="),
    term("", "Protection needed", `${T} yr`, `through ${Math.ceil(NOW_YEAR + T)}`),
    el("div", "op", exposure > 0 ? ">" : "≤"),
    term("Z", "to Q-Day", `${Z} yr`, `best estimate ${state.qday.likely}`),
    el("div", "op", "→"),
    term("", exposure > 0 ? "Exposed" : "Within tolerance",
         exposure > 0 ? `${exposure.toFixed(1)} yr` : "0 yr",
         exposure > 0 ? "readable before you finish" : "migration completes first",
         exposure > 0 ? "res" : "res ok"),
  );

  // plain language, so the chart confirms rather than explains
  plain.append(
    document.createTextNode("Something encrypted today has to stay secret until "),
    el("b", null, String(secureUntil)),
    document.createTextNode(" — "),
    el("b", null, `${X} years`),
    document.createTextNode(" of secrecy plus "),
    el("b", null, `${Y} years`),
    document.createTextNode(" to migrate. A quantum computer able to break it is expected around "),
    el("b", null, String(state.qday.likely)),
    document.createTextNode(exposure > 0 ? ". That leaves " : "."),
  );
  if (exposure > 0) {
    plain.append(
      el("b", "bad", `${exposure.toFixed(1)} years`),
      document.createTextNode(" in which this estate's data is readable and nothing can be done about it."),
    );
  } else {
    plain.append(document.createTextNode(" Migration finishes first."));
  }

  /* The old chart asked you to read two spans against a calendar and find the
     overlap yourself. This states the inequality directly: one bar for the
     protection you need, one for the time you have, from a common origin. */
  // the arrival range, in years from now
  const dA = Math.max(0, state.qday.earliest - NOW_YEAR);
  const dB = Math.max(dA + 1, state.qday.latest - NOW_YEAR);

  const W = 1000, L = 96, R = 138, BOT = 168;
  const span = Math.max(T, dB, 8) * 1.06;
  const px = (y) => L + (y / span) * (W - L - R);
  const MONO = tok("--mono"), bad = tok("--i-broken"), ink = tok("--ink"),
        ink2 = tok("--ink-2"), ink3 = tok("--ink-3"), ink4 = tok("--ink-4"),
        rule = tok("--rule"), rule2 = tok("--rule-2");
  const RX = W - R + 12;
  const H = 30;

  const rowLabel = (y, text) => svg.appendChild(sv("text", { x: L - 14, y: y + 20,
    fill: ink3, "font-size": 11, "font-family": MONO, "letter-spacing": 1,
    "text-anchor": "end" }, text));
  const rowValue = (y, text, fill) => svg.appendChild(sv("text", { x: RX, y: y + 20,
    fill, "font-size": 15, "font-weight": 640, "font-family": MONO }, text));
  const caption = (y, text) => svg.appendChild(sv("text", { x: L, y: y + H + 16,
    fill: ink4, "font-size": 11.5, "font-family": tok("--ui") }, text));

  // ── what you need: X then Y, stacked, from a common origin ──
  const yNeed = 18;
  rowLabel(yNeed, "NEED");
  svg.appendChild(sv("rect", { x: px(0), y: yNeed, width: Math.max(2, px(X) - px(0)),
    height: H, fill: tok("--weakened"), opacity: .55 }));
  svg.appendChild(sv("rect", { x: px(X), y: yNeed, width: Math.max(2, px(T) - px(X)),
    height: H, fill: tok("--unknown"), opacity: .5 }));
  svg.appendChild(sv("rect", { x: px(0), y: yNeed, width: px(T) - px(0), height: H,
    fill: "none", stroke: ink, "stroke-width": 1.5 }));
  rowValue(yNeed, `${T} yr`, ink);
  caption(yNeed, `${X} yr of secrecy + ${Y} yr to migrate — protected through `
    + `${Math.ceil(NOW_YEAR + T)}`);

  // ── what you have: Z, with the uncertainty it really carries ──
  const yHave = 88;
  rowLabel(yHave, "HAVE");
  svg.appendChild(sv("rect", { x: px(dA), y: yHave + 6, width: Math.max(2, px(dB) - px(dA)),
    height: H - 12, fill: ink4, opacity: .18 }));
  svg.appendChild(sv("rect", { x: px(0), y: yHave, width: Math.max(2, px(Z) - px(0)),
    height: H, fill: tok("--unknown"), opacity: .5 }));
  svg.appendChild(sv("rect", { x: px(0), y: yHave, width: px(Z) - px(0), height: H,
    fill: "none", stroke: ink, "stroke-width": 1.5 }));
  rowValue(yHave, `${Z} yr`, ink);
  caption(yHave, `until a quantum computer breaks it — best estimate `
    + `${state.qday.likely}, could be ${NOW_YEAR + dA} to ${NOW_YEAR + dB}`);

  // ── the shortfall, called out between the two ends ──
  if (exposure > 0) {
    svg.appendChild(sv("rect", { x: px(Z), y: yNeed, width: px(T) - px(Z),
      height: yHave + H - yNeed, fill: bad, opacity: .12 }));
    svg.appendChild(sv("line", { x1: px(Z), y1: yNeed, x2: px(Z), y2: BOT - 24,
      stroke: bad, "stroke-width": 1.5, "stroke-dasharray": "4 4" }));
    svg.appendChild(sv("line", { x1: px(T), y1: yNeed, x2: px(T), y2: BOT - 24,
      stroke: bad, "stroke-width": 1.5, "stroke-dasharray": "4 4" }));
    svg.appendChild(sv("text", { x: (px(Z) + px(T)) / 2, y: BOT - 8, fill: bad,
      "font-size": 13, "font-weight": 640, "font-family": MONO, "text-anchor": "middle" },
      `${exposure.toFixed(1)} YEARS SHORT`));
  } else {
    svg.appendChild(sv("text", { x: px(T) + 12, y: BOT - 8, fill: tok("--i-safe"),
      "font-size": 13, "font-weight": 640, "font-family": MONO }, "NO SHORTFALL"));
  }

  // ── scale ──
  svg.appendChild(sv("line", { x1: px(0), y1: BOT, x2: W - R + 30, y2: BOT,
    stroke: rule2, "stroke-width": 1 }));
  const step = span > 26 ? 8 : span > 13 ? 4 : 2;
  for (let y = 0; y <= span + 1e-6; y += step) {
    const xx = px(y);
    if (xx > W - R + 30) break;
    svg.appendChild(sv("line", { x1: xx, y1: BOT, x2: xx, y2: BOT + 5,
      stroke: rule2, "stroke-width": 1 }));
    svg.appendChild(sv("text", { x: xx, y: BOT + 20, fill: ink3, "font-size": 11.5,
      "font-family": MONO, "text-anchor": "middle" }, y === 0 ? "now" : `${y} yr`));
  }

  $("x-clock").textContent = exposure > 0
    ? `${exposure.toFixed(1)} yr exposed` : "within tolerance";
}

/* ─── 04 remediation programme ────────────────────────────────────── */

function renderPlan() {
  const body = $("plan-body");
  body.textContent = "";
  const empty = (msg) => {
    const tr = el("tr", "empty");
    const td = document.createElement("td");
    td.colSpan = 6; td.textContent = msg;
    tr.appendChild(td); body.appendChild(tr);
  };
  if (!state.findings.length) { empty("Run a scan to build a migration programme."); return; }

  const groups = new Map();
  for (const f of state.findings) {
    if (f.quantum_class === "quantum-safe" || f.quantum_class === "hybrid") continue;
    const r = f.recommendation || {};
    const key = r.target_name || "Manual review";
    let g = groups.get(key);
    if (!g) {
      g = { key, assets: 0, sites: 0, peak: 0, effort: r.effort || "medium",
            action: r.action || "", delta: r.size_delta_bytes };
      groups.set(key, g);
    }
    g.assets += 1;
    g.sites += f.occurrences;
    g.peak = Math.max(g.peak, f.risk_score);
    if (g.delta === undefined || g.delta === null) g.delta = r.size_delta_bytes;
  }
  const list = [...groups.values()].sort((a, b) => b.peak - a.peak);
  if (!list.length) { empty("Nothing to migrate — every asset is already quantum-safe."); return; }

  $("x-plan").textContent = `${list.length} workstreams · `
    + `${list.reduce((a, g) => a + g.sites, 0).toLocaleString()} call sites`;

  for (const g of list) {
    const tr = document.createElement("tr");
    const td = (cls, text) => {
      const c = document.createElement("td");
      if (cls) c.className = cls;
      if (text !== undefined) c.textContent = text;
      return c;
    };
    const nameTd = td();
    const ws = el("span", "ws");
    const sq = document.createElement("i");
    sq.style.background = tok(SEV_VAR[sevOf(g.peak)]);
    sq.title = `peak risk ${g.peak.toFixed(0)} · ${sevOf(g.peak)}`;
    ws.append(sq, document.createTextNode(g.key));
    nameTd.appendChild(ws);
    const delta = (g.delta === undefined || g.delta === null)
      ? "—" : `${g.delta > 0 ? "+" : ""}${g.delta.toLocaleString()}`;
    tr.append(nameTd, td("n", String(g.assets)), td("n", g.sites.toLocaleString()),
              td("n", delta), td("ctx", g.effort), td("act", g.action));
    body.appendChild(tr);
  }
}

/* ─── 05 the ledger ───────────────────────────────────────────────── */

function visible() {
  const q = $("filter-q").value.trim().toLowerCase();
  const cls = $("filter-class").value, ctx = $("filter-context").value;
  return state.findings.filter((f) => {
    if (cls && f.quantum_class !== cls) return false;
    if (ctx && (f.extra?.context || "production") !== ctx) return false;
    if (q && !`${f.algorithm} ${f.title} ${f.primary_location}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

function renderLedger() {
  const host = $("ledger");
  host.textContent = "";
  const rows = visible();
  $("findings-hint").textContent = state.findings.length
    ? `${rows.length} / ${state.findings.length}` : "";

  if (!rows.length) {
    host.appendChild(el("li", "led-empty", state.findings.length
      ? "Nothing matches those filters."
      : (state.scanId ? "This scan found no cryptographic assets."
                      : "No scan on record — aim the console at an estate and run it.")));
    return;
  }

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const li = document.createElement("li");
    const row = document.createElement("button");
    row.className = "led";
    row.dataset.sev = sevOf(f.risk_score);
    row.style.borderLeftColor = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    row.setAttribute("aria-label",
      `${f.algorithm}: ${f.title}. Risk ${f.risk_score.toFixed(0)}, `
      + `${CLASS_LABEL[f.quantum_class] || f.quantum_class}, `
      + `${ASSURANCE_LABEL[f.assurance] || ""} evidence, ${f.occurrences} call sites.`);

    const ident = el("span");
    const cls = el("span", "cls led-cls " + f.quantum_class);
    const dot = document.createElement("i");
    dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    cls.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
    const algo = el("span", "led-algo", f.algorithm); algo.title = f.algorithm;
    ident.append(algo, cls);

    const ev = f.evidence?.[0];
    const where = ev ? (ev.line ? `${ev.location}:${ev.line}` : ev.location) : "";
    const what = el("span");
    const find = el("span", "led-find", f.title); find.title = f.title;
    const loc = el("span", "led-loc", where); loc.title = where;
    what.append(find, loc);

    const asr = el("span", "led-asr asr-" + (f.assurance || "capability"),
                   ASSURANCE_LABEL[f.assurance] || f.assurance || "");
    asr.title = ASSURANCE_TIP[f.assurance] || "";
    ident.appendChild(asr);

    const recName = f.recommendation?.target_name || "manual review";
    const to = el("span", "led-to"
      + (f.recommendation?.unresolved ? " led-unresolved" : ""), recName);
    to.title = f.recommendation?.unresolved
      ? "No target named: " + (f.recommendation?.rationale || "")
      : recName;

    const sites = el("span", "led-sites", f.occurrences.toLocaleString());
    sites.appendChild(el("i", null, "sites"));

    row.append(el("span", "led-score", f.risk_score.toFixed(0)), ident, what, to, sites);
    row.addEventListener("click", () => openDrawer(f));
    li.appendChild(row);
    frag.appendChild(li);
  }
  host.appendChild(frag);
}

/* ═══ drawer ════════════════════════════════════════════════════════ */

let _open = null, _returnTo = null;

/* ─── per-asset assessment editor ──────────────────────────────────
   Deliberately plain: four inputs, a preview and an explicit save. The
   distinction that matters is preview versus saved, so it is a banner rather
   than a subtlety. */
function assessmentEditor(f, assetKey) {
  const wrap = el("div", "assess");
  const state = el("p", "assess-state", "Showing the saved assessment.");
  const form = el("div", "assess-form");

  const fields = {};
  const spec = [
    ["shelf_life_years", "Confidentiality lifetime / trust horizon (years)", "number"],
    ["migration_years", "Migration duration (years)", "number"],
    ["criticality", "Business criticality (1.0 = ordinary production)", "number"],
  ];
  for (const [name, label, type] of spec) {
    const row = el("label", "assess-row");
    row.appendChild(el("span", null, label));
    const input = document.createElement("input");
    input.type = type; input.step = "0.1"; input.min = "0";
    input.placeholder = String(f.extra?.risk_inputs?.[name]?.value ?? "");
    fields[name] = input;
    row.appendChild(input);
    form.appendChild(row);
  }

  const sensRow = el("label", "assess-row");
  sensRow.appendChild(el("span", null, "Data sensitivity"));
  const sens = document.createElement("select");
  sens.appendChild(new Option("(derived)", ""));
  for (const k of Object.keys(state_meta()?.sensitivities || {})) {
    sens.appendChild(new Option(k, k));
  }
  fields.sensitivity = sens;
  sensRow.appendChild(sens);
  form.appendChild(sensRow);

  const consRow = el("div", "assess-row assess-cons");
  consRow.appendChild(el("span", null, "Deployment constraints"));
  const consBox = el("div", "cons-box");
  const constraints = state_meta()?.constraints || {};
  const consInputs = [];
  for (const [key, meaning] of Object.entries(constraints)) {
    const lab = el("label", "cons");
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = key;
    lab.title = meaning;
    lab.append(cb, document.createTextNode(" " + key));
    consInputs.push(cb);
    consBox.appendChild(lab);
  }
  consRow.appendChild(consBox);
  form.appendChild(consRow);

  const body = () => {
    const out = { constraints: consInputs.filter((c) => c.checked).map((c) => c.value) };
    for (const [name, input] of Object.entries(fields)) {
      const v = input.value.trim();
      if (v !== "") out[name] = input.type === "number" ? Number(v) : v;
    }
    return out;
  };

  const actions = el("div", "assess-actions");
  const previewBtn = el("button", "btn-s", "Preview");
  const saveBtn = el("button", "btn-p", "Save assessment");
  const resetBtn = el("button", "btn-q", "Reset to defaults");
  actions.append(previewBtn, saveBtn, resetBtn);

  const outcome = el("p", "assess-out");

  previewBtn.addEventListener("click", async () => {
    try {
      const q = qdayBody();
      const r = await api("/api/assessment/preview", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: state.scanId, asset_key: assetKey,
                               ...q, override: body() }),
      });
      state_setPreview(true);
      wrap.classList.add("is-preview");
      state.textContent = "PREVIEW — nothing has been saved.";
      outcome.textContent =
        `Risk ${r.before.risk_score} → ${r.after.risk_score} `
        + `(${r.after.severity}); exposure ${r.before.exposure_years} → `
        + `${r.after.exposure_years} years.`;
    } catch (e) { outcome.textContent = "Rejected: " + e.message; }
  });

  saveBtn.addEventListener("click", async () => {
    try {
      await api("/api/assessment/override/" + encodeURIComponent(assetKey), {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body()),
      });
      wrap.classList.remove("is-preview");
      state.textContent = "Saved. This asset now uses your inputs on every rescore.";
      outcome.textContent = "Re-run the Q-Day control or rescan to see it applied.";
    } catch (e) { outcome.textContent = "Rejected: " + e.message; }
  });

  resetBtn.addEventListener("click", async () => {
    try {
      await api("/api/assessment/override/" + encodeURIComponent(assetKey),
                { method: "DELETE" });
      wrap.classList.remove("is-preview");
      for (const input of Object.values(fields)) input.value = "";
      for (const cb of consInputs) cb.checked = false;
      state.textContent = "Reset. This asset is back to derived and default inputs.";
      outcome.textContent = "";
    } catch (e) { outcome.textContent = "Failed: " + e.message; }
  });

  wrap.append(state, form, actions, outcome);
  return wrap;
}

/* The console keeps one copy of the editable-input schema, fetched once. */
let _inputMeta = null;
function state_meta() { return _inputMeta; }

/* Whether what is on screen is a saved assessment or an unsaved what-if. This
   is a banner rather than a subtlety: an operator who quotes a preview as a
   saved figure has quoted a number nobody kept. */
function setAssessmentState(kind, overridesApplied, assessedOn) {
  const host = $("assess-banner");
  if (!host) return;
  const saved = kind === "saved";
  host.hidden = false;
  host.className = "assess-banner " + (saved ? "is-saved" : "is-preview");
  host.textContent = saved
    ? `Saved assessment · ${assessedOn || ""} · ${overridesApplied || 0} asset(s) with operator inputs`
    : `Unsaved preview · release the Q-Day control to save · ${overridesApplied || 0} asset(s) with operator inputs`;
}
function state_setPreview(on) { state.previewing = !!on; }
async function loadAssessmentMeta() {
  try { _inputMeta = await api("/api/assessment/inputs"); } catch { _inputMeta = null; }
}
function qdayBody() {
  const likely = Number($("qday-likely").value);
  return { earliest: state.qday?.earliest ?? 2030, likely,
           latest: state.qday?.latest ?? 2044 };
}

/* ─── 06 scan history ───────────────────────────────────────────────
   Every stored scan, reopenable. The store has always had these; the console
   simply never showed them, so an operator could not get back to an
   assessment they had already made. */
async function loadHistory() {
  const host = $("history-list");
  const state = $("history-state");
  if (!host) return;

  state.hidden = false;
  state.className = "state";
  state.textContent = "Loading…";
  host.textContent = "";

  try {
    const { scans } = await api("/api/scans");
    if (!scans.length) {
      state.className = "state empty";
      state.textContent = "No scans stored yet. Run one above and it will appear here.";
      return;
    }
    state.hidden = true;
    $("x-history").textContent = `${scans.length} stored`;

    for (const scan of scans) {
      host.appendChild(historyRow(scan));
    }
  } catch (e) {
    state.className = "state error";
    state.textContent = "Could not load scan history: " + e.message;
  }
}

function historyRow(scan) {
  const stats = scan.stats || {};
  const summary = scan.summary || {};
  const complete = stats.complete !== false;

  const li = document.createElement("li");
  li.className = "hist" + (scan.id === state.scanId ? " is-current" : "");

  const when = scan.started_at
    ? new Date(scan.started_at * 1000).toLocaleString()
    : "—";

  const head = el("div", "hist-h");
  head.appendChild(el("span", "hist-label", scan.target_label || scan.target_value));
  const badge = el("span", "hist-state " + (complete ? "ok" : "partial"),
                   complete ? "COMPLETE" : "PARTIAL");
  badge.title = complete
    ? "Every selected sensor ran and nothing was refused."
    : (stats.incomplete_reasons || []).join("; ");
  head.appendChild(badge);
  li.appendChild(head);

  li.appendChild(el("div", "hist-m",
    `${when} · ${scan.target_kind || "repository"} · `
    + `${scan.finding_count ?? summary.total ?? 0} asset(s)`
    + (summary.quantum_vulnerable !== undefined
        ? ` · ${summary.quantum_vulnerable} quantum-vulnerable` : "")));

  const path = el("div", "hist-p mono", scan.target_value || "");
  path.title = scan.target_value || "";
  li.appendChild(path);

  if (!complete && (stats.incomplete_reasons || []).length) {
    const why = el("ul", "hist-why");
    for (const reason of stats.incomplete_reasons.slice(0, 4)) {
      why.appendChild(el("li", null, reason));
    }
    li.appendChild(why);
  }

  const actions = el("div", "hist-a");
  const open = el("button", "btn-s", "Reopen");
  open.addEventListener("click", () => reopenScan(scan.id));
  const report = el("a", "btn-q", "Report");
  report.href = `/api/scan/${scan.id}/report`;
  report.target = "_blank"; report.rel = "noopener";
  const cbom = el("a", "btn-q", "CBOM");
  cbom.href = `/api/scan/${scan.id}/cbom?download=true`;
  actions.append(open, report, cbom);
  li.appendChild(actions);
  return li;
}

async function reopenScan(id) {
  const state_el = $("history-state");
  state_el.hidden = false;
  state_el.className = "state";
  state_el.textContent = "Loading that scan…";
  try {
    const payload = await api(`/api/scan/${id}`);
    adoptScan(id, payload);
    state_el.hidden = true;
    loadHistory();
    document.getElementById("s-verdict").scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    state_el.className = "state error";
    state_el.textContent = "Could not reopen that scan: " + e.message;
  }
}

/* Show whether the assessment on screen is complete, and if not, why. */
function renderIntegrity(payload) {
  const box = $("integrity");
  if (!box) return;
  const warnings = payload.warnings || [];
  if (payload.complete !== false && !warnings.length) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  box.className = "integrity" + (payload.complete === false ? " partial" : " warn");
  box.textContent = "";
  box.appendChild(el("strong", null,
    payload.complete === false
      ? "PARTIAL SCAN — this inventory is incomplete."
      : "This scan completed with warnings."));
  const ul = el("ul", null);
  for (const w of warnings.slice(0, 6)) ul.appendChild(el("li", null, w));
  box.appendChild(ul);
  if (payload.complete === false) {
    box.appendChild(el("p", "muted",
      "Findings from the sensors that did run are valid. Absence of a finding "
      + "is not evidence of absence."));
  }
}

function sec(t) { const s = el("div", "d-sec"); s.appendChild(el("h3", null, t)); return s; }
function kv(pairs) {
  const dl = el("dl", "kv");
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, String(v)));
  }
  return dl;
}

function openDrawer(f, isRefresh) {
  hideTip();
  if (!isRefresh) _returnTo = document.activeElement;
  _open = f;
  const d = $("drawer-body"); d.textContent = "";

  const head = el("div", "d-head");
  head.appendChild(el("div", "d-title", f.algorithm));
  head.appendChild(el("div", "d-sub", f.title));
  const meta = el("div", "d-meta");
  const c = el("span", "cls " + f.quantum_class);
  const dot = document.createElement("i");
  dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
  c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
  const sevSpan = el("span", null, `${sevOf(f.risk_score)} · ${f.risk_score.toFixed(1)}`);
  sevSpan.style.color = tok(SEV_VAR[sevOf(f.risk_score)]);
  const asrSpan = el("span", "asr-chip asr-" + (f.assurance || "capability"),
                     ASSURANCE_LABEL[f.assurance] || "");
  asrSpan.title = ASSURANCE_TIP[f.assurance] || "";
  meta.append(c, sevSpan, asrSpan, el("span", null, f.extra?.context || "production"));
  head.appendChild(meta);
  d.appendChild(head);

  if (f.detail) { const s = sec("Assessment"); s.appendChild(el("p", "said", f.detail)); d.appendChild(s); }

  /* Purpose and assurance, stated before the recommendation, because both are
     the reasons the recommendation says what it says. */
  {
    const s = sec("What the evidence establishes");
    s.appendChild(kv([
      ["Purpose", PURPOSE_LABEL[f.purpose] || f.purpose || "unresolved"],
      ["Assurance", ASSURANCE_LABEL[f.assurance] || f.assurance || ""],
      ["Proves use", f.proves_use ? "yes" : "no — reachable or declared only"],
    ]));
    if (f.purpose_evidence) s.appendChild(el("p", "said", "Purpose " + f.purpose_evidence + "."));
    s.appendChild(el("p", "said", ASSURANCE_TIP[f.assurance] || ""));
    const br = f.assurance_breakdown || {};
    const parts = Object.entries(br).map(([k, v]) => `${v} ${ASSURANCE_LABEL[k] || k}`);
    if (parts.length > 1) {
      s.appendChild(el("p", "said", "Evidence mix: " + parts.join(", ") + "."));
    }
    d.appendChild(s);
  }

  const m = f.extra?.mosca;
  if (m) {
    const s = sec("Mosca exposure");
    s.appendChild(kv([["Secrecy (X)", `${m.shelf_life} yr`], ["Migration (Y)", `${m.migration_years} yr`],
      ["To Q-Day (Z)", `${m.years_to_qday} yr`], ["Exposure", `${m.exposure_years} yr`],
      ["P(exposed)", `${(m.probability_exposed * 100).toFixed(0)}%`]]));
    s.appendChild(el("p", "said", m.verdict)); d.appendChild(s);
  }

  const r = f.recommendation;
  if (r && r.unresolved) {
    const s = sec("No migration target named");
    s.appendChild(kv([["Reason", r.target_name], ["Purpose", PURPOSE_LABEL[r.purpose] || r.purpose]]));
    if (r.rationale) s.appendChild(el("p", "said", r.rationale));
    if (r.action) s.appendChild(el("p", "said act", r.action));
    if (r.validate_before) s.appendChild(el("p", "said warn", r.validate_before));
    d.appendChild(s);
  } else if (r) {
    const s = sec("Recommended migration");
    s.appendChild(kv([["Target", r.target_name],
      ["Chosen for", PURPOSE_LABEL[r.purpose] || r.purpose], ["Effort", r.effort],
      ["Hybrid", r.hybrid ? "yes" : "no"],
      ["Size delta", (r.size_delta_bytes === null || r.size_delta_bytes === undefined)
        ? "" : `${r.size_delta_bytes > 0 ? "+" : ""}${r.size_delta_bytes} B`],
      ["Libraries", r.library_support]]));
    if (r.rationale) s.appendChild(el("p", "said", r.rationale));
    if (r.action) s.appendChild(el("p", "said act", r.action));
    if (r.size_note) s.appendChild(el("p", "said warn", r.size_note));
    if (r.agility_note) s.appendChild(el("p", "said", r.agility_note));
    if (r.validate_before) s.appendChild(el("p", "said warn", r.validate_before));
    if (r.purpose_evidence) {
      s.appendChild(el("p", "said", "Target chosen because the purpose was "
        + r.purpose_evidence + "."));
    }
    d.appendChild(s);
  }

  /* Container provenance. Which image, which layer, and — the part that
     matters — whether the file is still in the final filesystem. */
  const prov = f.extra?.container;
  if (prov) {
    const s = sec("Container provenance");
    s.appendChild(kv([
      ["Image", prov.image || "—"],
      ["Path", prov.path || "—"],
      ["Layer", prov.layer_index >= 0
        ? `${prov.layer_index} · ${(prov.layer_digest || "").slice(0, 19)}`
        : "image config"],
      ["State", prov.effective ? "in the final filesystem" : "historical layer only"],
    ]));
    if (!prov.effective) {
      s.appendChild(el("p", "said warn",
        `Layer ${prov.superseded_by_layer} removed or replaced this file. It is `
        + "still extractable from the archive, so it is inventoried — but it is "
        + "not part of what the image runs."));
    }
    d.appendChild(s);
  }

  /* Correlation. A link, never a merge: this finding's own assurance is
     restated here so nobody reads the link as a promotion. */
  const link = f.extra?.correlation;
  if (link) {
    const s = sec("Correlated with other evidence");
    s.appendChild(kv([
      ["Linked by", (link.basis || []).join(", ") || "—"],
      ["Other detectors", (link.peer_detectors || []).join(", ") || "—"],
      ["This finding's assurance", ASSURANCE_LABEL[link.own_assurance_unchanged]
        || link.own_assurance_unchanged],
      ["Strongest in group", ASSURANCE_LABEL[link.strongest_assurance_in_group]
        || link.strongest_assurance_in_group],
    ]));
    s.appendChild(el("p", "said",
      "Linked because the same concrete artefact was cited by more than one "
      + "detector. The link does not change this finding's assurance or "
      + "confidence."));

    /* The peers themselves, not just their ids. A link you cannot follow is
       an assertion; a link you can follow is evidence. */
    const peers = (link.peers || [])
      .map((id) => state.findings.find((x) => x.id === id))
      .filter(Boolean);
    if (peers.length) {
      const list = el("div", "peers");
      for (const peer of peers) {
        const row = el("div", "peer");
        const head = el("div", "peer-h");
        head.appendChild(el("span", "mono", peer.algorithm));
        head.appendChild(el("span", "prov prov-" + (peer.assurance || ""),
                            ASSURANCE_LABEL[peer.assurance] || peer.assurance));
        head.appendChild(el("span", "muted", peer.scanner || ""));
        row.appendChild(head);
        row.appendChild(el("div", "peer-t", peer.title || ""));
        for (const ev of (peer.evidence || []).slice(0, 3)) {
          row.appendChild(el("div", "peer-e mono",
            (ev.line ? `${ev.location}:${ev.line}` : ev.location)
            + ` · ${ev.technique} · conf ${Number(ev.confidence).toFixed(2)}`));
        }
        const open = el("button", "btn-q", "Open this finding");
        open.addEventListener("click", () => openDrawer(peer));
        row.appendChild(open);
        list.appendChild(row);
      }
      s.appendChild(list);
    } else if ((link.peers || []).length) {
      s.appendChild(el("p", "said muted",
        "The linked findings are filtered out of the current view. Clear the "
        + "filters in the inventory to see them."));
    }
    if (link.corroborated_by_use) {
      s.appendChild(el("p", "said act",
        "A declared capability here is corroborated by evidence of actual use "
        + "elsewhere in the same component."));
    }
    for (const c of (link.conflicts || [])) {
      s.appendChild(el("p", "said warn", c));
    }
    d.appendChild(s);
  }

  /* ── Assessment: the inputs, where each came from, and an editor ──
     Every number the score rests on is shown with its origin. A score built
     from four defaults and one built from four reviewed values look identical
     unless the tool says which is which. */
  {
    const inputs = f.extra?.risk_inputs || {};
    const model = f.extra?.exposure_model || {};
    const meta = f.extra?.assessment || {};
    const assetKey = f.extra?.asset_key;
    const s = sec("Assessment inputs");

    if (model.label) {
      s.appendChild(el("p", "said",
        `Exposure model: ${model.label}. X means ${model.x_label}. `
        + (model.retroactive
            ? "Damage is retroactive — data already sealed cannot be un-sealed by migrating later."
            : "Nothing already signed is invalidated; the risk is forgery from Q-Day onward.")));
    }

    const rows = el("div", "inputs");
    for (const [name, input] of Object.entries(inputs)) {
      const row = el("div", "input-row");
      row.appendChild(el("span", "input-k", name.replace(/_/g, " ")));
      row.appendChild(el("span", "input-v", String(input.value)));
      const tag = el("span", "prov prov-" + input.provenance, input.provenance_label);
      tag.title = input.source || "";
      row.appendChild(tag);
      rows.appendChild(row);
    }
    s.appendChild(rows);

    if (assetKey) s.appendChild(assessmentEditor(f, assetKey));
    d.appendChild(s);
  }

  const fac = f.extra?.factors;
  if (fac) {
    const s = sec("Score composition");
    s.appendChild(kv(Object.entries(fac).map(([k, v]) =>
      [k.replace(/_/g, " "), typeof v === "number" ? String(Number(v.toFixed(3))) : v])));
    d.appendChild(s);
  }

  const files = f.extra?.files || 1;
  const shown = Math.min(40, (f.evidence || []).length);
  const s2 = sec(`Evidence — ${shown} of ${f.occurrences} in ${files} file${files === 1 ? "" : "s"}`);
  for (const ev of (f.evidence || []).slice(0, 40)) {
    const item = el("div", "ev");
    item.appendChild(el("div", "l", ev.line ? `${ev.location}:${ev.line}` : ev.location));
    if (ev.snippet) item.appendChild(el("div", "s", ev.snippet));
    item.appendChild(el("div", "m",
      `${ev.technique} · ${ASSURANCE_LABEL[ev.assurance] || ev.assurance || "?"}`
      + ` · conf ${ev.confidence.toFixed(2)}${ev.symbol ? " · " + ev.symbol : ""}`));
    s2.appendChild(item);
  }
  d.appendChild(s2);

  const drawer = $("drawer");
  drawer.hidden = false; $("scrim").hidden = false;
  drawer.setAttribute("role", "dialog");
  drawer.setAttribute("aria-modal", "true");
  drawer.setAttribute("aria-label", `${f.algorithm} — ${f.title}`);
  if (!isRefresh) $("drawer-close").focus();
}

function closeDrawer() {
  if ($("drawer").hidden) return;
  $("drawer").hidden = true; $("scrim").hidden = true;
  _open = null;
  if (_returnTo && document.contains(_returnTo)) _returnTo.focus();
  _returnTo = null;
}

/* Keep Tab inside the drawer while it is modal. */
document.addEventListener("keydown", (e) => {
  if (e.key !== "Tab" || $("drawer").hidden) return;
  const f = $("drawer").querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

const cbomVersion = () => ($("cbom-version") || {}).value || "1.6";

/* Two results, reported as two results. The structural check is ours and is
   not conformance; the official one validates against the schema the
   CycloneDX project publishes. Collapsing them into one PASS would be the
   overclaim this whole surface exists to avoid, and "could not run" must
   never read as "passed". */
async function validateCbom() {
  if (!state.scanId) return;
  const box = $("validate-result");
  const version = cbomVersion();
  box.hidden = false; box.className = "call"; box.textContent = "Validating…";
  try {
    const r = await api(`/api/scan/${state.scanId}/cbom/validate`
      + `?spec_version=${encodeURIComponent(version)}`);

    const structural = r.structural || {};
    const official = r.official || {};
    const lines = [];

    lines.push(structural.valid
      ? `Structural check: PASS (${r.components} components).`
      : `Structural check: FAIL — ${(structural.problems || []).slice(0, 2).join("; ")}`);

    if (!official.checked) {
      lines.push(`Official ${r.spec} schema: NOT RUN — ${official.reason_unavailable || "unavailable"}.`);
    } else if (official.valid) {
      lines.push(`Official ${r.spec} JSON Schema: PASS `
        + `(pinned ${String(official.schema?.pinned_commit || "").slice(0, 8)}).`);
    } else {
      lines.push(`Official ${r.spec} JSON Schema: FAIL — `
        + `${(official.problems || []).slice(0, 2).join("; ")}`);
    }

    const ok = structural.valid && official.valid === true;
    box.className = "call " + (ok ? "pass" : (official.checked === false ? "" : "fail"));
    box.textContent = lines.join(" ");
  } catch (e) { box.className = "call fail"; box.textContent = "Validation failed: " + e.message; }
}

boot();
