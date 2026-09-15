/* CryptoDrishti. Vanilla JS, no framework, no build step, no external request. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null, scanId: null, findings: [], summary: null, scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  classFilter: null, invView: "ranked",
  pollTimer: null, qdayTimer: null, hideTimer: null, shown: {},
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
const SENSORS = ["source", "dependency", "certificate", "config", "binary", "network"];
const SECTIONS = [
  ["s-verdict", "Assessment"], ["s-estate", "Risk distribution"],
  ["s-clock", "Exposure window"], ["s-plan", "Remediation"], ["s-record", "Inventory"],
];
const FIGS = [
  ["total",    "Assets",        "distinct cryptographic assets"],
  ["vuln",     "Vulnerable",    "broken or weakened by quantum attack"],
  ["crit",     "Critical",      "risk score at or above 70"],
  ["exposure", "Peak exposure", "years readable past Q-Day"],
];

const sevOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;

/* Memoised: renderSwarm and renderInventory would otherwise force a style read per mark. */
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

  const preset = $("target-preset");
  for (const t of state.meta.suggested_targets) {
    const o = document.createElement("option");
    o.value = t.path; o.textContent = t.label; preset.appendChild(o);
  }
  preset.addEventListener("change", () => { if (preset.value) $("scan-path").value = preset.value; });
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

  buildFigures(); buildSensors(); buildIndex(); initTheme();

  $("run-scan").addEventListener("click", startScan);
  $("scan-path").addEventListener("keydown", (e) => { if (e.key === "Enter") startScan(); });
  let ft = null;
  $("filter-q").addEventListener("input", () => { clearTimeout(ft); ft = setTimeout(renderInventory, 90); });
  $("filter-class").addEventListener("change", () => {
    state.classFilter = $("filter-class").value || null;
    renderSwarm(); renderInventory(); renderComposition();
  });
  $("filter-context").addEventListener("change", renderInventory);
  const setView = (v) => {
    state.invView = v;
    $("view-ranked").setAttribute("aria-pressed", String(v === "ranked"));
    $("view-table").setAttribute("aria-pressed", String(v === "table"));
    $("inv-ranked").hidden = v !== "ranked";
    $("inv-table").hidden = v !== "table";
    try { localStorage.setItem("cd-inv", v); } catch (_) {}
    renderInventory();
  };
  $("view-ranked").addEventListener("click", () => setView("ranked"));
  $("view-table").addEventListener("click", () => setView("table"));
  let v0 = "ranked";
  try { v0 = localStorage.getItem("cd-inv") || "ranked"; } catch (_) {}
  setView(v0 === "table" ? "table" : "ranked");
  $("btn-cbom").addEventListener("click", () => {
    if (state.scanId) location.href = `/api/scan/${state.scanId}/cbom?download=true`;
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
    clearTimeout(rt); rt = setTimeout(() => { renderSwarm(); renderMosca(); }, 160);
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

/* ═══ chrome ════════════════════════════════════════════════════════ */

/* Built once so the count-up tweens keep a stable element to write into. */
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
    a.append(el("span", null, String(i + 1).padStart(2, "0")), el("span", null, name));
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
  }, { rootMargin: "-15% 0px -70% 0px" });
  for (const [id] of SECTIONS) obs.observe($(id));
}

function renderColophon() {
  const host = $("colophon");
  host.textContent = "";
  const m = state.scanMeta;
  if (!m) return;
  const st = m.stats || {};
  const dl = document.createElement("dl");
  const pairs = [
    ["Estate", m.target_label || m.target_value],
    ["Path", m.target_value],
    ["Profile", state.meta?.profiles?.[m.profile] || m.profile],
    ["Source files", st.files_scanned ? st.files_scanned.toLocaleString() : ""],
    ["Binaries", st.binaries_scanned || ""],
    ["Certificates", st.certificate_files_scanned || ""],
    ["Endpoints probed", st.endpoints_probed || ""],
    ["Sensors", (st.sensors_run || []).join(", ")],
    ["Detector hits", st.raw_hits ? st.raw_hits.toLocaleString() : ""],
    ["Duration", m.duration ? `${m.duration.toFixed(1)} s` : ""],
  ];
  // Omit a row rather than print an em dash: a colophon of placeholders reads
  // as a broken page, not as an absent value.
  for (const [k, v] of pairs) {
    if (!v) continue;
    const cell = el("div");
    cell.append(el("dt", null, k), el("dd", null, String(v)));
    dl.appendChild(cell);
  }
  host.appendChild(dl);
}

function onKey(e) {
  if (e.key === "Escape") { closeDrawer(); return; }
  if (e.target.matches("input, select, textarea")) return;
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  const ids = SECTIONS.map(([id]) => id);
  const mid = innerHeight / 3;
  let cur = 0;
  ids.forEach((id, i) => { if ($(id).getBoundingClientRect().top <= mid) cur = i; });
  const next = Math.max(0, Math.min(ids.length - 1, cur + (e.key === "ArrowDown" ? 1 : -1)));
  e.preventDefault();
  $(ids[next]).scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth" });
}

const isDark = () => {
  const s = document.documentElement.getAttribute("data-theme");
  return s ? s === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
};

function initTheme() {
  const sync = () => {
    $("theme-toggle").textContent = isDark() ? "Light" : "Dark";
    $("theme-toggle").setAttribute("aria-pressed", String(isDark()));
    dropTokens();
    renderSwarm(); renderMosca(); renderInventory(); renderPlan(); renderComposition();
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

/* ═══ scanning ══════════════════════════════════════════════════════ */

function buildSensors() {
  const host = $("sensors"); host.textContent = "";
  for (const k of SENSORS) {
    const s = el("span");
    s.dataset.sensor = k; s.dataset.state = "idle";
    s.append(document.createElement("i"), document.createTextNode(k));
    host.appendChild(s);
  }
}

function reflectSensors(phase) {
  const t = (phase || "").toLowerCase();
  const m = { source: "source code", dependency: "dependency", certificate: "certificate",
              config: "configuration", binary: "binaries", network: "endpoint" };
  const els = [...document.querySelectorAll("#sensors span")];
  let active = -1;
  els.forEach((n, i) => {
    if (m[n.dataset.sensor] && t.includes(m[n.dataset.sensor])) { n.dataset.state = "active"; active = i; }
  });
  if (active >= 0) els.forEach((n, i) => { if (i < active) n.dataset.state = "done"; });
}

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) { $("scan-path").focus(); return; }
  $("run-scan").disabled = true;
  clearTimeout(state.hideTimer);
  $("scan-progress").hidden = false;
  for (const n of document.querySelectorAll("#sensors span")) n.dataset.state = "idle";
  setProgress(2, "Queued");
  try {
    const { scan_id } = await api("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path,
        label: ($("target-preset").value ? $("target-preset").selectedOptions[0]?.textContent : "") || "",
        profile: $("profile").value,
        endpoints: $("scan-endpoints").value.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    });
    poll(scan_id);
  } catch (e) { setProgress(0, "Error: " + e.message); $("run-scan").disabled = false; }
}

function setProgress(pct, phase) {
  $("progress-fill").style.width = pct + "%";
  $("progress-pct").textContent = Math.round(pct) + "%";
  $("progress-phase").textContent = phase;
}

function poll(id) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    let job;
    try { job = await api(`/api/scan/${id}/status`); } catch (_) { return; }
    setProgress(job.progress || 0, job.phase || job.state);
    reflectSensors(job.phase);
    if (job.state === "done") {
      clearInterval(state.pollTimer);
      $("run-scan").disabled = false;
      for (const n of document.querySelectorAll("#sensors span")) n.dataset.state = "done";
      await loadScan(id);
      state.hideTimer = setTimeout(() => { $("scan-progress").hidden = true; }, 1600);
    } else if (job.state === "error") {
      clearInterval(state.pollTimer);
      $("run-scan").disabled = false;
      setProgress(0, "Scan failed: " + (job.error || "unknown error"));
      console.error(job.trace || job.error);
    }
  }, 400);
}

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
  state.classFilter = null;
  $("filter-class").value = "";
  $("validate-result").hidden = true;
  renderAll();
}

async function reconcile() {
  const m = state.findings[0]?.extra?.mosca;
  if (!m) return;
  const wantZ = state.qday.likely - NOW_YEAR;
  const wantX = state.meta?.sensitivities?.[state.sensitivity];
  if (Math.abs(m.years_to_qday - wantZ) > 0.01
      || (wantX !== undefined && Math.abs(m.shelf_life - wantX) > 0.01)) await recomputeQday(false);
}

async function loadScan(id) { applyScan(id, await api(`/api/scan/${id}`)); await reconcile(); }

/* ═══ Q-Day ═════════════════════════════════════════════════════════ */

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
      if (d.mosca) f.extra.mosca = d.mosca;
      if (d.factors) f.extra.factors = d.factors;
    }
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
    ["verdict", renderVerdict], ["composition", renderComposition],
    ["colophon", renderColophon], ["distribution", renderSwarm],
    ["exposure", renderMosca], ["plan", renderPlan], ["inventory", renderInventory],
  ]) {
    try { fn(); } catch (e) { console.error(`render ${name} failed`, e); }
  }
}

/* ─── 01 assessment ─────────────────────────────────────────────── */

function renderVerdict() {
  const s = state.summary;
  if (!s) return;

  animateTo($("v-pct"), "pct", s.vulnerable_pct, 0);

  const broken = s.by_class["shor-broken"] || 0;
  const safe = (s.by_class["quantum-safe"] || 0) + (s.by_class["hybrid"] || 0);
  const line = $("v-line");
  line.textContent = "";
  line.append(
    document.createTextNode("of this estate does not survive a quantum computer. "),
    el("b", "bad", String(broken)),
    document.createTextNode(" assets break outright"),
  );
  if (safe) line.append(document.createTextNode("; "), el("b", "good", String(safe)),
                        document.createTextNode(" are already quantum-safe."));
  else line.append(document.createTextNode("."));

  animateTo($("fig-total"), "total", s.total);
  animateTo($("fig-vuln"), "vuln", s.quantum_vulnerable);
  animateTo($("fig-crit"), "crit", s.by_severity?.critical || 0);
  animateTo($("fig-exposure"), "exp", s.max_exposure_years, 1);

  $("x-verdict").textContent = `${s.total} assets · ${s.vulnerable_pct}% at risk`;
  $("x-estate").textContent = `${s.total} marks`;
  $("x-record").textContent = `${s.total} assets`;

}

/* One stacked bar carrying the whole estate, doubling as the class filter. */
function renderComposition() {
  const bar = $("composition"), key = $("legend");
  bar.textContent = ""; key.textContent = "";
  const s = state.summary;
  if (!s || !s.total) return;

  bar.classList.toggle("filtered", Boolean(state.classFilter));
  const setFilter = (k) => {
    state.classFilter = state.classFilter === k ? null : k;
    $("filter-class").value = state.classFilter || "";
    renderSwarm(); renderInventory(); renderComposition();
  };

  for (const k of CLASS_ORDER) {
    const n = s.by_class[k] || 0;
    if (!n) continue;
    const share = (n / s.total) * 100;

    const seg = document.createElement("button");
    seg.style.width = share + "%";
    seg.style.background = tok(CLASS_VAR[k]);
    seg.setAttribute("aria-pressed", String(state.classFilter === k));
    seg.title = `${CLASS_LABEL[k]} — ${n} of ${s.total}`;
    seg.setAttribute("aria-label", `${CLASS_LABEL[k]}, ${n} assets, ${share.toFixed(1)} percent`);
    seg.addEventListener("click", () => setFilter(k));
    bar.appendChild(seg);

    const b = document.createElement("button");
    b.setAttribute("aria-pressed", String(state.classFilter === k));
    const sw = document.createElement("i");
    sw.style.background = tok(CLASS_VAR[k]);
    const cnt = el("span", "kn", String(n));
    const wrap = el("span");
    wrap.append(el("span", "kl", CLASS_LABEL[k]), document.createTextNode(" "),
                el("span", "ks", `${share.toFixed(1)}%`));
    b.append(sw, cnt, wrap);
    b.addEventListener("click", () => setFilter(k));
    const li = document.createElement("li");
    li.appendChild(b); key.appendChild(li);
  }
}

/* ─── 02 risk distribution ──────────────────────────────────────── */

const NS = "http://www.w3.org/2000/svg";
function sv(n, a, t) {
  const e = document.createElementNS(NS, n);
  for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v);
  if (t !== undefined) e.textContent = t;
  return e;
}

function renderSwarm() {
  const svg = $("beeswarm");
  svg.textContent = "";
  if (!state.summary || !state.findings.length) return;

  const W = 1000, PAD_L = 6, PAD_R = 6, AX = 232, H = 268;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const x = (score) => PAD_L + (score / 100) * (W - PAD_L - PAD_R);
  const R = 5, GAP = 1.6;
  const MONO = tok("--mono"), ink3 = tok("--ink-3"), ink4 = tok("--ink-4");
  const rule = tok("--rule"), rule2 = tok("--rule-2");

  // band boundaries, drawn behind everything
  for (const [v, label] of [[25, "medium"], [45, "high"], [70, "critical"]]) {
    svg.appendChild(sv("line", { x1: x(v), y1: 18, x2: x(v), y2: AX,
      stroke: rule, "stroke-width": 1 }));
    svg.appendChild(sv("text", { x: x(v) + 6, y: 15, fill: ink4, "font-size": 11,
      "font-family": MONO, "letter-spacing": 1 }, label.toUpperCase()));
  }
  svg.appendChild(sv("text", { x: PAD_L, y: 15, fill: ink4, "font-size": 11,
    "font-family": MONO, "letter-spacing": 1 }, "RISK SCORE"));

  // axis
  svg.appendChild(sv("line", { x1: PAD_L, y1: AX, x2: W - PAD_R, y2: AX,
    stroke: rule2, "stroke-width": 1 }));
  for (const v of [0, 25, 45, 70, 100]) {
    svg.appendChild(sv("line", { x1: x(v), y1: AX, x2: x(v), y2: AX + 5,
      stroke: rule2, "stroke-width": 1 }));
    svg.appendChild(sv("text", { x: x(v), y: AX + 20, "text-anchor": "middle",
      fill: ink3, "font-size": 12, "font-family": MONO }, String(v)));
  }

  // Place each asset at its score, stacking upward only where marks would touch.
  const placed = [];
  const sorted = [...state.findings].sort((a, b) => a.risk_score - b.risk_score);
  for (const f of sorted) {
    const cx = x(f.risk_score);
    let cy = AX - R - 3, tries = 0;
    while (tries < 40 && placed.some((p) =>
      (p.cx - cx) ** 2 + (p.cy - cy) ** 2 < (2 * R + GAP) ** 2)) {
      cy -= (2 * R + GAP) * 0.92; tries += 1;
      if (cy < R + 24) { cy = AX - R - 3; break; }
    }
    placed.push({ cx, cy });
    const dimmed = state.classFilter && f.quantum_class !== state.classFilter;
    const dot = sv("circle", {
      cx, cy, r: R, fill: tok(CLASS_VAR[f.quantum_class] || "--unknown"),
      opacity: dimmed ? 0.15 : 1, tabindex: dimmed ? "-1" : "0", role: "img",
      "aria-label": `${f.algorithm}, ${CLASS_LABEL[f.quantum_class] || f.quantum_class}, `
        + `risk ${f.risk_score.toFixed(0)}, ${f.occurrences} call sites`,
    });
    dot.setAttribute("class", "dot");
    dot.addEventListener("mousemove", (e) => showTip(e, f));
    dot.addEventListener("mouseleave", hideTip);
    dot.addEventListener("click", () => openDrawer(f));
    dot.addEventListener("focus", () => showTipAt(dot, f));
    dot.addEventListener("blur", hideTip);
    dot.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
    });
    svg.appendChild(dot);
  }
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

/* ─── 03 exposure window ────────────────────────────────────────── */

/* Q-Day is modelled as a triangular distribution over [earliest, likely,
   latest]. Reporting a single date would be a claim nobody can support; the
   defensible statement is how much of that distribution lands inside the
   window during which this data still has to be secret. */
function triPdf(z, a, c, b) {
  if (z <= a || z >= b) return 0;
  return z <= c ? (2 * (z - a)) / ((b - a) * (c - a))
                : (2 * (b - z)) / ((b - a) * (b - c));
}
function triCdf(z, a, c, b) {
  if (z <= a) return 0;
  if (z >= b) return 1;
  return z <= c ? ((z - a) ** 2) / ((b - a) * (c - a))
                : 1 - ((b - z) ** 2) / ((b - a) * (b - c));
}

function renderMosca() {
  const svg = $("mosca-svg");
  const eq = $("mosca-eq");
  svg.textContent = ""; eq.textContent = "";

  if (!state.findings.length) {
    svg.appendChild(sv("text", { x: 500, y: 150, "text-anchor": "middle",
      fill: tok("--ink-4"), "font-size": 15, "font-family": tok("--ui") },
      "Run a scan to model exposure."));
    $("mosca-verdict").className = "call";
    $("mosca-verdict").textContent = "No estate loaded.";
    return;
  }

  let worst = null;
  for (const f of state.findings) {
    const m = f.extra?.mosca;
    if (m && (!worst || m.exposure_years > worst.exposure_years)) worst = m;
  }
  const X = state.meta?.sensitivities?.[state.sensitivity] ?? 10;
  const Y = worst ? worst.migration_years : 2.0;
  const Z = Math.max(0, state.qday.likely - NOW_YEAR);
  const T = X + Y;                                  // protection required through
  const exposure = Math.max(0, T - Z);

  // distribution bounds, in years from now
  const dA = Math.max(0, state.qday.earliest - NOW_YEAR);
  const dC = Math.max(dA + 0.5, state.qday.likely - NOW_YEAR);
  const dB = Math.max(dC + 0.5, state.qday.latest - NOW_YEAR);
  const pExposed = triCdf(T, dA, dC, dB);

  /* ── the inequality, stated ── */
  const cell = (label, value, cls) => {
    const d = el("div", cls);
    d.append(el("dt", null, label), el("dd", null, value));
    return d;
  };
  const op = (t) => el("div", "op", t);
  eq.append(
    cell("X · secrecy", `${X} yr`),
    op("+"),
    cell("Y · migration", `${Y} yr`),
    op("="),
    cell("Protect through", String(NOW_YEAR + T)),
    op("vs"),
    cell("Z · Q-Day median", String(state.qday.likely)),
    op("→"),
    cell("Exposure", `${exposure.toFixed(1)} yr`, exposure > 0 ? "res" : "res ok"),
    cell("P(exposed)", `${(pExposed * 100).toFixed(0)}%`, exposure > 0 ? "res" : "res ok"),
  );

  /* ── one chart, one axis: the protection window above, the arrival
        distribution below, so the overlap is the shaded area ── */
  const W = 1000, L = 30, R = 178, AXIS = 116, BASE = 292, CURVE = 130;
  const span = Math.max(T, dB, 8) * 1.06;
  const px = (y) => L + (y / span) * (W - L - R);
  const MONO = tok("--mono"), bad = tok("--i-broken"), ink3 = tok("--ink-3"),
        ink4 = tok("--ink-4"), rule2 = tok("--rule-2");
  const LX = W - R + 12;

  // protection window bars
  const bar = (name, y, x1, x2, colour, label) => {
    svg.appendChild(sv("text", { x: L - 8, y: y + 14, fill: ink3, "font-size": 12,
      "font-weight": 600, "font-family": MONO, "text-anchor": "end" }, name));
    svg.appendChild(sv("rect", { x: x1, y, width: Math.max(3, x2 - x1), height: 19, fill: colour }));
    svg.appendChild(sv("text", { x: LX, y: y + 14, fill: tok("--ink-2"),
      "font-size": 12, "font-family": MONO }, label));
  };
  svg.appendChild(sv("text", { x: L, y: 18, fill: ink4, "font-size": 10,
    "font-family": MONO, "letter-spacing": 1 }, "PROTECTION WINDOW"));
  bar("Y", 30, px(0), px(Y), tok("--unknown"), `${Y} yr migration`);
  bar("X", 62, px(Y), px(T), tok("--weakened"), `${X} yr secrecy`);

  // axis
  svg.appendChild(sv("line", { x1: L, y1: AXIS, x2: W - R + 30, y2: AXIS,
    stroke: rule2, "stroke-width": 1 }));
  const step = span > 26 ? 8 : span > 13 ? 4 : 2;
  for (let y = 0; y <= span + 1e-6; y += step) {
    const xx = px(y);
    if (xx > W - R + 30) break;
    svg.appendChild(sv("line", { x1: xx, y1: AXIS - 4, x2: xx, y2: AXIS + 4,
      stroke: rule2, "stroke-width": 1 }));
    svg.appendChild(sv("text", { x: xx, y: AXIS + 19, fill: ink3, "font-size": 12,
      "font-family": MONO, "text-anchor": "middle" }, String(NOW_YEAR + y)));
  }

  // the arrival distribution, drawn downward from below the axis
  const N = 240;
  let peak = 0;
  const pts = [];
  for (let i = 0; i <= N; i++) {
    const z = dA + ((dB - dA) * i) / N;
    const d = triPdf(z, dA, dC, dB);
    if (d > peak) peak = d;
    pts.push([z, d]);
  }
  const cy = (d) => BASE - (peak ? (d / peak) * CURVE : 0);
  const polyTo = (lo, hi) => {
    const seg = pts.filter(([z]) => z >= lo && z <= hi);
    if (seg.length < 2) return null;
    const head = `${px(lo)},${BASE}`;
    const body = seg.map(([z, d]) => `${px(z).toFixed(2)},${cy(d).toFixed(2)}`).join(" ");
    return `${head} ${px(lo).toFixed(2)},${cy(triPdf(lo, dA, dC, dB)).toFixed(2)} ${body} `
         + `${px(hi).toFixed(2)},${cy(triPdf(hi, dA, dC, dB)).toFixed(2)} ${px(hi)},${BASE}`;
  };
  svg.appendChild(sv("text", { x: LX, y: BASE, fill: ink4, "font-size": 10,
    "font-family": MONO, "letter-spacing": 1 }, "Q-DAY ARRIVAL"));

  const cut = Math.min(Math.max(T, dA), dB);
  const safePoly = polyTo(cut, dB);
  if (safePoly) svg.appendChild(sv("polygon", { points: safePoly,
    fill: tok("--unknown"), opacity: .16 }));
  const hitPoly = polyTo(dA, cut);
  if (hitPoly) svg.appendChild(sv("polygon", { points: hitPoly, fill: bad, opacity: .26 }));

  svg.appendChild(sv("polyline", {
    points: pts.map(([z, d]) => `${px(z).toFixed(2)},${cy(d).toFixed(2)}`).join(" "),
    fill: "none", stroke: tok("--ink-3"), "stroke-width": 1.5 }));
  svg.appendChild(sv("line", { x1: px(dA), y1: BASE, x2: px(dB), y2: BASE,
    stroke: rule2, "stroke-width": 1 }));

  // the protection boundary, cutting through both halves
  svg.appendChild(sv("line", { x1: px(T), y1: 24, x2: px(T), y2: BASE,
    stroke: bad, "stroke-width": 1.5, "stroke-dasharray": "5 4" }));
  const flip = px(T) > W - R - 150;
  svg.appendChild(sv("text", { x: px(T) + (flip ? -8 : 8), y: 100, fill: bad,
    "font-size": 12, "font-weight": 640, "font-family": MONO,
    "text-anchor": flip ? "end" : "start" }, `PROTECT THROUGH ${NOW_YEAR + T}`));

  // the median, marked on the distribution only
  svg.appendChild(sv("line", { x1: px(dC), y1: cy(peak), x2: px(dC), y2: BASE,
    stroke: ink3, "stroke-width": 1, "stroke-dasharray": "3 3" }));
  const mflip = px(dC) > W - R - 130;
  svg.appendChild(sv("text", { x: px(dC) + (mflip ? -6 : 6), y: cy(peak) - 6, fill: ink3,
    "font-size": 11, "font-family": MONO, "text-anchor": mflip ? "end" : "start" },
    `MEDIAN ${state.qday.likely}`));

  if (pExposed > 0.02 && hitPoly) {
    const mid = px(Math.max(dA, (dA + cut) / 2));
    svg.appendChild(sv("text", { x: mid, y: BASE + 20, fill: bad, "font-size": 12,
      "font-weight": 640, "font-family": MONO, "text-anchor": "middle" },
      `P(EXPOSED) = ${(pExposed * 100).toFixed(0)}%`));
  }

  const out = $("mosca-verdict");
  if (exposure > 0) {
    out.className = "call";
    out.textContent = `Data sealed today must stay secret through ${NOW_YEAR + T}. `
      + `${(pExposed * 100).toFixed(0)}% of the modelled Q-Day distribution falls before that, `
      + `leaving the worst asset readable for ${exposure.toFixed(1)} years.`;
  } else {
    out.className = "call ok";
    out.textContent = "Migration completes before the modelled arrival window. "
      + "Within tolerance at the current assumptions.";
  }
  $("x-clock").textContent = `X ${X} · Y ${Y} · Z ${Z} yr`;
}

/* ─── 04 remediation programme ──────────────────────────────────── */

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
    tr.append(
      nameTd,
      td("n", String(g.assets)),
      td("n", g.sites.toLocaleString()),
      td("n", delta),
      td("ctx", g.effort),
      td("act", g.action),
    );
    body.appendChild(tr);
  }
}

/* ─── 05 inventory ──────────────────────────────────────────────── */

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

/* Two readings of the same list. Ranked shows risk as a length, which carries
   across a room; the table carries every column for someone reading closely. */
function renderInventory() {
  const rows = visible();
  $("findings-hint").textContent = state.findings.length
    ? `Showing ${rows.length} of ${state.findings.length} assets. Select a row for evidence and remediation.`
    : "Detector hits grouped into distinct assets.";
  if (state.invView === "table") renderTable(rows); else renderRanked(rows);
}

function emptyMessage() {
  return state.findings.length ? "Nothing matches those filters."
    : (state.scanId ? "This scan found no cryptographic assets."
                    : "No scan loaded — set a target above and press Run scan.");
}

function renderRanked(rows) {
  const host = $("inv-ranked");
  host.textContent = "";
  if (!rows.length) { host.appendChild(el("p", "rk-empty", emptyMessage())); return; }

  const head = el("div", "rk-head");
  for (const h of ["Risk", "", "Algorithm", "Class", "Finding", "Sites", "Migrate to"]) {
    head.appendChild(el("span", "rk-h", h));
  }
  host.appendChild(head);

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const row = document.createElement("button");
    row.className = "rk";
    row.dataset.sev = sevOf(f.risk_score);
    row.setAttribute("aria-label",
      `${f.algorithm}: ${f.title}. Risk ${f.risk_score.toFixed(0)}, `
      + `${CLASS_LABEL[f.quantum_class] || f.quantum_class}.`);

    const meter = el("span", "rk-meter");
    const fill = document.createElement("i");
    fill.style.width = Math.max(2, f.risk_score) + "%";
    fill.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    meter.appendChild(fill);

    const cls = el("span", "cls " + f.quantum_class);
    const dot = document.createElement("i");
    dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    cls.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));

    const find = el("span", "rk-find", f.title); find.title = f.title;
    const algo = el("span", "rk-algo", f.algorithm); algo.title = f.algorithm;
    const to = el("span", "rk-to", f.recommendation?.target_name || "—");
    to.title = f.recommendation?.target_name || "";

    row.append(
      el("span", "rk-score", f.risk_score.toFixed(0)),
      meter, algo, cls, find,
      el("span", "rk-sites", f.occurrences.toLocaleString()),
      to,
    );
    row.addEventListener("click", () => openDrawer(f));
    frag.appendChild(row);
  }
  host.appendChild(frag);
}

function renderTable(rows) {
  const body = $("findings-body");
  body.textContent = "";
  if (!rows.length) {
    const tr = el("tr", "empty");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = emptyMessage();
    tr.appendChild(td); body.appendChild(tr); return;
  }

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.dataset.sev = sevOf(f.risk_score);
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-label", `${f.algorithm}: ${f.title}. Risk ${f.risk_score.toFixed(0)}.`);
    const cell = (cls, text) => {
      const td = document.createElement("td");
      if (cls) td.className = cls;
      if (text !== undefined) td.textContent = text;
      return td;
    };
    const clsTd = cell();
    const c = el("span", "cls " + f.quantum_class);
    const dot = document.createElement("i");
    dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
    clsTd.appendChild(c);
    const ev = f.evidence?.[0];
    const where = ev ? (ev.line ? `${ev.location}:${ev.line}` : ev.location) : "";
    const target = f.recommendation?.target_name || "";
    tr.append(
      cell("n risk", f.risk_score.toFixed(0)),
      Object.assign(cell("algo", f.algorithm), { title: f.algorithm }),
      clsTd,
      Object.assign(cell(null, f.title), { title: f.title }),
      cell("n", f.occurrences.toLocaleString()),
      cell("ctx", f.extra?.context || "production"),
      Object.assign(cell("loc", where), { title: where }),
      Object.assign(cell("to", target), { title: target }),
    );
    tr.addEventListener("click", () => openDrawer(f));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
    });
    frag.appendChild(tr);
  }
  body.appendChild(frag);
}

/* ═══ drawer ════════════════════════════════════════════════════════ */

let _open = null, _returnTo = null;

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
  meta.append(c, sevSpan, el("span", null, f.extra?.context || "production"));
  head.appendChild(meta);
  d.appendChild(head);

  if (f.detail) { const s = sec("Assessment"); s.appendChild(el("p", "said", f.detail)); d.appendChild(s); }

  const m = f.extra?.mosca;
  if (m) {
    const s = sec("Mosca exposure");
    s.appendChild(kv([["Secrecy (X)", `${m.shelf_life} yr`], ["Migration (Y)", `${m.migration_years} yr`],
      ["To Q-Day (Z)", `${m.years_to_qday} yr`], ["Exposure", `${m.exposure_years} yr`],
      ["P(exposed)", `${(m.probability_exposed * 100).toFixed(0)}%`]]));
    s.appendChild(el("p", "said", m.verdict)); d.appendChild(s);
  }

  const r = f.recommendation;
  if (r) {
    const s = sec("Recommended migration");
    s.appendChild(kv([["Target", r.target_name], ["Effort", r.effort],
      ["Hybrid", r.hybrid ? "yes" : "no"],
      ["Size delta", (r.size_delta_bytes === null || r.size_delta_bytes === undefined)
        ? "" : `${r.size_delta_bytes > 0 ? "+" : ""}${r.size_delta_bytes} B`],
      ["Libraries", r.library_support]]));
    if (r.rationale) s.appendChild(el("p", "said", r.rationale));
    if (r.action) s.appendChild(el("p", "said act", r.action));
    if (r.size_note) s.appendChild(el("p", "said warn", r.size_note));
    if (r.agility_note) s.appendChild(el("p", "said", r.agility_note));
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
      `${ev.technique} · conf ${ev.confidence.toFixed(2)}${ev.symbol ? " · " + ev.symbol : ""}`));
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

async function validateCbom() {
  if (!state.scanId) return;
  const box = $("validate-result");
  box.hidden = false; box.className = "call"; box.textContent = "Validating…";
  try {
    const r = await api(`/api/scan/${state.scanId}/cbom/validate`);
    box.className = "call " + (r.valid ? "pass" : "fail");
    box.textContent = r.valid
      ? `PASS — ${r.components} cryptographic-asset components conform to ${r.spec}.`
      : `FAIL — ${r.problems.length} problem(s): ${r.problems.slice(0, 3).join("; ")}`;
  } catch (e) { box.className = "call fail"; box.textContent = "Validation failed: " + e.message; }
}

boot();
