/* CryptoDrishti. Vanilla JS, no framework, no build step, no external request. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null, scanId: null, findings: [], summary: null, scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  pollTimer: null, qdayTimer: null,
  shown: {},                // last rendered numbers, for tweening
  cells: new Map(),         // finding id -> treemap node, so the layout animates
};

const CLASS_LABEL = {
  "shor-broken": "Broken by Shor",
  "grover-weakened": "Weakened by Grover",
  "quantum-safe": "Quantum-safe",
  "hybrid": "Hybrid",
  "unknown": "Unresolved",
};

/* Fixed order. Never cycled, never reassigned by rank. */
const CLASS_ORDER = ["shor-broken", "grover-weakened", "unknown", "hybrid", "quantum-safe"];

const CLASS_FILL = {
  "shor-broken": "--f-broken", "grover-weakened": "--f-weakened",
  "unknown": "--f-unknown", "hybrid": "--f-hybrid", "quantum-safe": "--f-safe",
};
const SEV_VAR = {
  critical: "--sev-crit", high: "--sev-high", medium: "--sev-med", low: "--sev-low",
};
const SENSOR_LABEL = {
  source: "source", dependency: "deps", certificate: "certs",
  config: "config", binary: "binary", network: "network",
};

const severityOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;

/** Resolve a design token to its current value, so SVG follows the theme
 *  instead of freezing whatever colour was hardcoded. */
function tok(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Relative luminance of a hex colour, for choosing text on a filled cell. */
function luminance(hex) {
  const h = (hex || "").replace("#", "");
  if (h.length !== 6) return 0.5;
  const v = [0, 2, 4].map((i) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/* ── animation ─────────────────────────────────────────────────────── */

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function animateTo(el, key, value, decimals) {
  const from = state.shown[key];
  state.shown[key] = value;
  const fmt = (v) => (decimals ? v.toFixed(decimals) : Math.round(v).toLocaleString());
  if (reduceMotion || from === undefined || from === value) { el.textContent = fmt(value); return; }
  const start = performance.now(), dur = 460;
  (function step(now) {
    const t = Math.min(1, (now - start) / dur);
    el.textContent = fmt(from + (value - from) * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  })(performance.now());
}

/* ── boot ──────────────────────────────────────────────────────────── */

async function boot() {
  const pre = window.__PRELOAD__ || null;
  try {
    state.meta = pre?.meta || await api("/api/meta");
  } catch (err) { console.error("Failed to load metadata", err); return; }

  $("product-name").textContent = state.meta.product;
  $("ps-badge").textContent = state.meta.ps_id;
  $("foot-meta").textContent = `Problem statement ${state.meta.ps_id} · ${state.meta.ps_org}`;
  document.title = state.meta.product;

  const preset = $("target-preset");
  for (const t of state.meta.suggested_targets) {
    const o = document.createElement("option");
    o.value = t.path; o.textContent = t.label;
    preset.appendChild(o);
  }
  preset.addEventListener("change", () => {
    if (preset.value) $("scan-path").value = preset.value;
  });

  const profile = $("profile");
  for (const [key, label] of Object.entries(state.meta.profiles)) {
    const o = document.createElement("option");
    o.value = key; o.textContent = label;
    profile.appendChild(o);
  }

  const sens = $("sensitivity");
  for (const [key, years] of Object.entries(state.meta.sensitivities)) {
    const o = document.createElement("option");
    o.value = key; o.textContent = `${key} · ${years} yr`;
    sens.appendChild(o);
  }
  sens.addEventListener("change", () => {
    state.sensitivity = sens.value;
    renderMosca();
    scheduleQday(true);
  });

  state.qday = { ...state.meta.qday_default };
  const params = new URLSearchParams(location.search);
  const qp = Number(params.get("qday"));
  if (qp >= 2028 && qp <= 2050) state.qday.likely = qp;
  const sp = params.get("sensitivity");
  if (sp && state.meta.sensitivities[sp] !== undefined) state.sensitivity = sp;

  const slider = $("qday-likely");
  slider.addEventListener("input", () => {
    state.qday.likely = Number(slider.value);
    $("qday-out").textContent = slider.value;
    renderMosca();
    scheduleQday(false);
  });
  slider.addEventListener("change", () => scheduleQday(true));

  const classFilter = $("filter-class");
  for (const key of CLASS_ORDER) {
    const o = document.createElement("option");
    o.value = key; o.textContent = CLASS_LABEL[key];
    classFilter.appendChild(o);
  }

  buildSensors();
  initTheme();

  $("run-scan").addEventListener("click", startScan);
  $("filter-q").addEventListener("input", renderTable);
  $("filter-class").addEventListener("change", renderTable);
  $("filter-context").addEventListener("change", renderTable);
  $("btn-cbom").addEventListener("click", () => {
    if (state.scanId) location.href = `/api/scan/${state.scanId}/cbom?download=true`;
  });
  $("btn-report").addEventListener("click", () => {
    if (state.scanId) window.open(`/api/scan/${state.scanId}/report`, "_blank");
  });
  $("btn-validate").addEventListener("click", validateCbom);
  $("drawer-close").addEventListener("click", closeDrawer);
  $("scrim").addEventListener("click", closeDrawer);
  $("explain-toggle").addEventListener("click", toggleExplain);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  let rt = null;
  window.addEventListener("resize", () => {
    clearTimeout(rt);
    rt = setTimeout(() => { renderTreemap(); renderMosca(); }, 160);
  });

  let wantExplain = params.get("explain") === "1";
  if (!wantExplain) {
    try { wantExplain = localStorage.getItem("cd-explain") === "1"; } catch (_) {}
  }
  if (wantExplain) toggleExplain();

  sens.value = state.sensitivity;
  slider.value = state.qday.likely;
  $("qday-out").textContent = state.qday.likely;

  renderMosca();
  if (pre?.scan) {
    applyScan(pre.scan.scan.id, pre.scan);
    $("scan-path").value = pre.scan.scan.target_value || "";
    await reconcile();
  } else {
    await loadLatest();
  }
}

/* ── theme ─────────────────────────────────────────────────────────── */

function isDarkNow() {
  const set = document.documentElement.getAttribute("data-theme");
  if (set) return set === "dark";
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function initTheme() {
  // ?theme= wins, then the remembered choice, then the system setting.
  const forced = new URLSearchParams(location.search).get("theme");
  let saved = null;
  try { saved = localStorage.getItem("cd-theme"); } catch (_) {}
  const pick = (forced === "dark" || forced === "light") ? forced : saved;
  if (pick === "dark" || pick === "light") {
    document.documentElement.setAttribute("data-theme", pick);
  }
  syncThemeLabel();
  $("theme-toggle").addEventListener("click", () => {
    const next = isDarkNow() ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("cd-theme", next); } catch (_) {}
    syncThemeLabel();
    renderTreemap();
    renderMosca();
    renderDistributions();
  });
}

function syncThemeLabel() { $("theme-toggle").textContent = isDarkNow() ? "Light" : "Dark"; }

function toggleExplain() {
  const on = document.body.classList.toggle("explaining");
  $("explain-toggle").setAttribute("aria-pressed", String(on));
  try { localStorage.setItem("cd-explain", on ? "1" : "0"); } catch (_) {}
  renderTreemap();
}

/* ── scanning ──────────────────────────────────────────────────────── */

function buildSensors() {
  const host = $("sensors");
  host.textContent = "";
  for (const [key, label] of Object.entries(SENSOR_LABEL)) {
    const el = document.createElement("span");
    el.className = "sensor";
    el.dataset.sensor = key;
    el.dataset.state = "idle";
    el.append(document.createElement("i"), document.createTextNode(label));
    host.appendChild(el);
  }
}

function reflectSensors(phase) {
  const text = (phase || "").toLowerCase();
  const match = {
    source: "source code", dependency: "dependency", certificate: "certificate",
    config: "configuration", binary: "binaries", network: "endpoint",
  };
  const els = Array.from(document.querySelectorAll(".sensor"));
  let active = -1;
  els.forEach((el, i) => {
    if (match[el.dataset.sensor] && text.includes(match[el.dataset.sensor])) {
      el.dataset.state = "active"; active = i;
    }
  });
  if (active >= 0) els.forEach((el, i) => { if (i < active) el.dataset.state = "done"; });
}

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) return;
  const btn = $("run-scan");
  btn.disabled = true;
  $("scan-progress").hidden = false;
  for (const el of document.querySelectorAll(".sensor")) el.dataset.state = "idle";
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
  } catch (err) {
    setProgress(0, "Error: " + err.message);
    btn.disabled = false;
  }
}

function setProgress(pct, phase) {
  $("progress-fill").style.width = pct + "%";
  $("progress-phase").textContent = phase;
}

function poll(scanId) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    let job;
    try { job = await api(`/api/scan/${scanId}/status`); } catch (_) { return; }
    setProgress(job.progress || 0, job.phase || job.state);
    reflectSensors(job.phase);
    if (job.state === "done") {
      clearInterval(state.pollTimer);
      $("run-scan").disabled = false;
      for (const el of document.querySelectorAll(".sensor")) el.dataset.state = "done";
      await loadScan(scanId);
      setTimeout(() => { $("scan-progress").hidden = true; }, 1600);
    } else if (job.state === "error") {
      clearInterval(state.pollTimer);
      $("run-scan").disabled = false;
      setProgress(0, "Error: " + (job.error || "scan failed"));
      console.error(job.trace || job.error);
    }
  }, 400);
}

async function loadLatest() {
  try {
    const { scans } = await api("/api/scans");
    if (scans.length) {
      $("scan-path").value = scans[0].target_value;
      await loadScan(scans[0].id);
    }
  } catch (err) { console.error(err); }
}

function applyScan(scanId, data) {
  state.scanId = scanId;
  state.findings = data.findings;
  state.summary = data.summary;
  state.scanMeta = data.scan;
  state.cells.clear();
  $("treemap").textContent = "";
  $("validate-result").hidden = true;
  renderAll();
}

/** Keep the stored scoring in step with where the controls actually sit. */
async function reconcile() {
  const m = state.findings[0]?.extra?.mosca;
  if (!m) return;
  const wantZ = state.qday.likely - NOW_YEAR;
  const wantX = state.meta?.sensitivities?.[state.sensitivity];
  const stale = Math.abs(m.years_to_qday - wantZ) > 0.01
    || (wantX !== undefined && Math.abs(m.shelf_life - wantX) > 0.01);
  if (stale) await recomputeQday(false);
}

async function loadScan(scanId) {
  applyScan(scanId, await api(`/api/scan/${scanId}`));
  await reconcile();
}

/* ── Q-Day ─────────────────────────────────────────────────────────── */

function scheduleQday(persist) {
  if (!state.scanId) { renderMosca(); return; }
  clearTimeout(state.qdayTimer);
  state.qdayTimer = setTimeout(() => recomputeQday(persist), 140);
}

async function recomputeQday(persist) {
  if (!state.scanId) return;
  try {
    const data = await api("/api/qday", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: state.scanId, earliest: state.qday.earliest,
        likely: state.qday.likely, latest: state.qday.latest,
        sensitivity: state.sensitivity, persist: Boolean(persist),
      }),
    });
    const byId = new Map(state.findings.map((f) => [f.id, f]));
    for (const d of data.deltas) {
      const f = byId.get(d.id);
      if (!f) continue;
      f.risk_score = d.risk_score;
      f.quantum_class = d.quantum_class;
      f.exposure_years = d.exposure_years;
      f.extra = f.extra || {};
      if (d.mosca) f.extra.mosca = d.mosca;
      if (d.factors) f.extra.factors = d.factors;
    }
    const rank = new Map(data.order.map((id, i) => [id, i]));
    state.findings.sort((a, b) => (rank.get(a.id) ?? 0) - (rank.get(b.id) ?? 0));
    state.summary = data.summary;
    renderAll();
  } catch (err) { console.error("Q-Day recompute failed", err); }
}

/* ── render ────────────────────────────────────────────────────────── */

function renderAll() {
  renderStatement();
  renderFigures();
  renderTreemap();
  renderDistributions();
  renderMosca();
  renderTable();
}

function span(cls, text) {
  const s = document.createElement("span");
  if (cls) s.className = cls;
  if (text !== undefined) s.textContent = text;
  return s;
}

function renderStatement() {
  const s = state.summary;
  if (!s) return;
  $("posture-target").textContent = state.scanMeta?.target_label || "";

  const broken = s.by_class["shor-broken"] || 0;
  const safe = (s.by_class["quantum-safe"] || 0) + (s.by_class["hybrid"] || 0);

  const el = $("posture-verdict");
  el.textContent = "";
  el.append(
    span("n bad", `${s.quantum_vulnerable} of ${s.total}`),
    document.createTextNode(" cryptographic assets do not survive a quantum computer. "),
    span("n bad", String(broken)),
    document.createTextNode(" are broken outright by Shor's algorithm. ")
  );
  if (safe) {
    el.append(span("n good", String(safe)),
              document.createTextNode(" are already quantum-safe."));
  }
}

function renderFigures() {
  const s = state.summary;
  if (!s) return;
  const st = state.scanMeta?.stats || {};
  animateTo($("t-total"), "total", s.total);
  $("t-total-sub").textContent = `from ${(st.raw_hits || 0).toLocaleString()} detector hits`;
  animateTo($("t-vuln"), "vuln", s.quantum_vulnerable);
  $("t-vuln-sub").textContent = `${s.vulnerable_pct}% of the estate`;
  animateTo($("t-crit"), "crit", s.by_severity?.critical || 0);
  $("t-crit-sub").textContent = `${s.by_severity?.high || 0} high · 70 and above`;
  animateTo($("t-exposure"), "exp", s.max_exposure_years, 1);
}

/* ── treemap ───────────────────────────────────────────────────────── */

function worstRatio(row, side) {
  let sum = 0, mx = -Infinity, mn = Infinity;
  for (const n of row) { sum += n.area; if (n.area > mx) mx = n.area; if (n.area < mn) mn = n.area; }
  if (sum <= 0 || side <= 0) return Infinity;
  return Math.max((side * side * mx) / (sum * sum), (sum * sum) / (side * side * mn));
}

/** Squarified treemap (Bruls, Huizing & van Wijk). */
function squarify(nodes, x, y, w, h, out) {
  while (nodes.length) {
    if (nodes.length === 1) { out.push({ n: nodes[0], x, y, w, h }); return; }
    const side = Math.min(w, h);
    let row = [nodes[0]], best = worstRatio(row, side), i = 1;
    while (i < nodes.length) {
      const cand = row.concat([nodes[i]]);
      const r = worstRatio(cand, side);
      if (r > best) break;
      row = cand; best = r; i += 1;
    }
    const rowArea = row.reduce((s, n) => s + n.area, 0);
    if (w >= h) {
      const rw = rowArea / h;
      let cy = y;
      for (const n of row) { const nh = (n.area / rowArea) * h; out.push({ n, x, y: cy, w: rw, h: nh }); cy += nh; }
      x += rw; w -= rw;
    } else {
      const rh = rowArea / w;
      let cx = x;
      for (const n of row) { const nw = (n.area / rowArea) * w; out.push({ n, x: cx, y, w: nw, h: rh }); cx += nw; }
      y += rh; h -= rh;
    }
    nodes = nodes.slice(row.length);
    if (w <= 0.5 || h <= 0.5) return;
  }
}

function renderTreemap() {
  const host = $("treemap");
  const W = host.clientWidth, H = host.clientHeight;
  if (!W || !H || !state.findings.length) return;

  const fills = {};
  for (const k of CLASS_ORDER) fills[k] = tok(CLASS_FILL[k]);

  const items = state.findings
    .map((f) => ({ f, value: Math.max(1, f.occurrences) }))
    .sort((a, b) => b.value - a.value);
  const total = items.reduce((s, i) => s + i.value, 0);
  const scale = (W * H) / total;
  const nodes = items.map((i) => ({ f: i.f, value: i.value, area: i.value * scale }));

  const placed = [];
  squarify(nodes, 0, 0, W, H, placed);

  const GAP = 2, seen = new Set();
  for (const p of placed) {
    const f = p.n.f;
    seen.add(f.id);
    let cell = state.cells.get(f.id);
    if (!cell) {
      cell = document.createElement("div");
      cell.className = "cell";
      const lab = document.createElement("div");
      lab.className = "lab";
      lab.append(document.createElement("span"), document.createElement("em"));
      const sev = document.createElement("i");
      sev.className = "sev";
      cell.append(lab, sev);
      cell.addEventListener("click", () => openDrawer(f));
      cell.addEventListener("mousemove", (e) => showTip(e, f));
      cell.addEventListener("mouseleave", hideTip);
      host.appendChild(cell);
      state.cells.set(f.id, cell);
    }

    const fill = fills[f.quantum_class] || fills.unknown;
    cell.style.left = (p.x + GAP / 2) + "px";
    cell.style.top = (p.y + GAP / 2) + "px";
    cell.style.width = Math.max(0, p.w - GAP) + "px";
    cell.style.height = Math.max(0, p.h - GAP) + "px";
    cell.style.background = fill;
    const dark = luminance(fill) < 0.45;
    cell.classList.toggle("on-dark", dark);
    cell.classList.toggle("on-light", !dark);

    const sev = cell.querySelector("i.sev");
    sev.style.background = tok(SEV_VAR[severityOf(f.risk_score)]);
    sev.style.width = Math.max(6, f.risk_score) + "%";

    const lab = cell.querySelector(".lab");
    const big = p.w > 78 && p.h > 34;
    lab.style.display = big ? "flex" : "none";
    if (big) {
      lab.children[0].textContent = f.algorithm;
      lab.children[1].textContent = `${f.occurrences} uses`;
    }
  }
  for (const [id, cell] of state.cells) {
    if (!seen.has(id)) { cell.remove(); state.cells.delete(id); }
  }

  const key = $("seglegend");
  key.textContent = "";
  for (const k of CLASS_ORDER) {
    const n = state.summary?.by_class?.[k] || 0;
    if (!n) continue;
    const item = document.createElement("span");
    item.className = "k";
    const sw = span("sw");
    sw.style.background = fills[k];
    item.append(sw, span("kn", String(n)), document.createTextNode(" " + CLASS_LABEL[k]));
    key.appendChild(item);
  }
}

function showTip(e, f) {
  const tip = $("tip");
  tip.hidden = false;
  tip.textContent = "";
  tip.append(span("t", f.algorithm));
  const rows = [
    ["Class", CLASS_LABEL[f.quantum_class] || f.quantum_class],
    ["Call sites", f.occurrences.toLocaleString()],
    ["Risk", `${f.risk_score.toFixed(0)} · ${severityOf(f.risk_score)}`],
    ["Migrate to", f.recommendation?.target_name || "—"],
  ];
  for (const [k, v] of rows) {
    const r = document.createElement("div");
    r.className = "r";
    r.append(span(null, k), span(null, v));
    tip.appendChild(r);
  }
  const rect = tip.getBoundingClientRect(), pad = 14;
  let x = e.clientX + pad, y = e.clientY + pad;
  if (x + rect.width > window.innerWidth - 8) x = e.clientX - rect.width - pad;
  if (y + rect.height > window.innerHeight - 8) y = e.clientY - rect.height - pad;
  tip.style.left = Math.max(8, x) + "px";
  tip.style.top = Math.max(8, y) + "px";
}
function hideTip() { $("tip").hidden = true; }

/* ── distributions ─────────────────────────────────────────────────── */

function distRow(label, count, total, colour) {
  const row = document.createElement("div");
  row.className = "dist-row";
  const t = span("t");
  const fill = document.createElement("i");
  fill.style.width = Math.max(total ? (100 * count) / total : 0, count > 0 ? 2 : 0) + "%";
  fill.style.background = colour;
  t.appendChild(fill);
  row.append(span("l", label), t, span("c", count.toLocaleString()));
  return row;
}

function renderDistributions() {
  const s = state.summary;
  if (!s) return;
  const sd = $("sev-dist");
  sd.textContent = "";
  for (const k of ["critical", "high", "medium", "low"]) {
    sd.appendChild(distRow(k[0].toUpperCase() + k.slice(1),
      s.by_severity[k] || 0, s.total, tok(SEV_VAR[k])));
  }

  const by = {};
  for (const f of state.findings) by[f.scanner] = (by[f.scanner] || 0) + 1;
  const sc = $("scanner-dist");
  sc.textContent = "";
  const max = Math.max(1, ...Object.values(by));
  for (const [name, n] of Object.entries(by).sort((a, b) => b[1] - a[1])) {
    sc.appendChild(distRow(SENSOR_LABEL[name] || name, n, max, tok("--ink-3")));
  }

  const st = state.scanMeta?.stats || {};
  const bits = [];
  if (st.files_scanned) bits.push(`${st.files_scanned.toLocaleString()} source files`);
  const langs = Object.entries(st.languages || {}).slice(0, 4).map(([k, v]) => `${k} ${v.toLocaleString()}`);
  if (langs.length) bits.push(langs.join(" · "));
  if (st.binaries_scanned) bits.push(`${st.binaries_scanned} binaries`);
  if (st.certificate_files_scanned) bits.push(`${st.certificate_files_scanned} certificate files`);
  if (st.endpoints_probed) bits.push(`${st.endpoints_probed} live endpoints`);
  if (st.sensors_run) bits.push(`sensors: ${st.sensors_run.join(", ")}`);
  $("lang-summary").textContent = bits.join("   ·   ");
}

/* ── Mosca timeline ────────────────────────────────────────────────── */

const NS = "http://www.w3.org/2000/svg";
function sv(name, attrs, text) {
  const el = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}

function renderMosca() {
  const svg = $("mosca-svg");
  svg.textContent = "";

  let worst = null;
  for (const f of state.findings) {
    const m = f.extra?.mosca;
    if (m && (!worst || m.exposure_years > worst.exposure_years)) worst = m;
  }
  const X = state.meta?.sensitivities?.[state.sensitivity] ?? 10;
  const Y = worst ? worst.migration_years : 2.0;
  const Z = Math.max(0, state.qday.likely - NOW_YEAR);
  const exposure = Math.max(0, X + Y - Z);

  const W = 1000, L = 34, R = 176;
  const spanYears = Math.max(X + Y, Z, 8) * 1.06;
  const px = (y) => L + (y / spanYears) * (W - L - R);

  const ink2 = tok("--ink-2"), ink3 = tok("--ink-3");
  const hair = tok("--hair-2"), bad = tok("--i-broken");
  const cX = tok("--f-weakened");
  const AXIS = 128, MONO = "ui-monospace, Menlo, monospace";

  $("formula").textContent = `X ${X} + Y ${Y} − Z ${Z} = ${exposure.toFixed(1)} yr exposed`;

  if (exposure > 0) {
    svg.appendChild(sv("rect", { x: px(Z), y: 22, width: Math.max(0, px(X + Y) - px(Z)),
      height: AXIS - 22, fill: bad, opacity: "0.10" }));
  }

  svg.appendChild(sv("line", { x1: L, y1: AXIS, x2: W - R + 34, y2: AXIS,
    stroke: hair, "stroke-width": "1" }));

  const step = spanYears > 26 ? 8 : 4;
  for (let y = 0; y <= spanYears; y += step) {
    const x = px(y);
    if (x > W - R + 34) break;
    svg.appendChild(sv("text", { x, y: AXIS + 18, fill: ink3, "font-size": "11.5",
      "font-family": MONO, "text-anchor": "middle" }, String(NOW_YEAR + y)));
  }

  const LABEL_X = W - R + 12;
  const bar = (name, y, x1, x2, colour, value) => {
    svg.appendChild(sv("text", { x: L - 8, y: y + 12, fill: ink3, "font-size": "12",
      "font-family": MONO, "text-anchor": "end" }, name));
    svg.appendChild(sv("rect", { x: x1, y, width: Math.max(2, x2 - x1), height: 16,
      rx: 2, fill: colour }));
    svg.appendChild(sv("text", { x: LABEL_X, y: y + 12, fill: ink2, "font-size": "12",
      "font-family": MONO }, value));
  };
  bar("Y", 36, px(0), px(Y), ink2, `${Y} yr migration`);
  bar("X", 66, px(Y), px(Y + X), cX, `${X} yr secrecy`);

  svg.appendChild(sv("line", { x1: px(Z), y1: 18, x2: px(Z), y2: AXIS,
    stroke: bad, "stroke-width": "1.5", "stroke-dasharray": "5 4" }));
  const flip = px(Z) > W - R - 90;
  svg.appendChild(sv("text", { x: px(Z) + (flip ? -8 : 8), y: 15, fill: bad,
    "font-size": "12", "font-weight": "600", "font-family": MONO,
    "text-anchor": flip ? "end" : "start" }, `Q-Day ${state.qday.likely}`));

  if (exposure > 0) {
    const x1 = px(Z), x2 = px(X + Y);
    svg.appendChild(sv("line", { x1, y1: 100, x2, y2: 100, stroke: bad, "stroke-width": "1" }));
    for (const x of [x1, x2]) {
      svg.appendChild(sv("line", { x1: x, y1: 96, x2: x, y2: 104, stroke: bad, "stroke-width": "1" }));
    }
    svg.appendChild(sv("text", { x: (x1 + x2) / 2, y: 118, fill: bad, "font-size": "12",
      "font-weight": "600", "font-family": MONO, "text-anchor": "middle" },
      `${exposure.toFixed(1)} years exposed`));
  }

  const out = $("mosca-verdict");
  const p = state.findings.reduce((m, f) => Math.max(m, f.extra?.mosca?.probability_exposed || 0), 0);
  if (exposure > 0) {
    out.className = "readout";
    out.textContent = `The worst-exposed asset keeps data readable for ${exposure.toFixed(1)} years `
      + `after Q-Day` + (state.findings.length ? ` · P(exposed) = ${(p * 100).toFixed(0)}%` : "") + ".";
  } else {
    out.className = "readout ok";
    out.textContent = "Within tolerance at the current assumptions.";
  }
}

/* ── table ─────────────────────────────────────────────────────────── */

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

function renderTable() {
  const body = $("findings-body");
  body.textContent = "";
  const rows = visible();

  $("findings-hint").textContent = state.findings.length
    ? `${rows.length.toLocaleString()} of ${state.findings.length.toLocaleString()} assets · click a row for evidence, the score breakdown and the recommended replacement`
    : "Detector hits grouped into distinct assets, ranked by risk.";

  if (!rows.length) {
    const tr = document.createElement("tr");
    tr.className = "empty";
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = state.findings.length ? "Nothing matches those filters." : "No scan loaded.";
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }

  const fills = {};
  for (const k of CLASS_ORDER) fills[k] = tok(CLASS_FILL[k]);

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.dataset.sev = severityOf(f.risk_score);
    tr.tabIndex = 0;

    const risk = document.createElement("td");
    risk.className = "num risk";
    risk.textContent = f.risk_score.toFixed(0);

    const algo = document.createElement("td");
    algo.className = "algo"; algo.textContent = f.algorithm;

    const clsTd = document.createElement("td");
    const c = span("cls " + f.quantum_class);
    const dot = span("d");
    dot.style.background = fills[f.quantum_class] || fills.unknown;
    c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
    clsTd.appendChild(c);

    const title = document.createElement("td");
    title.textContent = f.title;

    const uses = document.createElement("td");
    uses.className = "num"; uses.textContent = f.occurrences.toLocaleString();

    const ctxTd = document.createElement("td");
    ctxTd.className = "ctx"; ctxTd.textContent = f.extra?.context || "production";

    const ev = f.evidence?.[0];
    const where = ev ? (ev.line ? `${ev.location}:${ev.line}` : ev.location) : "";
    const loc = document.createElement("td");
    loc.className = "loc"; loc.textContent = where; loc.title = where;

    const to = document.createElement("td");
    to.className = "to";
    to.textContent = f.recommendation?.target_name || "";
    to.title = to.textContent;

    tr.append(risk, algo, clsTd, title, uses, ctxTd, loc, to);
    tr.addEventListener("click", () => openDrawer(f));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
    });
    frag.appendChild(tr);
  }
  body.appendChild(frag);
}

/* ── drawer ────────────────────────────────────────────────────────── */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function sec(title) { const s = el("div", "d-sec"); s.appendChild(el("h3", null, title)); return s; }
function kv(pairs) {
  const dl = el("dl", "kv");
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, String(v)));
  }
  return dl;
}

function openDrawer(f) {
  hideTip();
  const d = $("drawer-body");
  d.textContent = "";

  const head = el("div", "d-head");
  head.appendChild(el("div", "d-title", f.algorithm));
  head.appendChild(el("div", "d-sub", f.title));
  const meta = el("div", "d-meta");
  const c = span("cls " + f.quantum_class);
  const dot = span("d");
  dot.style.background = tok(CLASS_FILL[f.quantum_class] || "--f-unknown");
  c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
  meta.appendChild(c);
  const sevSpan = el("span", null, `${severityOf(f.risk_score)} · ${f.risk_score.toFixed(1)}`);
  sevSpan.style.color = tok(SEV_VAR[severityOf(f.risk_score)]);
  meta.appendChild(sevSpan);
  meta.appendChild(el("span", null, f.extra?.context || "production"));
  head.appendChild(meta);
  d.appendChild(head);

  if (f.detail) d.appendChild(el("p", "said", f.detail));

  const m = f.extra?.mosca;
  if (m) {
    const s = sec("Mosca exposure");
    s.appendChild(kv([
      ["Secrecy required (X)", `${m.shelf_life} years`],
      ["Migration time (Y)", `${m.migration_years} years`],
      ["Years to Q-Day (Z)", `${m.years_to_qday} years`],
      ["Exposure (X+Y-Z)", `${m.exposure_years} years`],
      ["P(exposed)", `${(m.probability_exposed * 100).toFixed(0)}%`],
    ]));
    s.appendChild(el("p", "said", m.verdict));
    d.appendChild(s);
  }

  const fac = f.extra?.factors;
  if (fac) {
    const s = sec("Score composition - every term auditable");
    s.appendChild(kv(Object.entries(fac).map(([k, v]) => [
      k.replace(/_/g, " "), typeof v === "number" ? String(Number(v.toFixed(3))) : v,
    ])));
    d.appendChild(s);
  }

  const r = f.recommendation;
  if (r) {
    const s = sec("Recommended migration");
    s.appendChild(kv([
      ["Target", r.target_name], ["Effort", r.effort], ["Hybrid", r.hybrid ? "yes" : "no"],
      ["Size delta", (r.size_delta_bytes === null || r.size_delta_bytes === undefined)
        ? "" : `${r.size_delta_bytes > 0 ? "+" : ""}${r.size_delta_bytes} bytes`],
      ["Library support", r.library_support],
    ]));
    if (r.rationale) s.appendChild(el("p", "said", r.rationale));
    if (r.action) s.appendChild(el("p", "said act", r.action));
    if (r.size_note) s.appendChild(el("p", "said warn", r.size_note));
    if (r.agility_note) s.appendChild(el("p", "said", r.agility_note));
    d.appendChild(s);
  }

  const files = f.extra?.files || 1;
  const s = sec(`Evidence - ${f.occurrences} occurrence${f.occurrences === 1 ? "" : "s"} in ${files} file${files === 1 ? "" : "s"}`);
  const list = el("div", "evlist");
  for (const ev of (f.evidence || []).slice(0, 60)) {
    const item = el("div", "ev");
    item.appendChild(el("div", "l", ev.line ? `${ev.location}:${ev.line}` : ev.location));
    if (ev.snippet) item.appendChild(el("div", "s", ev.snippet));
    item.appendChild(el("div", "m",
      `${ev.technique} · confidence ${ev.confidence.toFixed(2)}${ev.symbol ? " · " + ev.symbol : ""}`));
    list.appendChild(item);
  }
  s.appendChild(list);
  d.appendChild(s);

  $("drawer").hidden = false;
  $("scrim").hidden = false;
}

function closeDrawer() { $("drawer").hidden = true; $("scrim").hidden = true; }

async function validateCbom() {
  if (!state.scanId) return;
  const box = $("validate-result");
  box.hidden = false;
  box.className = "validate";
  box.textContent = "Validating...";
  try {
    const r = await api(`/api/scan/${state.scanId}/cbom/validate`);
    box.className = "validate " + (r.valid ? "pass" : "fail");
    box.textContent = r.valid
      ? `PASS — ${r.components} cryptographic-asset components conform to ${r.spec}.`
      : `FAIL — ${r.problems.length} problem(s): ${r.problems.slice(0, 4).join("; ")}`;
  } catch (err) {
    box.className = "validate fail";
    box.textContent = "Validation failed: " + err.message;
  }
}

boot();
