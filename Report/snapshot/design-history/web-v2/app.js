/* CryptoDrishti console.
   Vanilla JS. No framework, no build step, no external request. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null,
  scanId: null,
  findings: [],
  summary: null,
  scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  pollTimer: null,
  qdayTimer: null,
  shownValues: {},          // for animated counters
};

const CLASS_LABEL = {
  "shor-broken": "Broken by Shor",
  "grover-weakened": "Weakened by Grover",
  "quantum-safe": "Quantum-safe",
  "hybrid": "Hybrid",
  "unknown": "Unresolved",
};

const CLASS_ORDER = ["shor-broken", "grover-weakened", "unknown", "hybrid", "quantum-safe"];

const CLASS_COLOR = {
  "shor-broken": "var(--crit)",
  "grover-weakened": "var(--med)",
  "quantum-safe": "var(--safe)",
  "hybrid": "var(--info)",
  "unknown": "var(--muted)",
};

const SEV_COLOR = {
  critical: "var(--crit)", high: "var(--high)",
  medium: "var(--med)", low: "var(--low)",
};

const SENSOR_LABEL = {
  source: "source", dependency: "deps", certificate: "certs",
  config: "config", binary: "binary", network: "network",
};

const severityOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/* ---------------------------------------------------------- animation */

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Tween a number in place, so a re-rank is felt rather than merely shown. */
function animateTo(el, key, value, decimals) {
  const from = state.shownValues[key];
  state.shownValues[key] = value;
  const fmt = (v) => (decimals ? v.toFixed(decimals) : Math.round(v).toLocaleString());

  if (reduceMotion || from === undefined || from === value) {
    el.textContent = fmt(value);
    return;
  }
  const start = performance.now();
  const dur = 420;
  function step(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = fmt(from + (value - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* --------------------------------------------------------------- boot */

async function boot() {
  try {
    state.meta = await api("/api/meta");
  } catch (err) {
    console.error("Failed to load metadata", err);
    return;
  }

  $("product-name").textContent = state.meta.product;
  $("product-tagline").textContent = state.meta.tagline;
  $("ps-badge").textContent = state.meta.ps_id;
  $("foot-meta").textContent = `Problem statement ${state.meta.ps_id} · ${state.meta.ps_org}`;
  document.title = `${state.meta.product} — Cryptographic Discovery & Quantum Risk`;

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
    o.value = key; o.textContent = `${key} — ${years} year confidentiality`;
    if (key === state.sensitivity) o.selected = true;
    sens.appendChild(o);
  }
  sens.addEventListener("change", () => {
    state.sensitivity = sens.value;
    renderMosca();
    scheduleQdayRecompute(true);
  });

  state.qday = { ...state.meta.qday_default };
  const slider = $("qday-likely");
  slider.value = state.qday.likely;
  $("qday-out").textContent = state.qday.likely;
  slider.addEventListener("input", () => {
    state.qday.likely = Number(slider.value);
    $("qday-out").textContent = slider.value;
    renderMosca();
    scheduleQdayRecompute(false);
  });
  slider.addEventListener("change", () => scheduleQdayRecompute(true));

  const classFilter = $("filter-class");
  for (const key of CLASS_ORDER) {
    const o = document.createElement("option");
    o.value = key; o.textContent = CLASS_LABEL[key];
    classFilter.appendChild(o);
  }

  buildSensorStrip();

  $("run-scan").addEventListener("click", startScan);
  $("filter-q").addEventListener("input", renderTable);
  $("filter-class").addEventListener("change", renderTable);
  $("filter-context").addEventListener("change", renderTable);
  $("btn-cbom").addEventListener("click", downloadCbom);
  $("btn-report").addEventListener("click", openReport);
  $("btn-validate").addEventListener("click", validateCbom);
  $("drawer-close").addEventListener("click", closeDrawer);
  $("scrim").addEventListener("click", closeDrawer);
  $("explain-toggle").addEventListener("click", toggleExplain);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });

  try {
    if (localStorage.getItem("cd-explain") === "1") toggleExplain();
  } catch (_) { /* storage can be unavailable; the toggle still works */ }

  renderMosca();
  await loadMostRecentScan();
}

function toggleExplain() {
  const on = document.body.classList.toggle("explaining");
  $("explain-toggle").setAttribute("aria-pressed", String(on));
  try { localStorage.setItem("cd-explain", on ? "1" : "0"); } catch (_) {}
}

async function loadMostRecentScan() {
  try {
    const { scans } = await api("/api/scans");
    if (scans.length) {
      $("scan-path").value = scans[0].target_value;
      await loadScan(scans[0].id);
    }
  } catch (err) {
    console.error("Failed to list scans", err);
  }
}

/* --------------------------------------------------------------- scan */

function buildSensorStrip() {
  const host = $("sensors");
  host.textContent = "";
  for (const [key, label] of Object.entries(SENSOR_LABEL)) {
    const el = document.createElement("span");
    el.className = "sensor";
    el.dataset.sensor = key;
    el.dataset.state = "idle";
    const led = document.createElement("span");
    led.className = "led";
    el.append(led, document.createTextNode(label));
    host.appendChild(el);
  }
}

/** Light the sensor whose name appears in the phase text the server reports. */
function reflectSensors(phase) {
  const text = (phase || "").toLowerCase();
  const match = {
    source: "source code", dependency: "dependency", certificate: "certificate",
    config: "configuration", binary: "binaries", network: "endpoint",
  };
  let activeFound = false;
  const els = Array.from(document.querySelectorAll(".sensor"));
  for (const el of els) {
    const needle = match[el.dataset.sensor];
    if (needle && text.includes(needle)) {
      el.dataset.state = "active";
      activeFound = true;
    }
  }
  // Everything before the active sensor has finished.
  if (activeFound) {
    let seenActive = false;
    for (const el of els) {
      if (el.dataset.state === "active") { seenActive = true; continue; }
      if (!seenActive) el.dataset.state = "done";
    }
  }
}

function markAllSensors(stateName) {
  for (const el of document.querySelectorAll(".sensor")) el.dataset.state = stateName;
}

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) return;

  const btn = $("run-scan");
  btn.disabled = true;
  $("scan-progress").hidden = false;
  markAllSensors("idle");
  setProgress(2, "Queued");

  try {
    const { scan_id } = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path,
        label: ($("target-preset").value
          ? $("target-preset").selectedOptions[0]?.textContent : "") || "",
        profile: $("profile").value,
        endpoints: $("scan-endpoints").value.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    });
    pollScan(scan_id);
  } catch (err) {
    setProgress(0, "Error: " + err.message);
    btn.disabled = false;
  }
}

function setProgress(pct, phase) {
  $("progress-fill").style.width = pct + "%";
  $("progress-phase").textContent = phase;
}

function pollScan(scanId) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    let job;
    try { job = await api(`/api/scan/${scanId}/status`); } catch (_) { return; }

    setProgress(job.progress || 0, job.phase || job.state);
    reflectSensors(job.phase);

    if (job.state === "done") {
      clearInterval(state.pollTimer);
      $("run-scan").disabled = false;
      markAllSensors("done");
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

async function loadScan(scanId) {
  const data = await api(`/api/scan/${scanId}`);
  state.scanId = scanId;
  state.findings = data.findings;
  state.summary = data.summary;
  state.scanMeta = data.scan;
  $("validate-result").hidden = true;
  renderAll();

  // A stored scan carries whatever Q-Day it was last scored under, which may
  // not be where the slider sits. Re-score once at the current control values
  // so the number under the slider and the numbers on screen always agree --
  // otherwise the console can open showing 2034 with scores computed at 2037.
  const storedZ = state.findings[0]?.extra?.mosca?.years_to_qday;
  const shownZ = state.qday.likely - NOW_YEAR;
  if (storedZ !== undefined && Math.abs(storedZ - shownZ) > 0.01) {
    await recomputeQday(false);
  }
}

/* -------------------------------------------------------------- Q-Day */

function scheduleQdayRecompute(persist) {
  if (!state.scanId) { renderMosca(); return; }
  clearTimeout(state.qdayTimer);
  state.qdayTimer = setTimeout(() => recomputeQday(persist), 140);
}

async function recomputeQday(persist) {
  if (!state.scanId) return;
  try {
    const data = await api("/api/qday", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: state.scanId,
        earliest: state.qday.earliest,
        likely: state.qday.likely,
        latest: state.qday.latest,
        sensitivity: state.sensitivity,
        persist: Boolean(persist),
      }),
    });

    // Merge only what changed. Evidence and recommendations are unaffected by
    // a Q-Day change, and re-sending them on every tick is what made this slow.
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
  } catch (err) {
    console.error("Q-Day recompute failed", err);
  }
}

/* ------------------------------------------------------------- render */

function renderAll() {
  renderPosture();
  renderTiles();
  renderDistributions();
  renderMosca();
  renderTable();
}

/* ---- posture ---- */

function renderPosture() {
  const s = state.summary;
  if (!s) return;

  $("posture-target").textContent = state.scanMeta?.target_label || "";

  const broken = s.by_class["shor-broken"] || 0;
  const safe = (s.by_class["quantum-safe"] || 0) + (s.by_class["hybrid"] || 0);
  const verdict = $("posture-verdict");
  verdict.textContent = "";

  const frag = document.createDocumentFragment();
  const b = document.createElement("b");
  b.textContent = `${s.quantum_vulnerable} of ${s.total}`;
  frag.append(b, document.createTextNode(
    " cryptographic assets in this estate do not survive a quantum computer. "));
  const strong = document.createElement("b");
  strong.textContent = String(broken);
  frag.append(strong, document.createTextNode(
    " are broken outright by Shor's algorithm — no key size helps. "));
  if (safe) {
    const ok = document.createElement("span");
    ok.className = "ok";
    ok.textContent = `${safe} are already quantum-safe.`;
    frag.append(ok);
  }
  verdict.appendChild(frag);

  const bar = $("segbar");
  const legend = $("seglegend");
  bar.textContent = "";
  legend.textContent = "";
  for (const key of CLASS_ORDER) {
    const n = s.by_class[key] || 0;
    if (!n) continue;
    const seg = document.createElement("span");
    seg.style.width = (100 * n / s.total) + "%";
    seg.style.background = CLASS_COLOR[key];
    seg.title = `${CLASS_LABEL[key]}: ${n}`;
    bar.appendChild(seg);

    const item = document.createElement("span");
    item.className = "item";
    const sw = document.createElement("span");
    sw.className = "swatch";
    sw.style.background = CLASS_COLOR[key];
    const num = document.createElement("span");
    num.className = "n";
    num.textContent = n;
    item.append(sw, num, document.createTextNode(" " + CLASS_LABEL[key]));
    legend.appendChild(item);
  }
}

/* ---- tiles ---- */

function renderTiles() {
  const s = state.summary;
  if (!s) return;
  const stats = state.scanMeta?.stats || {};

  animateTo($("t-total"), "total", s.total);
  $("t-total-sub").textContent =
    `grouped from ${(stats.raw_hits || 0).toLocaleString()} detector hits`;

  animateTo($("t-vuln"), "vuln", s.quantum_vulnerable);
  $("t-vuln-sub").textContent = `${s.vulnerable_pct}% of the estate`;

  animateTo($("t-crit"), "crit", s.by_severity?.critical || 0);
  $("t-crit-sub").textContent =
    `${(s.by_severity?.high || 0).toLocaleString()} high · score 70+ is critical`;

  animateTo($("t-exposure"), "exp", s.max_exposure_years, 1);
}

/* ---- distributions ---- */

function distRow(label, count, total, color) {
  const pct = total ? (100 * count) / total : 0;
  const row = document.createElement("div");
  row.className = "dist-row";
  const l = document.createElement("span"); l.className = "label"; l.textContent = label;
  const track = document.createElement("span"); track.className = "track";
  const fill = document.createElement("span"); fill.className = "fill";
  fill.style.width = Math.max(pct, count > 0 ? 1.5 : 0) + "%";
  fill.style.background = color;
  track.appendChild(fill);
  const c = document.createElement("span"); c.className = "count";
  c.textContent = count.toLocaleString();
  row.append(l, track, c);
  return row;
}

function renderDistributions() {
  const s = state.summary;
  if (!s) return;

  const sd = $("sev-dist");
  sd.textContent = "";
  for (const key of ["critical", "high", "medium", "low"]) {
    sd.appendChild(distRow(key[0].toUpperCase() + key.slice(1),
      s.by_severity[key] || 0, s.total, SEV_COLOR[key]));
  }

  const byScanner = {};
  for (const f of state.findings) {
    byScanner[f.scanner] = (byScanner[f.scanner] || 0) + 1;
  }
  const sc = $("scanner-dist");
  sc.textContent = "";
  const maxScanner = Math.max(1, ...Object.values(byScanner));
  for (const [name, n] of Object.entries(byScanner).sort((a, b) => b[1] - a[1])) {
    sc.appendChild(distRow(SENSOR_LABEL[name] || name, n, maxScanner, "var(--accent)"));
  }

  const stats = state.scanMeta?.stats || {};
  const langs = stats.languages || {};
  const bits = [];
  if (stats.files_scanned) bits.push(`${stats.files_scanned.toLocaleString()} source files`);
  const parts = Object.entries(langs).slice(0, 5).map(([k, v]) => `${k} ${v.toLocaleString()}`);
  if (parts.length) bits.push(parts.join(" · "));
  if (stats.binaries_scanned) bits.push(`${stats.binaries_scanned} binaries`);
  if (stats.certificate_files_scanned) bits.push(`${stats.certificate_files_scanned} certificate files`);
  if (stats.endpoints_probed) bits.push(`${stats.endpoints_probed} live endpoints`);
  if (stats.sensors_run) bits.push(`sensors: ${stats.sensors_run.join(", ")}`);
  $("lang-summary").textContent = bits.join(" · ");
}

/* ---- Mosca timeline ---- */

const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(name, attrs, text) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}

function renderMosca() {
  const svg = $("mosca-svg");
  svg.textContent = "";

  const X = (state.meta?.sensitivities || {})[state.sensitivity] ?? 10;
  const Y = 2.0;
  const Z = Math.max(0, state.qday.likely - NOW_YEAR);
  const exposure = Math.max(0, X + Y - Z);

  const W = 760, H = 178;
  const L = 58, R = 30, spanYears = Math.max(X + Y, Z, 8) * 1.14;
  const px = (yrs) => L + (yrs / spanYears) * (W - L - R);

  $("formula").textContent = `X ${X} + Y ${Y} − Z ${Z} = ${exposure.toFixed(1)} yrs`;

  if (exposure > 0) {
    svg.appendChild(svgEl("rect", {
      x: px(Z), y: 20, width: Math.max(0, px(X + Y) - px(Z)), height: 108,
      fill: "var(--crit)", opacity: "0.13",
    }));
  }

  svg.appendChild(svgEl("line", {
    x1: L, y1: 128, x2: W - R, y2: 128, stroke: "var(--line)", "stroke-width": "1",
  }));

  const tickEvery = spanYears > 26 ? 8 : 4;
  for (let yr = 0; yr <= spanYears; yr += tickEvery) {
    const x = px(yr);
    if (x > W - R) break;
    svg.appendChild(svgEl("line", {
      x1: x, y1: 128, x2: x, y2: 133, stroke: "var(--line)", "stroke-width": "1",
    }));
    svg.appendChild(svgEl("text", {
      x, y: 147, fill: "var(--faint)", "font-size": "10.5",
      "font-family": "var(--mono)", "text-anchor": "middle",
    }, String(NOW_YEAR + yr)));
  }

  const bar = (label, y, x1, x2, colour, valueText) => {
    svg.appendChild(svgEl("text", {
      x: L - 10, y: y + 11, fill: "var(--muted)", "font-size": "11",
      "font-family": "var(--mono)", "text-anchor": "end",
    }, label));
    svg.appendChild(svgEl("rect", {
      x: x1, y, width: Math.max(2, x2 - x1), height: 15, rx: 2, fill: colour,
    }));
    svg.appendChild(svgEl("text", {
      x: Math.min(x2 + 8, W - 4), y: y + 11, fill: "var(--ink-2)", "font-size": "11",
      "font-family": "var(--mono)", "text-anchor": x2 + 8 > W - 90 ? "end" : "start",
    }, valueText));
  };

  bar("Y", 32, px(0), px(Y), "var(--accent)", `${Y} yr migration`);
  bar("X", 58, px(Y), px(Y + X), "var(--high)", `${X} yr confidentiality`);

  svg.appendChild(svgEl("line", {
    x1: px(Z), y1: 18, x2: px(Z), y2: 128,
    stroke: "var(--crit)", "stroke-width": "2", "stroke-dasharray": "5 4",
  }));
  svg.appendChild(svgEl("circle", { cx: px(Z), cy: 18, r: 4, fill: "var(--crit)" }));
  const anchorEnd = px(Z) > W * 0.7;
  svg.appendChild(svgEl("text", {
    x: px(Z) + (anchorEnd ? -9 : 9), y: 14,
    fill: "var(--crit)", "font-size": "11", "font-weight": "600",
    "font-family": "var(--mono)", "text-anchor": anchorEnd ? "end" : "start",
  }, `Q-Day ${state.qday.likely}`));

  if (exposure > 0) {
    const x1 = px(Z), x2 = px(X + Y), mid = (x1 + x2) / 2;
    svg.appendChild(svgEl("line", {
      x1, y1: 104, x2, y2: 104, stroke: "var(--crit)", "stroke-width": "1.5",
    }));
    for (const x of [x1, x2]) {
      svg.appendChild(svgEl("line", {
        x1: x, y1: 99, x2: x, y2: 109, stroke: "var(--crit)", "stroke-width": "1.5",
      }));
    }
    svg.appendChild(svgEl("text", {
      x: mid, y: 122, fill: "var(--crit)", "font-size": "11", "font-weight": "600",
      "font-family": "var(--mono)", "text-anchor": "middle",
    }, `${exposure.toFixed(1)} years exposed`));
  }

  const cap = $("mosca-verdict");
  const worst = state.findings.reduce(
    (m, f) => Math.max(m, f.extra?.mosca?.probability_exposed || 0), 0);
  if (exposure > 0) {
    cap.className = "mosca-verdict";
    cap.textContent =
      `Data sealed today stays readable for ${exposure.toFixed(1)} years after Q-Day`
      + (state.findings.length ? ` · P(exposed) = ${(worst * 100).toFixed(0)}%` : "");
  } else {
    cap.className = "mosca-verdict ok";
    cap.textContent = "Within tolerance at the current assumptions.";
  }
}

/* ---- table ---- */

function visibleFindings() {
  const q = $("filter-q").value.trim().toLowerCase();
  const cls = $("filter-class").value;
  const ctx = $("filter-context").value;

  return state.findings.filter((f) => {
    if (cls && f.quantum_class !== cls) return false;
    if (ctx && (f.extra?.context || "production") !== ctx) return false;
    if (q) {
      const hay = `${f.algorithm} ${f.title} ${f.primary_location}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderTable() {
  const body = $("findings-body");
  body.textContent = "";
  const rows = visibleFindings();

  $("findings-hint").textContent = state.findings.length
    ? `${rows.length.toLocaleString()} of ${state.findings.length.toLocaleString()} assets shown · click a row for evidence and remediation`
    : "Detector hits are grouped into distinct assets.";

  if (!rows.length) {
    const tr = document.createElement("tr");
    tr.className = "empty";
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = state.findings.length
      ? "No assets match the current filters."
      : "No scan loaded. Choose a target above and run a scan.";
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const sev = severityOf(f.risk_score);
    const tr = document.createElement("tr");
    tr.dataset.sev = sev;
    tr.tabIndex = 0;

    const tdRisk = document.createElement("td");
    tdRisk.className = "num risk";
    const wrap = document.createElement("span"); wrap.className = "riskwrap";
    const val = document.createElement("span"); val.className = "riskval";
    val.textContent = f.risk_score.toFixed(0);
    const rbar = document.createElement("span"); rbar.className = "riskbar";
    const rfill = document.createElement("i");
    rfill.style.width = Math.max(2, f.risk_score) + "%";
    rfill.style.background = SEV_COLOR[sev];
    rbar.appendChild(rfill);
    wrap.append(val, rbar);
    tdRisk.appendChild(wrap);

    const tdAlgo = document.createElement("td");
    tdAlgo.className = "algo";
    tdAlgo.textContent = f.algorithm;

    const tdClass = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "pill " + f.quantum_class;
    pill.textContent = CLASS_LABEL[f.quantum_class] || f.quantum_class;
    tdClass.appendChild(pill);

    const tdTitle = document.createElement("td");
    tdTitle.textContent = f.title;

    const tdUses = document.createElement("td");
    tdUses.className = "num";
    tdUses.textContent = f.occurrences.toLocaleString();

    const tdCtx = document.createElement("td");
    const context = f.extra?.context || "production";
    const ctxSpan = document.createElement("span");
    ctxSpan.className = "ctx " + context;
    ctxSpan.textContent = context;
    tdCtx.appendChild(ctxSpan);

    const ev = f.evidence?.[0];
    const loc = ev ? (ev.line ? `${ev.location}:${ev.line}` : ev.location) : "";
    const tdLoc = document.createElement("td");
    tdLoc.className = "loc";
    tdLoc.textContent = loc;
    tdLoc.title = loc;

    const tdTarget = document.createElement("td");
    tdTarget.className = "target";
    const target = f.recommendation?.target_name || "";
    tdTarget.textContent = target;
    tdTarget.title = target;

    tr.append(tdRisk, tdAlgo, tdClass, tdTitle, tdUses, tdCtx, tdLoc, tdTarget);
    tr.addEventListener("click", () => openDrawer(f));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
    });
    frag.appendChild(tr);
  }
  body.appendChild(frag);
}

/* ------------------------------------------------------------- drawer */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function section(title) {
  const s = el("div", "d-section");
  s.appendChild(el("h3", null, title));
  return s;
}

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
  const d = $("drawer-body");
  d.textContent = "";

  const head = el("div", "d-head");
  head.appendChild(el("div", "d-title", f.algorithm));
  head.appendChild(el("div", "d-sub", f.title));
  const badges = el("div", "d-badges");
  badges.appendChild(el("span", "pill " + f.quantum_class,
    CLASS_LABEL[f.quantum_class] || f.quantum_class));
  const sev = severityOf(f.risk_score);
  const sevPill = el("span", "pill", `${sev} · ${f.risk_score.toFixed(1)}`);
  sevPill.style.color = SEV_COLOR[sev];
  sevPill.style.borderColor = "var(--line)";
  badges.appendChild(sevPill);
  badges.appendChild(el("span", "pill unknown", f.extra?.context || "production"));
  head.appendChild(badges);
  d.appendChild(head);

  if (f.detail) d.appendChild(el("div", "d-note", f.detail));

  const m = f.extra?.mosca;
  if (m) {
    const s = section("Mosca exposure");
    s.appendChild(kv([
      ["Confidentiality (X)", `${m.shelf_life} years`],
      ["Migration time (Y)", `${m.migration_years} years`],
      ["Years to Q-Day (Z)", `${m.years_to_qday} years`],
      ["Exposure (X+Y−Z)", `${m.exposure_years} years`],
      ["P(exposed)", `${(m.probability_exposed * 100).toFixed(0)}%`],
    ]));
    s.appendChild(el("div", "d-note", m.verdict));
    d.appendChild(s);
  }

  const fac = f.extra?.factors;
  if (fac) {
    const s = section("Score composition — every term is auditable");
    s.appendChild(kv(Object.entries(fac).map(([k, v]) => [
      k.replace(/_/g, " "),
      typeof v === "number" ? String(Number(v.toFixed(3))) : v,
    ])));
    d.appendChild(s);
  }

  const r = f.recommendation;
  if (r) {
    const s = section("Recommended migration");
    s.appendChild(kv([
      ["Target", r.target_name],
      ["Effort", r.effort],
      ["Hybrid", r.hybrid ? "yes" : "no"],
      ["Size delta", (r.size_delta_bytes === null || r.size_delta_bytes === undefined)
        ? "" : `${r.size_delta_bytes > 0 ? "+" : ""}${r.size_delta_bytes} bytes`],
      ["Library support", r.library_support],
    ]));
    if (r.rationale) s.appendChild(el("div", "d-note", r.rationale));
    if (r.action) s.appendChild(el("div", "d-note good", r.action));
    if (r.size_note) s.appendChild(el("div", "d-note warn", r.size_note));
    if (r.agility_note) s.appendChild(el("div", "d-note", r.agility_note));
    d.appendChild(s);
  }

  const files = f.extra?.files || 1;
  const s = section(
    `Evidence — ${f.occurrences} occurrence${f.occurrences === 1 ? "" : "s"} across ${files} file${files === 1 ? "" : "s"}`);
  const list = el("div", "evlist");
  for (const ev of (f.evidence || []).slice(0, 60)) {
    const item = el("div", "ev");
    item.appendChild(el("div", "evloc", ev.line ? `${ev.location}:${ev.line}` : ev.location));
    if (ev.snippet) item.appendChild(el("div", "evsnip", ev.snippet));
    item.appendChild(el("div", "evtech",
      `${ev.technique} · confidence ${ev.confidence.toFixed(2)}${ev.symbol ? " · " + ev.symbol : ""}`));
    list.appendChild(item);
  }
  s.appendChild(list);
  d.appendChild(s);

  $("drawer").hidden = false;
  $("scrim").hidden = false;
}

function closeDrawer() {
  $("drawer").hidden = true;
  $("scrim").hidden = true;
}

/* --------------------------------------------------------------- CBOM */

function openReport() {
  if (!state.scanId) return;
  window.open(`/api/scan/${state.scanId}/report`, "_blank");
}

function downloadCbom() {
  if (!state.scanId) return;
  window.location.href = `/api/scan/${state.scanId}/cbom?download=true`;
}

async function validateCbom() {
  if (!state.scanId) return;
  const box = $("validate-result");
  box.hidden = false;
  box.className = "validate";
  box.textContent = "Validating…";
  try {
    const r = await api(`/api/scan/${state.scanId}/cbom/validate`);
    box.className = "validate " + (r.valid ? "pass" : "fail");
    box.textContent = r.valid
      ? `PASS — ${r.components} cryptographic-asset components conform to ${r.spec}. ${r.note}`
      : `FAIL — ${r.problems.length} problem(s): ${r.problems.slice(0, 4).join("; ")}`;
  } catch (err) {
    box.className = "validate fail";
    box.textContent = "Validation failed: " + err.message;
  }
}

boot();
