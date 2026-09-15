/* CryptoDrishti. Vanilla JS, no framework, no build step, no external request. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null, scanId: null, findings: [], summary: null, scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  pollTimer: null, qdayTimer: null, shown: {}, dialDrawn: false,
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
const SENSOR_LABEL = {
  source: "source", dependency: "dependency", certificate: "certificate",
  config: "config", binary: "binary", network: "network",
};

const sevOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;
/* Resolving a custom property allocates a live CSSStyleDeclaration and forces a
   style read. renderDial calls this once per spoke and renderTable once per row,
   so the value is memoised and the cache dropped whenever the theme changes. */
const _tokCache = new Map();
const tok = (n) => {
  let v = _tokCache.get(n);
  if (v === undefined) {
    v = getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    _tokCache.set(n, v);
  }
  return v;
};
const dropTokenCache = () => _tokCache.clear();
/* ?still=1 renders the finished state with no entrance animation — for
   screenshots, print, and the fallback recording. */
const stillMode = new URLSearchParams(location.search).get("still") === "1";
const reduceMotion =
  stillMode || window.matchMedia("(prefers-reduced-motion: reduce)").matches;

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let d = res.statusText;
    try { d = (await res.json()).detail || d; } catch (_) {}
    throw new Error(d);
  }
  return res.json();
}

const _tweens = new Map();
function animateTo(el, key, value, dec) {
  // Dragging the slider fires these faster than a tween completes. Without
  // cancelling, several loops write the same element and the digits oscillate.
  const running = _tweens.get(key);
  if (running !== undefined) cancelAnimationFrame(running);
  const from = state.shown[key];
  state.shown[key] = value;
  const fmt = (v) => (dec ? v.toFixed(dec) : Math.round(v).toLocaleString());
  if (reduceMotion || from === undefined || from === value) {
    _tweens.delete(key); el.textContent = fmt(value); return;
  }
  const t0 = performance.now(), dur = 460;
  const step = (now) => {
    const t = Math.min(1, (now - t0) / dur);
    el.textContent = fmt(from + (value - from) * (1 - Math.pow(1 - t, 3)));
    if (t < 1) _tweens.set(key, requestAnimationFrame(step));
    else _tweens.delete(key);
  };
  _tweens.set(key, requestAnimationFrame(step));
}

/* ═══ boot ══════════════════════════════════════════════════════════ */

async function boot() {
  const pre = window.__PRELOAD__ || null;
  try { state.meta = pre?.meta || await api("/api/meta"); }
  catch (e) { console.error(e); return; }

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
  const p = new URLSearchParams(location.search);
  const qp = Number(p.get("qday"));
  if (qp >= 2028 && qp <= 2050) setQday(qp);
  const sp = p.get("sensitivity");
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

  buildSensors(); initTheme();

  $("run-scan").addEventListener("click", startScan);
  let filterTimer = null;
  $("filter-q").addEventListener("input", () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(renderTable, 90);   // rebuilding every row per keystroke drops the scroll position
  });
  $("filter-class").addEventListener("change", renderTable);
  $("filter-context").addEventListener("change", renderTable);
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
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  let rt = null;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(renderMosca, 160); });

  let wantExplain = p.get("explain") === "1";
  if (!wantExplain) { try { wantExplain = localStorage.getItem("cd-explain") === "1"; } catch (_) {} }
  if (wantExplain) toggleExplain();

  renderMosca();
  if (pre?.scan) {
    applyScan(pre.scan.scan.id, pre.scan);
    $("scan-path").value = pre.scan.scan.target_value || "";
    await reconcile();
  } else { await loadLatest(); }
}

/* The slider spans 2028-2050 but the distribution's bounds were frozen at the
   server defaults, so any value outside them made /api/qday reject the request
   and the page silently kept stale numbers. Keep the window around `likely`. */
function setQday(likely) {
  const d = state.meta?.qday_default || { earliest: 2030, latest: 2044 };
  state.qday.likely = likely;
  state.qday.earliest = Math.min(d.earliest, likely - 2);
  state.qday.latest = Math.max(d.latest, likely + 2);
}

const isDark = () => {
  const s = document.documentElement.getAttribute("data-theme");
  return s ? s === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
};

function initTheme() {
  // The attribute is already resolved by the inline script in <head>; this only
  // wires the control up to it.
  const syncTheme = () => {
    const dark = isDark();
    $("theme-toggle").textContent = dark ? "Light" : "Dark";
    $("theme-toggle").setAttribute("aria-pressed", String(dark));
    dropTokenCache();
    renderDial(); renderMosca(); renderTable();
    if (_openFinding) openDrawer(_openFinding, true);
  };
  $("theme-toggle").addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("cd-theme", next); } catch (_) {}
    syncTheme();
  });
  // Follow the OS when the user has not pinned a theme, so JS-painted colour
  // (every SVG fill) does not freeze at whatever it resolved to on load.
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const onSystem = () => { if (!document.documentElement.hasAttribute("data-theme")) syncTheme(); };
  mq.addEventListener ? mq.addEventListener("change", onSystem) : mq.addListener(onSystem);
}

function toggleExplain() {
  const on = document.body.classList.toggle("explaining");
  $("explain-toggle").setAttribute("aria-pressed", String(on));
  try { localStorage.setItem("cd-explain", on ? "1" : "0"); } catch (_) {}
}

/* ═══ scanning ══════════════════════════════════════════════════════ */

function buildSensors() {
  const host = $("sensors"); host.textContent = "";
  for (const [k, l] of Object.entries(SENSOR_LABEL)) {
    const el = document.createElement("span");
    el.className = "sensor"; el.dataset.sensor = k; el.dataset.state = "idle";
    el.append(document.createElement("i"), document.createTextNode(l));
    host.appendChild(el);
  }
}

function reflectSensors(phase) {
  const t = (phase || "").toLowerCase();
  const m = { source: "source code", dependency: "dependency", certificate: "certificate",
              config: "configuration", binary: "binaries", network: "endpoint" };
  const els = [...document.querySelectorAll(".sensor")];
  let active = -1;
  els.forEach((el, i) => {
    if (m[el.dataset.sensor] && t.includes(m[el.dataset.sensor])) { el.dataset.state = "active"; active = i; }
  });
  if (active >= 0) els.forEach((el, i) => { if (i < active) el.dataset.state = "done"; });
}

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) return;
  $("run-scan").disabled = true;
  clearTimeout(state.hideTimer);   // a pending hide from the last scan would blank this one
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
  } catch (e) { setProgress(0, "Error: " + e.message); $("run-scan").disabled = false; }
}

function setProgress(pct, phase) {
  $("progress-fill").style.width = pct + "%";
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
      for (const el of document.querySelectorAll(".sensor")) el.dataset.state = "done";
      state.dialDrawn = false;
      await loadScan(id);
      state.hideTimer = setTimeout(() => { $("scan-progress").hidden = true; }, 1600);
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
    if (scans.length) { $("scan-path").value = scans[0].target_value; await loadScan(scans[0].id); }
  } catch (e) { console.error(e); }
}

function applyScan(id, data) {
  state.scanId = id;
  state.findings = data.findings;
  state.summary = data.summary;
  state.scanMeta = data.scan;
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

let _qdaySeq = 0;
async function recomputeQday(persist) {
  if (!state.scanId) return;
  const seq = ++_qdaySeq;
  try {
    const data = await api("/api/qday", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: state.scanId, earliest: state.qday.earliest, likely: state.qday.likely,
        latest: state.qday.latest, sensitivity: state.sensitivity, persist: Boolean(persist),
      }),
    });
    const map = new Map(state.findings.map((f) => [f.id, f]));
    for (const d of data.deltas) {
      const f = map.get(d.id); if (!f) continue;
      f.risk_score = d.risk_score; f.quantum_class = d.quantum_class;
      f.exposure_years = d.exposure_years; f.extra = f.extra || {};
      if (d.mosca) f.extra.mosca = d.mosca;
      if (d.factors) f.extra.factors = d.factors;
    }
    // A slower earlier request must not overwrite a newer one's ranking.
    if (seq !== _qdaySeq) return;
    const rank = new Map(data.order.map((id, i) => [id, i]));
    state.findings.sort((a, b) => (rank.get(a.id) ?? 0) - (rank.get(b.id) ?? 0));
    state.summary = data.summary;
    renderAll();
    // The drawer holds numbers copied out of the finding it was opened with;
    // re-render it so it cannot keep showing superseded exposure figures.
    if (_openFinding) { const f = state.findings.find((x) => x.id === _openFinding.id); if (f) openDrawer(f, true); }
  } catch (e) { console.error("Q-Day recompute failed", e); }
}

/* ═══ render ════════════════════════════════════════════════════════ */

function renderAll() { renderHeadline(); renderStats(); renderDial(); renderMosca(); renderTable(); }

function span(cls, text) {
  const s = document.createElement("span");
  if (cls) s.className = cls;
  if (text !== undefined) s.textContent = text;
  return s;
}

function renderHeadline() {
  const s = state.summary; if (!s) return;
  $("posture-target").textContent = state.scanMeta?.target_label || "";
  const broken = s.by_class["shor-broken"] || 0;
  const safe = (s.by_class["quantum-safe"] || 0) + (s.by_class["hybrid"] || 0);
  const el = $("posture-verdict");
  el.textContent = "";
  el.append(
    span("n bad", `${s.quantum_vulnerable} of ${s.total}`),
    document.createTextNode(" cryptographic assets will not survive a quantum computer. "),
    span("n bad", String(broken)),
    document.createTextNode(" break outright. ")
  );
  if (safe) el.append(span("n good", String(safe)), document.createTextNode(" are already safe."));
}

function renderStats() {
  const s = state.summary; if (!s) return;
  const st = state.scanMeta?.stats || {};
  animateTo($("t-total"), "total", s.total);
  $("t-total-sub").textContent = `from ${(st.raw_hits || 0).toLocaleString()} hits`;
  animateTo($("t-vuln"), "vuln", s.quantum_vulnerable);
  $("t-vuln-sub").textContent = `${s.vulnerable_pct}% of estate`;
  animateTo($("t-crit"), "crit", s.by_severity?.critical || 0);
  $("t-crit-sub").textContent = `${s.by_severity?.high || 0} high`;
  animateTo($("t-exposure"), "exp", s.max_exposure_years, 1);

  const bits = [];
  if (st.files_scanned) bits.push(`${st.files_scanned.toLocaleString()} source files`);
  if (st.binaries_scanned) bits.push(`${st.binaries_scanned} binaries`);
  if (st.certificate_files_scanned) bits.push(`${st.certificate_files_scanned} certificates`);
  if (st.endpoints_probed) bits.push(`${st.endpoints_probed} live endpoints`);
  if (st.sensors_run) bits.push(`${st.sensors_run.length} sensors`);
  if (state.scanMeta?.duration) bits.push(`${state.scanMeta.duration.toFixed(1)}s`);
  $("lang-summary").textContent = bits.join("  ·  ");
}

/* ── the dial: every asset as a spoke ──────────────────────────────── */

const NS = "http://www.w3.org/2000/svg";
function sv(n, a, t) {
  const e = document.createElementNS(NS, n);
  for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v);
  if (t !== undefined) e.textContent = t;
  return e;
}

function renderDial() {
  const svg = $("radial");
  svg.textContent = "";
  const s = state.summary;
  const legendHost = $("legend");
  if (!s || !state.findings.length) {
    // Bail AFTER clearing, or a scan that finds nothing leaves the previous
    // scan's legend stranded under an empty ring.
    legendHost.textContent = "";
    state.dialDrawn = false;
    return;
  }

  const CX = 210, CY = 210, R0 = 96, R1 = 196;
  const items = [...state.findings].sort((a, b) => b.risk_score - a.risk_score);
  const N = items.length;
  // Sweep clockwise with the gap centred at the bottom, so the arc opens where
  // the eye expects a dial to open.
  const sweep = 2 * Math.PI * 0.86;
  const start = Math.PI / 2 + (2 * Math.PI - sweep) / 2;
  const step = sweep / N;
  // Width follows the angular pitch at the inner radius, so spokes never
  // overlap however many assets there are — a fixed 2.2px floor smeared them
  // into a solid ring past roughly 240 assets.
  const pitch = (sweep * R0) / N;
  const width = Math.max(0.6, Math.min(9, pitch * 0.72));

  // quiet guide rings, so spoke length is readable as a magnitude
  // A baseline at the hub plus quartile rings, so a spoke's length reads as a
  // magnitude against a scale rather than as an arbitrary size.
  for (const frac of [0, 0.25, 0.5, 0.75, 1]) {
    svg.appendChild(sv("circle", {
      cx: CX, cy: CY, r: R0 + (R1 - R0) * frac, fill: "none",
      stroke: tok("--hair-2"), "stroke-width": frac === 0 || frac === 1 ? 1 : 0.75,
      "stroke-dasharray": frac === 0 || frac === 1 ? "none" : "2 5",
      opacity: frac === 0 || frac === 1 ? 0.7 : 0.5,
    }));
  }
  svg.appendChild(sv("text", {
    x: CX, y: CY - R1 - 7, "text-anchor": "middle", fill: tok("--ink-4"),
    "font-size": "10.5", "font-family": tok("--mono"),
  }, "risk 100"));

  // Spokes are always authored at their FINAL geometry. The entrance is a
  // decorative fade-and-settle on the group, so if the animation never runs —
  // reduced motion, a printing context, an engine that drops it — the chart is
  // still complete rather than an empty ring. The previous version started each
  // line at the hub and relied on SMIL to grow it, which meant any failure to
  // animate left the dial permanently blank.
  const group = sv("g", { class: "spokes" + (!reduceMotion && !state.dialDrawn ? " revealing" : "") });

  items.forEach((f, i) => {
    const a = start + step * (i + 0.5), cos = Math.cos(a), sin = Math.sin(a);
    // Butt caps, not round: a round cap adds half the stroke width beyond BOTH
    // ends, inflating every bar by a full stroke width and turning a near-zero
    // score into a dot rather than a short bar.
    const len = R0 + (R1 - R0) * Math.max(0.02, Math.min(1, f.risk_score / 100));
    const line = sv("line", {
      x1: CX + R0 * cos, y1: CY + R0 * sin,
      x2: CX + len * cos, y2: CY + len * sin,
      stroke: tok(CLASS_VAR[f.quantum_class] || "--unknown"),
      "stroke-width": width, "stroke-linecap": "butt",
      tabindex: "0", role: "img",
      "aria-label": `${f.algorithm}, ${CLASS_LABEL[f.quantum_class] || f.quantum_class}, `
        + `risk ${f.risk_score.toFixed(0)}, ${f.occurrences} call sites`,
    });
    line.setAttribute("class", "spoke");
    line.style.setProperty("--i", i);
    line.addEventListener("mousemove", (e) => showTip(e, f));
    line.addEventListener("mouseleave", hideTip);
    line.addEventListener("click", () => openDrawer(f));
    line.addEventListener("focus", () => showTipAt(line, f));
    line.addEventListener("blur", hideTip);
    line.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
    });
    group.appendChild(line);
  });
  svg.appendChild(group);
  state.dialDrawn = true;

  const pct = s.vulnerable_pct;
  svg.appendChild(sv("text", {
    x: CX, y: CY - 6, "text-anchor": "middle", fill: tok("--ink"),
    "font-size": "46", "font-weight": "650", "letter-spacing": "-2",
    "font-family": tok("--mono"),
  }, `${Math.round(pct)}%`));
  svg.appendChild(sv("text", {
    x: CX, y: CY + 20, "text-anchor": "middle", fill: tok("--ink-3"),
    "font-size": "12.5", "font-family": tok("--ui"),
  }, "of the estate is"));
  svg.appendChild(sv("text", {
    x: CX, y: CY + 38, "text-anchor": "middle", fill: tok("--ink-3"),
    "font-size": "12.5", "font-family": tok("--ui"),
  }, "quantum vulnerable"));

  const legend = legendHost;
  legend.textContent = "";
  for (const k of CLASS_ORDER) {
    const n = s.by_class[k] || 0;
    if (!n) continue;
    const item = span("lg");
    const dot = document.createElement("i");
    dot.style.background = tok(CLASS_VAR[k]);
    const b = document.createElement("b"); b.textContent = n;
    item.append(dot, b, document.createTextNode(" " + CLASS_LABEL[k]));
    legend.appendChild(item);
  }
}

/* Build the tooltip body once; the two entry points differ only in where it
   gets positioned — pointer coordinates, or the focused spoke's own box. */
function fillTip(f) {
  const tip = $("tip");
  tip.hidden = false; tip.textContent = "";
  tip.append(span("t", f.algorithm));
  for (const [k, v] of [
    ["Class", CLASS_LABEL[f.quantum_class] || f.quantum_class],
    ["Risk", `${f.risk_score.toFixed(0)} · ${sevOf(f.risk_score)}`],
    ["Call sites", f.occurrences.toLocaleString()],
    ["Migrate to", f.recommendation?.target_name || "—"],
  ]) {
    const r = document.createElement("div"); r.className = "r";
    r.append(span(null, k), span(null, v)); tip.appendChild(r);
  }
  return tip;
}

function placeTip(tip, cx, cy) {
  const rect = tip.getBoundingClientRect(), pad = 16;
  let x = cx + pad, y = cy + pad;
  if (x + rect.width > innerWidth - 8) x = cx - rect.width - pad;
  if (y + rect.height > innerHeight - 8) y = cy - rect.height - pad;
  tip.style.left = Math.max(8, x) + "px";
  tip.style.top = Math.max(8, y) + "px";
}

function showTip(e, f) { placeTip(fillTip(f), e.clientX, e.clientY); }

/** Keyboard equivalent: anchor the tooltip to the focused spoke. */
function showTipAt(el, f) {
  const b = el.getBoundingClientRect();
  placeTip(fillTip(f), b.left + b.width / 2, b.top + b.height / 2);
}

function hideTip() { $("tip").hidden = true; }

/* ── Mosca ─────────────────────────────────────────────────────────── */

function renderMosca() {
  const svg = $("mosca-svg");
  svg.textContent = "";

  // With no scan there is no Y to speak of, and drawing a complete, confident
  // timeline from defaults asserts an exposure figure for an estate that does
  // not exist. Say so instead.
  if (!state.findings.length) {
    svg.appendChild(sv("text", {
      x: 500, y: 74, "text-anchor": "middle", fill: tok("--ink-4"),
      "font-size": "15", "font-family": tok("--ui"),
    }, "Run a scan to model exposure."));
    $("formula").textContent = "";
    const empty = $("mosca-verdict");
    empty.className = "verdict";
    empty.textContent = "No estate loaded.";
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
  const exposure = Math.max(0, X + Y - Z);

  const W = 1000, L = 30, R = 168, AXIS = 104;
  const span_ = Math.max(X + Y, Z, 8) * 1.05;
  const px = (y) => L + (y / span_) * (W - L - R);
  const MONO = tok("--mono");
  const bad = tok("--i-broken"), ink3 = tok("--ink-3"), hair = tok("--hair");

  $("formula").textContent = `X ${X} + Y ${Y} − Z ${Z} = ${exposure.toFixed(1)} yr exposed`;

  if (exposure > 0) {
    svg.appendChild(sv("rect", { x: px(Z), y: 16, width: Math.max(0, px(X + Y) - px(Z)),
      height: AXIS - 16, rx: 6, fill: bad, opacity: "0.10" }));
  }
  svg.appendChild(sv("line", { x1: L, y1: AXIS, x2: W - R + 36, y2: AXIS,
    stroke: hair, "stroke-width": "1.5" }));

  const step = span_ > 26 ? 8 : 4;
  // Guard against the axis end, and allow the final tick: a strict `<= span_`
  // with float accumulation dropped the last label short of the plotted domain.
  for (let y = 0; y <= span_ + 1e-6; y += step) {
    const x = px(y);
    if (x > W - R + 36) break;
    svg.appendChild(sv("text", { x, y: AXIS + 22, fill: ink3, "font-size": "13",
      "font-family": MONO, "text-anchor": "middle" }, String(NOW_YEAR + y)));
  }

  const LX = W - R + 14;
  const bar = (name, y, x1, x2, colour, label) => {
    svg.appendChild(sv("text", { x: L - 8, y: y + 15, fill: ink3, "font-size": "13",
      "font-weight": "600", "font-family": MONO, "text-anchor": "end" }, name));
    svg.appendChild(sv("rect", { x: x1, y, width: Math.max(3, x2 - x1), height: 21,
      rx: 6, fill: colour }));
    svg.appendChild(sv("text", { x: LX, y: y + 15, fill: tok("--ink-2"), "font-size": "13",
      "font-family": MONO }, label));
  };
  bar("Y", 22, px(0), px(Y), tok("--ink-4"), `${Y} yr migration`);
  bar("X", 55, px(Y), px(Y + X), tok("--weakened"), `${X} yr secrecy`);

  svg.appendChild(sv("line", { x1: px(Z), y1: 10, x2: px(Z), y2: AXIS,
    stroke: bad, "stroke-width": "2", "stroke-dasharray": "6 5" }));
  svg.appendChild(sv("circle", { cx: px(Z), cy: 10, r: 4, fill: bad }));
  const flip = px(Z) > W - R - 96;
  svg.appendChild(sv("text", { x: px(Z) + (flip ? -10 : 10), y: 14, fill: bad,
    "font-size": "13", "font-weight": "650", "font-family": MONO,
    "text-anchor": flip ? "end" : "start" }, `Q-Day ${state.qday.likely}`));

  if (exposure > 0) {
    const x1 = px(Z), x2 = px(X + Y);
    svg.appendChild(sv("text", { x: (x1 + x2) / 2, y: 94, fill: bad, "font-size": "13",
      "font-weight": "650", "font-family": MONO, "text-anchor": "middle" },
      `${exposure.toFixed(1)} years exposed`));
  }

  const out = $("mosca-verdict");
  const p = state.findings.reduce((a, f) => Math.max(a, f.extra?.mosca?.probability_exposed || 0), 0);
  if (exposure > 0) {
    out.className = "verdict";
    out.textContent = `The worst-exposed asset keeps data readable for ${exposure.toFixed(1)} years `
      + `after Q-Day` + (state.findings.length ? ` · P(exposed) = ${(p * 100).toFixed(0)}%` : "") + ".";
  } else {
    out.className = "verdict ok";
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
    ? `${rows.length} of ${state.findings.length} assets · click a row for evidence and remediation`
    : "Detector hits grouped into distinct assets.";

  if (!rows.length) {
    const tr = document.createElement("tr"); tr.className = "empty";
    const td = document.createElement("td"); td.colSpan = 8;
    td.textContent = state.findings.length
      ? "Nothing matches those filters."
      : (state.scanId
          ? "This scan found no cryptographic assets."
          : "No scan loaded — choose a target above and press Scan.");
    tr.appendChild(td); body.appendChild(tr); return;
  }

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.dataset.sev = sevOf(f.risk_score);
    const cell = (cls, text) => {
      const td = document.createElement("td");
      if (cls) td.className = cls;
      if (text !== undefined) td.textContent = text;
      return td;
    };
    const clsTd = cell();
    const c = span("cls " + f.quantum_class);
    const dot = document.createElement("i");
    dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
    clsTd.appendChild(c);

    const ev = f.evidence?.[0];
    const where = ev ? (ev.line ? `${ev.location}:${ev.line}` : ev.location) : "";
    const target = f.recommendation?.target_name || "";

    tr.append(
      cell("num risk", f.risk_score.toFixed(0)),
      Object.assign(cell("algo", f.algorithm), { title: f.algorithm }), clsTd,
      Object.assign(cell(null, f.title), { title: f.title }),
      cell("num", f.occurrences.toLocaleString()),
      cell("ctx", f.extra?.context || "production"),
      Object.assign(cell("loc", where), { title: where }),
      Object.assign(cell("to", target), { title: target })
    );
    // The drawer is the only route to evidence and remediation, so the row has
    // to be reachable without a pointer.
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-label", `${f.algorithm}: ${f.title}. Risk ${f.risk_score.toFixed(0)}.`);
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
function sec(t) { const s = el("div", "dsec"); s.appendChild(el("h3", null, t)); return s; }
function kv(pairs) {
  const dl = el("dl", "kv");
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, String(v)));
  }
  return dl;
}

let _openFinding = null;
let _returnFocusTo = null;

function openDrawer(f, isRefresh) {
  hideTip();
  if (!isRefresh) _returnFocusTo = document.activeElement;
  _openFinding = f;
  const d = $("drawer-body"); d.textContent = "";
  const head = el("div", "dhead");
  head.appendChild(el("div", "dtitle", f.algorithm));
  head.appendChild(el("div", "dsub", f.title));
  const meta = el("div", "dmeta");
  const c = span("cls " + f.quantum_class);
  const dot = document.createElement("i");
  dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
  c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
  const sv2 = el("span", null, `${sevOf(f.risk_score)} · ${f.risk_score.toFixed(1)}`);
  sv2.style.color = tok(SEV_VAR[sevOf(f.risk_score)]);
  meta.append(c, sv2, el("span", null, f.extra?.context || "production"));
  head.appendChild(meta); d.appendChild(head);

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
  const s = sec(`Evidence — ${f.occurrences} in ${files} file${files === 1 ? "" : "s"}`);
  for (const ev of (f.evidence || []).slice(0, 40)) {
    const item = el("div", "ev");
    item.appendChild(el("div", "l", ev.line ? `${ev.location}:${ev.line}` : ev.location));
    if (ev.snippet) item.appendChild(el("div", "s", ev.snippet));
    item.appendChild(el("div", "m",
      `${ev.technique} · conf ${ev.confidence.toFixed(2)}${ev.symbol ? " · " + ev.symbol : ""}`));
    s.appendChild(item);
  }
  d.appendChild(s);

  const drawer = $("drawer");
  drawer.hidden = false;
  $("scrim").hidden = false;
  drawer.setAttribute("role", "dialog");
  drawer.setAttribute("aria-modal", "true");
  drawer.setAttribute("aria-label", `${f.algorithm} — ${f.title}`);
  if (!isRefresh) $("drawer-close").focus();
}

function closeDrawer() {
  if ($("drawer").hidden) return;
  $("drawer").hidden = true;
  $("scrim").hidden = true;
  _openFinding = null;
  // Return the caret to whatever opened the drawer, so keyboard users are not
  // dumped back at the top of the document.
  if (_returnFocusTo && document.contains(_returnFocusTo)) _returnFocusTo.focus();
  _returnFocusTo = null;
}

/* Keep Tab inside the drawer while it is modal. */
document.addEventListener("keydown", (e) => {
  if (e.key !== "Tab" || $("drawer").hidden) return;
  const focusable = $("drawer").querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (!focusable.length) return;
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

async function validateCbom() {
  if (!state.scanId) return;
  const box = $("validate-result");
  box.hidden = false; box.className = "banner"; box.textContent = "Validating…";
  try {
    const r = await api(`/api/scan/${state.scanId}/cbom/validate`);
    box.className = "banner " + (r.valid ? "pass" : "fail");
    box.textContent = r.valid
      ? `PASS — ${r.components} cryptographic-asset components conform to ${r.spec}.`
      : `FAIL — ${r.problems.length} problem(s): ${r.problems.slice(0, 3).join("; ")}`;
  } catch (e) { box.className = "banner fail"; box.textContent = "Validation failed: " + e.message; }
}

boot();
