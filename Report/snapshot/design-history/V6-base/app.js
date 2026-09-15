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
  ["s-verdict", "Assessment"], ["s-estate", "Weight"], ["s-clock", "Exposure"],
  ["s-plan", "Remediation"], ["s-record", "Inventory"], ["s-out", "Output"],
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

  buildFigures(); buildArray(); buildIndex(); initTheme();

  $("run-scan").addEventListener("click", startScan);
  $("scan-path").addEventListener("keydown", (e) => { if (e.key === "Enter") startScan(); });
  let ft = null;
  $("filter-q").addEventListener("input", () => { clearTimeout(ft); ft = setTimeout(renderLedger, 90); });
  $("filter-class").addEventListener("change", () => {
    state.classFilter = $("filter-class").value || null;
    renderDial(); renderTreemap(); renderLedger(); renderComposition();
  });
  $("filter-context").addEventListener("change", renderLedger);
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
    clearTimeout(rt); rt = setTimeout(() => { renderTreemap(); renderMosca(); }, 160);
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

function armArray() {
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
    $("rail-target").textContent = m.target_label || m.target_value || "—";
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

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) { $("scan-path").focus(); return; }
  $("run-scan").disabled = true;
  armArray(); startClock();
  try {
    const { scan_id } = await api("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path, label: "",
        profile: $("profile").value,
        endpoints: $("scan-endpoints").value.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    });
    poll(scan_id);
  } catch (e) {
    stopClock(); $("run-scan").disabled = false;
    $("array-state").textContent = "Error — " + e.message;
  }
}

function poll(id) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    let job;
    try { job = await api(`/api/scan/${id}/status`); } catch (_) { return; }
    reflectArray(job.phase, job.progress || 0);
    if (job.state === "done") {
      clearInterval(state.pollTimer); stopClock();
      $("run-scan").disabled = false;
      await loadScan(id);
      $("s-verdict").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth" });
    } else if (job.state === "error") {
      clearInterval(state.pollTimer); stopClock();
      $("run-scan").disabled = false;
      $("array-state").textContent = "Failed — " + (job.error || "unknown error");
      console.error(job.trace || job.error);
    }
  }, 400);
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
    renderDial(); renderTreemap(); renderMosca(); renderLedger(); renderPlan(); renderComposition();
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
    ["verdict", renderVerdict], ["composition", renderComposition], ["array", settleArray],
    ["treemap", renderTreemap], ["exposure", renderMosca],
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
    renderDial(); renderTreemap(); renderLedger(); renderComposition();
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
      line.addEventListener("mousemove", (e) => showTip(e, f));
      line.addEventListener("mouseleave", hideTip);
      line.addEventListener("click", () => openDrawer(f));
      line.addEventListener("focus", () => showTipAt(line, f));
      line.addEventListener("blur", hideTip);
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

  svg.appendChild(sv("text", { x: CX, y: CY - 4, "text-anchor": "middle", fill: tok("--ink"),
    "font-size": 52, "font-weight": 600, "letter-spacing": -2.5,
    "font-family": tok("--mono") }, `${Math.round(s.vulnerable_pct)}%`));
  svg.appendChild(sv("text", { x: CX, y: CY + 22, "text-anchor": "middle", fill: tok("--ink-3"),
    "font-size": 12.5, "font-family": tok("--ui") }, "of the estate is"));
  svg.appendChild(sv("text", { x: CX, y: CY + 40, "text-anchor": "middle", fill: tok("--ink-3"),
    "font-size": 12.5, "font-family": tok("--ui") }, "quantum vulnerable"));
}

/* ─── 02 where the weight sits: a squarified treemap ───────────────
   A list gives a two-line finding and a three-hundred-site finding equal
   space. The work does not divide that way, so area is call sites. */

const NS = "http://www.w3.org/2000/svg";
function sv(n, a, t) {
  const e = document.createElementNS(NS, n);
  for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v);
  if (t !== undefined) e.textContent = t;
  return e;
}

function squarify(items, x, y, w, h) {
  const out = [];
  const rest = items.slice();
  while (rest.length && w > 0.5 && h > 0.5) {
    const total = rest.reduce((a, it) => a + it.value, 0);
    if (total <= 0) break;
    const short = Math.min(w, h);
    const scale = (w * h) / total;
    const row = [];
    let sum = 0, best = Infinity;
    while (rest.length) {
      const cand = sum + rest[0].value;
      const len = (cand * scale) / short;
      if (len <= 0) { row.push(rest.shift()); sum = cand; continue; }
      const worst = Math.max(...[...row, rest[0]].map((r) => {
        const side = (r.value * scale) / len;
        return side > 0 ? Math.max(len / side, side / len) : Infinity;
      }));
      if (worst > best) break;
      best = worst; sum = cand; row.push(rest.shift());
    }
    const len = (sum * scale) / short;
    let off = 0;
    for (const r of row) {
      const side = (r.value * scale) / len;
      if (w >= h) out.push({ ...r, x, y: y + off, w: len, h: side });
      else out.push({ ...r, x: x + off, y, w: side, h: len });
      off += side;
    }
    if (w >= h) { x += len; w -= len; } else { y += len; h -= len; }
  }
  return out;
}

function renderTreemap() {
  const svg = $("treemap");
  svg.textContent = "";
  if (!state.findings.length) return;

  const W = 1000, H = 420, PAD = 2;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const MONO = tok("--mono"), ink = tok("--ink"), ink3 = tok("--ink-3"), surf = tok("--surf");

  const items = state.findings
    .map((f) => ({ f, value: Math.max(1, f.occurrences) }))
    .sort((a, b) => b.value - a.value);
  const tiles = squarify(items, 0, 0, W, H);

  for (const t of tiles) {
    const f = t.f;
    const dim = state.classFilter && f.quantum_class !== state.classFilter;
    const colour = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    const g = sv("g", { class: "tile", tabindex: dim ? "-1" : "0", role: "img",
      "aria-label": `${f.algorithm}, ${CLASS_LABEL[f.quantum_class] || f.quantum_class}, `
        + `${f.occurrences} call sites, risk ${f.risk_score.toFixed(0)}` });
    const x = t.x + PAD, y = t.y + PAD;
    const w = Math.max(0, t.w - PAD * 2), h = Math.max(0, t.h - PAD * 2);

    // A wash carries the class; a full-strength spine on the left carries it
    // again at a size that survives being small.
    g.appendChild(sv("rect", { class: "f", x, y, width: w, height: h,
      fill: colour, opacity: dim ? .06 : .17 }));
    g.appendChild(sv("rect", { x, y, width: Math.min(3, w), height: h,
      fill: colour, opacity: dim ? .2 : 1 }));
    g.appendChild(sv("rect", { x, y, width: w, height: h, fill: "none",
      stroke: surf, "stroke-width": 1 }));

    const fits = w > f.algorithm.length * 7.35 + 18;
    if (fits && h > 26 && !dim) {
      g.appendChild(sv("text", { x: x + 9, y: y + 17, fill: ink, "font-size": 12.5,
        "font-family": MONO, "font-weight": 640 }, f.algorithm));
      if (h > 44) {
        g.appendChild(sv("text", { x: x + 9, y: y + 33, fill: ink3, "font-size": 11,
          "font-family": MONO }, `${f.occurrences.toLocaleString()} sites`));
      }
    }
    if (!dim) {
      g.addEventListener("mousemove", (e) => showTip(e, f));
      g.addEventListener("mouseleave", hideTip);
      g.addEventListener("click", () => openDrawer(f));
      g.addEventListener("focus", () => showTipAt(g, f));
      g.addEventListener("blur", hideTip);
      g.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
      });
    }
    svg.appendChild(g);
  }
  const sites = state.findings.reduce((a, f) => a + f.occurrences, 0);
  $("x-estate").textContent = `${sites.toLocaleString()} call sites`;
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
  const svg = $("mosca-svg"), plain = $("mosca-plain");
  svg.textContent = ""; plain.textContent = "";

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

  // plain language first, so the chart confirms rather than explains
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

  const W = 1000, L = 34, R = 190, RULE = 156;
  const span = Math.max(T, state.qday.latest - NOW_YEAR, 8) * 1.06;
  const px = (y) => L + (y / span) * (W - L - R);
  const MONO = tok("--mono"), bad = tok("--i-broken"), ink = tok("--ink"),
        ink3 = tok("--ink-3"), ink4 = tok("--ink-4"), rule2 = tok("--rule-2");
  const LX = W - R + 14;

  const dA = Math.max(0, state.qday.earliest - NOW_YEAR);
  const dB = Math.max(dA + 1, state.qday.latest - NOW_YEAR);

  // the overlap, drawn behind both spans
  if (exposure > 0) {
    svg.appendChild(sv("rect", { x: px(Z), y: 22, width: px(T) - px(Z), height: RULE - 22,
      fill: bad, opacity: .12 }));
  }

  // span 1 — how long secrecy must hold
  svg.appendChild(sv("text", { x: L, y: 18, fill: ink4, "font-size": 10,
    "font-family": MONO, "letter-spacing": 1.2 }, "SECRECY MUST HOLD"));
  svg.appendChild(sv("rect", { x: px(0), y: 30, width: Math.max(3, px(T) - px(0)), height: 26,
    fill: tok("--unknown"), opacity: .30 }));
  svg.appendChild(sv("rect", { x: px(0), y: 30, width: 2, height: 26, fill: ink }));
  svg.appendChild(sv("rect", { x: px(T) - 2, y: 30, width: 2, height: 26, fill: ink }));
  svg.appendChild(sv("text", { x: LX, y: 47, fill: tok("--ink-2"), "font-size": 12,
    "font-family": MONO }, `through ${secureUntil}`));

  // span 2 — when the machine arrives
  svg.appendChild(sv("text", { x: L, y: 82, fill: ink4, "font-size": 10,
    "font-family": MONO, "letter-spacing": 1.2 }, "QUANTUM COMPUTER EXPECTED"));
  svg.appendChild(sv("rect", { x: px(dA), y: 94, width: Math.max(3, px(dB) - px(dA)), height: 26,
    fill: tok("--weakened"), opacity: .34 }));
  svg.appendChild(sv("rect", { x: px(Z) - 1.5, y: 88, width: 3, height: 38, fill: bad }));
  svg.appendChild(sv("text", { x: LX, y: 111, fill: tok("--ink-2"), "font-size": 12,
    "font-family": MONO }, `${NOW_YEAR + dA}–${NOW_YEAR + dB}`));
  svg.appendChild(sv("text", { x: px(Z), y: 84, fill: bad, "font-size": 11,
    "font-family": MONO, "font-weight": 640, "text-anchor": "middle" },
    `likely ${state.qday.likely}`));

  // the exposed years, named
  if (exposure > 0) {
    svg.appendChild(sv("text", { x: (px(Z) + px(T)) / 2, y: 143, fill: bad, "font-size": 12.5,
      "font-family": MONO, "font-weight": 640, "text-anchor": "middle" },
      `${exposure.toFixed(1)} YEARS EXPOSED`));
  }

  // the ruler
  svg.appendChild(sv("line", { x1: L, y1: RULE, x2: W - R + 30, y2: RULE,
    stroke: rule2, "stroke-width": 1 }));
  const step = span > 26 ? 8 : span > 13 ? 4 : 2;
  for (let y = 0; y <= span + 1e-6; y += step) {
    const xx = px(y);
    if (xx > W - R + 30) break;
    svg.appendChild(sv("line", { x1: xx, y1: RULE, x2: xx, y2: RULE + 5,
      stroke: rule2, "stroke-width": 1 }));
    svg.appendChild(sv("text", { x: xx, y: RULE + 21, fill: ink3, "font-size": 12,
      "font-family": MONO, "text-anchor": "middle" }, String(NOW_YEAR + y)));
  }
  svg.appendChild(sv("text", { x: L, y: RULE + 44, fill: ink4, "font-size": 10,
    "font-family": MONO, "letter-spacing": 1.2 }, "TODAY"));

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
      + `${CLASS_LABEL[f.quantum_class] || f.quantum_class}, ${f.occurrences} call sites.`);

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

    const to = el("span", "led-to", f.recommendation?.target_name || "manual review");
    to.title = f.recommendation?.target_name || "";

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
