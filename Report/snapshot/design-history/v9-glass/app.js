/* CryptoDrishti. Vanilla JS, no framework, no build step, no external request. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null, scanId: null, findings: [], summary: null, scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  classFilter: null,            // set from the estate chips
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
const SCENES = [
  ["sc-verdict", "Verdict"], ["sc-estate", "Estate"], ["sc-clock", "Clock"],
  ["sc-plan", "Plan"], ["sc-record", "Record"],
];

const sevOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;

/* Memoised: renderSwarm and renderTable would otherwise force a style read per mark. */
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
/* ?flat=1 collapses the full-height scenes to their content, so the whole deck
   prints — and screenshots — as one continuous document. */
if (_params.get("flat") === "1") document.documentElement.classList.add("flat");
const reduceMotion = stillMode
  || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
/* Entrance animations are opt-in via this class. Without it every scene panel
   renders at its resting state, which is what still captures and reduced
   motion need. */
if (!reduceMotion) document.body.classList.add("anim");

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
  const running = _tweens.get(key);
  if (running !== undefined) cancelAnimationFrame(running);
  const from = state.shown[key];
  state.shown[key] = value;
  const fmt = (v) => (dec ? v.toFixed(dec) : Math.round(v).toLocaleString());
  if (reduceMotion || from === undefined || from === value) {
    _tweens.delete(key); el.textContent = fmt(value); return;
  }
  const t0 = performance.now(), dur = 620;
  const step = (now) => {
    const t = Math.min(1, (now - t0) / dur);
    el.textContent = fmt(from + (value - from) * (1 - Math.pow(1 - t, 4)));
    if (t < 1) _tweens.set(key, requestAnimationFrame(step)); else _tweens.delete(key);
  };
  _tweens.set(key, requestAnimationFrame(step));
}

/* ══ boot ═══════════════════════════════════════════════════════════ */

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

  buildSensors(); buildRail(); initTheme();

  $("run-scan").addEventListener("click", startScan);
  let ft = null;
  $("filter-q").addEventListener("input", () => { clearTimeout(ft); ft = setTimeout(renderTable, 90); });
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
  document.addEventListener("keydown", onKey);

  let rt = null;
  window.addEventListener("resize", () => {
    clearTimeout(rt); rt = setTimeout(() => { renderSwarm(); renderMosca(); }, 160);
  });

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

/* The slider spans 2028-2050 but the distribution bounds were frozen at the
   server defaults, so anything outside them made /api/qday reject the request
   and the page silently kept stale numbers. Keep the window around `likely`. */
function setQday(likely) {
  const d = state.meta?.qday_default || { earliest: 2030, latest: 2044 };
  state.qday.likely = likely;
  state.qday.earliest = Math.min(d.earliest, likely - 2);
  state.qday.latest = Math.max(d.latest, likely + 2);
}

/* ══ scene rail ═════════════════════════════════════════════════════ */

function buildRail() {
  const ol = $("rail-list");
  for (const [id, name] of SCENES) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = "#" + id;
    const pip = document.createElement("span"); pip.className = "pip";
    const nm = document.createElement("span"); nm.className = "nm"; nm.textContent = name;
    a.append(pip, nm);
    a.dataset.scene = id;
    li.appendChild(a); ol.appendChild(li);
  }
  // Mark the scene occupying the middle of the viewport as current.
  const obs = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      for (const a of ol.querySelectorAll("a")) {
        a.setAttribute("aria-current", String(a.dataset.scene === e.target.id));
      }
    }
  }, { rootMargin: "-45% 0px -45% 0px" });
  for (const [id] of SCENES) obs.observe($(id));

  // Reveal a panel the moment it enters, not when it reaches the middle.
  const reveal = new IntersectionObserver((entries, o) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      e.target.classList.add("seen");
      o.unobserve(e.target);
    }
  }, { threshold: 0.08 });
  for (const [id] of SCENES) reveal.observe($(id));

  /* Failsafe. The entrance hides a panel until the observer reveals it; if the
     observer never fires the scene would stay blank, which is not a risk worth
     carrying on stage. Reveal everything unconditionally after a beat. */
  setTimeout(() => {
    for (const [id] of SCENES) $(id).classList.add("seen");
  }, 1500);
}

function onKey(e) {
  if (e.key === "Escape") { closeDrawer(); return; }
  if (e.target.matches("input, select, textarea")) return;
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  const ids = SCENES.map(([id]) => id);
  const mid = innerHeight / 2;
  let cur = 0;
  ids.forEach((id, i) => { if ($(id).getBoundingClientRect().top <= mid) cur = i; });
  const next = Math.max(0, Math.min(ids.length - 1, cur + (e.key === "ArrowDown" ? 1 : -1)));
  e.preventDefault();
  $(ids[next]).scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth" });
}

/* ══ theme ══════════════════════════════════════════════════════════ */

const isDark = () => {
  const s = document.documentElement.getAttribute("data-theme");
  return s ? s === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
};

function initTheme() {
  const sync = () => {
    $("theme-toggle").textContent = isDark() ? "Light" : "Dark";
    $("theme-toggle").setAttribute("aria-pressed", String(isDark()));
    dropTokens();
    renderSwarm(); renderMosca(); renderTable(); renderPlan();
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

/* ══ scanning ═══════════════════════════════════════════════════════ */

function buildSensors() {
  const host = $("sensors"); host.textContent = "";
  for (const k of SENSORS) {
    const el = document.createElement("span");
    el.dataset.sensor = k; el.dataset.state = "idle";
    el.append(document.createElement("i"), document.createTextNode(k));
    host.appendChild(el);
  }
}

function reflectSensors(phase) {
  const t = (phase || "").toLowerCase();
  const m = { source: "source code", dependency: "dependency", certificate: "certificate",
              config: "configuration", binary: "binaries", network: "endpoint" };
  const els = [...document.querySelectorAll("#sensors span")];
  let active = -1;
  els.forEach((el, i) => {
    if (m[el.dataset.sensor] && t.includes(m[el.dataset.sensor])) { el.dataset.state = "active"; active = i; }
  });
  if (active >= 0) els.forEach((el, i) => { if (i < active) el.dataset.state = "done"; });
}

async function startScan() {
  const path = $("scan-path").value.trim();
  if (!path) { $("scan-path").focus(); return; }
  $("run-scan").disabled = true;
  clearTimeout(state.hideTimer);
  $("scan-progress").hidden = false;
  for (const el of document.querySelectorAll("#sensors span")) el.dataset.state = "idle";
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
      for (const el of document.querySelectorAll("#sensors span")) el.dataset.state = "done";
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

/* ══ Q-Day ══════════════════════════════════════════════════════════ */

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

/* ══ render ═════════════════════════════════════════════════════════ */

function renderAll() { renderVerdict(); renderSwarm(); renderMosca(); renderPlan(); renderTable(); }

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

/* ── 1 verdict ── */

function renderVerdict() {
  const s = state.summary;
  if (!s) return;
  $("posture-target").textContent = state.scanMeta?.target_label || "";
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
                        document.createTextNode(" are already safe."));
  else line.append(document.createTextNode("."));

  const st = state.scanMeta?.stats || {};
  animateTo($("t-total"), "total", s.total);
  $("t-total-sub").textContent = `from ${(st.raw_hits || 0).toLocaleString()} detector hits`;
  animateTo($("t-vuln"), "vuln", s.quantum_vulnerable);
  $("t-vuln-sub").textContent = `${s.vulnerable_pct}% of the estate`;
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

/* ── 2 estate: a beeswarm across the risk axis ── */

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
  const s = state.summary;
  const chips = $("legend");
  chips.textContent = "";
  if (!s || !state.findings.length) return;

  const W = 1000, PAD_L = 8, PAD_R = 8, AX = 250, H = 300;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const x = (score) => PAD_L + (score / 100) * (W - PAD_L - PAD_R);
  const R = 6.5, GAP = 1.4;

  // axis
  svg.appendChild(sv("line", { x1: PAD_L, y1: AX, x2: W - PAD_R, y2: AX,
    stroke: tok("--hair-2"), "stroke-width": 1 }));
  for (const v of [0, 25, 45, 70, 100]) {
    svg.appendChild(sv("line", { x1: x(v), y1: AX, x2: x(v), y2: AX + 7,
      stroke: tok("--hair-2"), "stroke-width": 1 }));
    svg.appendChild(sv("text", { x: x(v), y: AX + 24, "text-anchor": "middle",
      fill: tok("--ink-4"), "font-size": 13, "font-family": tok("--mono") }, String(v)));
  }
  for (const [v, label] of [[25, "medium"], [45, "high"], [70, "critical"]]) {
    svg.appendChild(sv("text", { x: x(v) + 5, y: 22, fill: tok("--ink-4"),
      "font-size": 12, "font-family": tok("--ui") }, label));
    svg.appendChild(sv("line", { x1: x(v), y1: 28, x2: x(v), y2: AX,
      stroke: tok("--hair"), "stroke-width": 1, "stroke-dasharray": "2 6" }));
  }
  svg.appendChild(sv("text", { x: PAD_L, y: 22, fill: tok("--ink-4"),
    "font-size": 12, "font-family": tok("--ui") }, "risk score"));

  // Place each asset at its score, stacking upward only where dots would touch.
  const placed = [];
  const sorted = [...state.findings].sort((a, b) => a.risk_score - b.risk_score);
  const group = sv("g", {});
  sorted.forEach((f, di) => {
    const cx = x(f.risk_score);
    let cy = AX - R - 2, tries = 0;
    while (tries < 40 && placed.some((p) =>
      (p.cx - cx) ** 2 + (p.cy - cy) ** 2 < (2 * R + GAP) ** 2)) {
      cy -= (2 * R + GAP) * 0.92; tries += 1;
      if (cy < R + 34) { cy = AX - R - 2 - Math.random() * 0; break; }
    }
    placed.push({ cx, cy });
    const dimmed = state.classFilter && f.quantum_class !== state.classFilter;
    const dot = sv("circle", {
      cx, cy, r: R, fill: tok(CLASS_VAR[f.quantum_class] || "--unknown"),
      opacity: dimmed ? 0.12 : 0.92, tabindex: dimmed ? "-1" : "0", role: "img",
      "aria-label": `${f.algorithm}, ${CLASS_LABEL[f.quantum_class] || f.quantum_class}, `
        + `risk ${f.risk_score.toFixed(0)}, ${f.occurrences} call sites`,
    });
    dot.setAttribute("class", "dot");
    dot.style.setProperty("--i", di);   // drives the staggered entry in CSS
    dot.addEventListener("mousemove", (e) => showTip(e, f));
    dot.addEventListener("mouseleave", hideTip);
    dot.addEventListener("click", () => openDrawer(f));
    dot.addEventListener("focus", () => showTipAt(dot, f));
    dot.addEventListener("blur", hideTip);
    dot.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(f); }
    });
    group.appendChild(dot);
  });
  svg.appendChild(group);

  // class chips double as filters
  for (const k of CLASS_ORDER) {
    const n = s.by_class[k] || 0;
    if (!n) continue;
    const b = document.createElement("button");
    b.className = "chip";
    b.setAttribute("aria-pressed", String(state.classFilter === k));
    const i = document.createElement("i"); i.style.background = tok(CLASS_VAR[k]);
    b.append(i, el("b", null, String(n)), document.createTextNode(" " + CLASS_LABEL[k]));
    b.addEventListener("click", () => {
      state.classFilter = state.classFilter === k ? null : k;
      $("filter-class").value = state.classFilter || "";
      renderSwarm(); renderTable();
    });
    chips.appendChild(b);
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
  const b = tip.getBoundingClientRect(), pad = 16;
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

/* ── 3 clock ── */

function renderMosca() {
  const svg = $("mosca-svg");
  svg.textContent = "";

  if (!state.findings.length) {
    svg.appendChild(sv("text", { x: 500, y: 76, "text-anchor": "middle",
      fill: tok("--ink-4"), "font-size": 16, "font-family": tok("--ui") },
      "Run a scan to model exposure."));
    $("mosca-verdict").className = "verdict";
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
  const exposure = Math.max(0, X + Y - Z);

  const W = 1000, L = 26, R = 176, AXIS = 104;
  const span = Math.max(X + Y, Z, 8) * 1.05;
  const px = (y) => L + (y / span) * (W - L - R);
  const MONO = tok("--mono"), bad = tok("--i-broken"), ink3 = tok("--ink-3");

  if (exposure > 0) {
    svg.appendChild(sv("rect", { x: px(Z), y: 14, width: Math.max(0, px(X + Y) - px(Z)),
      height: AXIS - 14, rx: 6, fill: bad, opacity: .10 }));
  }
  svg.appendChild(sv("line", { x1: L, y1: AXIS, x2: W - R + 36, y2: AXIS,
    stroke: tok("--hair-2"), "stroke-width": 1.5 }));
  const step = span > 26 ? 8 : 4;
  for (let y = 0; y <= span + 1e-6; y += step) {
    const xx = px(y);
    if (xx > W - R + 36) break;
    svg.appendChild(sv("text", { x: xx, y: AXIS + 22, fill: ink3, "font-size": 13,
      "font-family": MONO, "text-anchor": "middle" }, String(NOW_YEAR + y)));
  }
  const LX = W - R + 14;
  const bar = (name, y, x1, x2, colour, label) => {
    svg.appendChild(sv("text", { x: L - 8, y: y + 15, fill: ink3, "font-size": 13,
      "font-weight": 600, "font-family": MONO, "text-anchor": "end" }, name));
    svg.appendChild(sv("rect", { x: x1, y, width: Math.max(3, x2 - x1), height: 21,
      rx: 6, fill: colour }));
    svg.appendChild(sv("text", { x: LX, y: y + 15, fill: tok("--ink-2"),
      "font-size": 13, "font-family": MONO }, label));
  };
  bar("Y", 20, px(0), px(Y), tok("--ink-4"), `${Y} yr migration`);
  bar("X", 53, px(Y), px(Y + X), tok("--weakened"), `${X} yr secrecy`);

  svg.appendChild(sv("line", { x1: px(Z), y1: 8, x2: px(Z), y2: AXIS,
    stroke: bad, "stroke-width": 2, "stroke-dasharray": "6 5" }));
  svg.appendChild(sv("circle", { cx: px(Z), cy: 8, r: 4, fill: bad }));
  const flip = px(Z) > W - R - 96;
  svg.appendChild(sv("text", { x: px(Z) + (flip ? -10 : 10), y: 12, fill: bad,
    "font-size": 13, "font-weight": 650, "font-family": MONO,
    "text-anchor": flip ? "end" : "start" }, `Q-Day ${state.qday.likely}`));
  if (exposure > 0) {
    svg.appendChild(sv("text", { x: (px(Z) + px(X + Y)) / 2, y: 94, fill: bad,
      "font-size": 13, "font-weight": 650, "font-family": MONO, "text-anchor": "middle" },
      `${exposure.toFixed(1)} years exposed`));
  }

  const out = $("mosca-verdict");
  const p = state.findings.reduce((a, f) => Math.max(a, f.extra?.mosca?.probability_exposed || 0), 0);
  if (exposure > 0) {
    out.className = "verdict";
    out.textContent = `The worst-exposed asset keeps data readable for ${exposure.toFixed(1)} years `
      + `after Q-Day · P(exposed) = ${(p * 100).toFixed(0)}%.`;
  } else {
    out.className = "verdict ok";
    out.textContent = "Within tolerance at the current assumptions.";
  }
}

/* ── 4 plan: workstreams grouped by replacement algorithm ── */

function renderPlan() {
  const host = $("streams");
  host.textContent = "";
  if (!state.findings.length) {
    host.appendChild(el("p", "sub", "Run a scan to build a migration plan."));
    return;
  }
  const groups = new Map();
  for (const f of state.findings) {
    const cls = f.quantum_class;
    if (cls === "quantum-safe" || cls === "hybrid") continue;   // nothing to do
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
  if (!list.length) {
    host.appendChild(el("p", "sub", "Nothing to migrate — every asset is already quantum-safe."));
    return;
  }
  const maxSites = Math.max(...list.map((g) => g.sites));

  list.forEach((g, gi) => {
    const row = el("div", "stream");
    row.style.setProperty("--i", gi);
    const to = el("div");
    to.append(el("span", "lbl", "Migrate to"), el("div", "to", g.key));
    const a = el("div");
    a.append(el("span", "lbl", "Assets"), el("div", "n", String(g.assets)));
    const si = el("div");
    si.append(el("span", "lbl", "Sites"), el("div", "n", g.sites.toLocaleString()));
    const ef = el("div");
    const dl = (g.delta === undefined || g.delta === null)
      ? g.effort
      : `${g.effort} · ${g.delta > 0 ? "+" : ""}${g.delta} B`;
    ef.append(el("span", "lbl", "Effort"), el("div", "eff", dl));
    const ac = el("div", "act", g.action);
    const bar = el("div", "bar");
    const fill = document.createElement("i");
    fill.style.width = Math.max(2, (g.sites / maxSites) * 100) + "%";
    fill.style.background = tok(SEV_VAR[sevOf(g.peak)]);
    bar.appendChild(fill);
    row.append(to, a, si, ef, ac, bar);
    host.appendChild(row);
  });
}

/* ── 5 record ── */

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
    const tr = el("tr", "empty");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = state.findings.length ? "Nothing matches those filters."
      : (state.scanId ? "This scan found no cryptographic assets."
                      : "No scan loaded — choose a target above and press Scan.");
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
      cell("num risk", f.risk_score.toFixed(0)),
      Object.assign(cell("algo", f.algorithm), { title: f.algorithm }),
      clsTd,
      Object.assign(cell(null, f.title), { title: f.title }),
      cell("num", f.occurrences.toLocaleString()),
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

/* ══ drawer ═════════════════════════════════════════════════════════ */

let _open = null, _returnTo = null;

function sec(t) { const s = el("div", "dsec"); s.appendChild(el("h3", null, t)); return s; }
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

  const head = el("div", "dhead");
  head.appendChild(el("div", "dtitle", f.algorithm));
  head.appendChild(el("div", "dsub", f.title));
  const meta = el("div", "dmeta");
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
  const s2 = sec(`Evidence — showing ${shown} of ${f.occurrences} in ${files} file${files === 1 ? "" : "s"}`);
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
