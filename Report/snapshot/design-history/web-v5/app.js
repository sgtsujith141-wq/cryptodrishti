/* CryptoDrishti operator console. Vanilla JS, no framework, no build, no CDN. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  meta: null, scanId: null, findings: [], summary: null, scanMeta: null,
  qday: { earliest: 2030, likely: 2034, latest: 2044 },
  sensitivity: "confidential",
  selected: null,                       // finding id
  sort: { key: "risk_score", dir: -1 },
  filters: { cls: new Set(), sev: new Set(), sensor: new Set(), ctx: new Set() },
  pollTimer: null, qdayTimer: null,
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
const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_VAR = { critical: "--crit", high: "--high", medium: "--med", low: "--low" };
const SENSOR_LABEL = {
  source: "source", dependency: "dependency", certificate: "certificate",
  config: "config", binary: "binary", network: "network",
};

const sevOf = (s) => (s >= 70 ? "critical" : s >= 45 ? "high" : s >= 25 ? "medium" : "low");
const NOW_YEAR = 2026;
const tok = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let d = res.statusText;
    try { d = (await res.json()).detail || d; } catch (_) {}
    throw new Error(d);
  }
  return res.json();
}

/* ══ boot ═══════════════════════════════════════════════════════════ */

async function boot() {
  const pre = window.__PRELOAD__ || null;
  try { state.meta = pre?.meta || await api("/api/meta"); }
  catch (e) { console.error(e); return; }

  $("product-name").textContent = state.meta.product;
  $("ps-badge").textContent = state.meta.ps_id;
  $("foot-meta").textContent = state.meta.ps_id;

  const preset = $("target-preset");
  for (const t of state.meta.suggested_targets) {
    const o = document.createElement("option");
    o.value = t.path; o.textContent = t.label;
    preset.appendChild(o);
  }
  preset.addEventListener("change", () => { if (preset.value) $("scan-path").value = preset.value; });

  for (const [k, label] of Object.entries(state.meta.profiles)) {
    const o = document.createElement("option");
    o.value = k; o.textContent = label;
    $("profile").appendChild(o);
  }
  for (const [k, yrs] of Object.entries(state.meta.sensitivities)) {
    const o = document.createElement("option");
    o.value = k; o.textContent = `${k} · ${yrs} yr`;
    $("sensitivity").appendChild(o);
  }

  state.qday = { ...state.meta.qday_default };
  const p = new URLSearchParams(location.search);
  const qp = Number(p.get("qday"));
  if (qp >= 2028 && qp <= 2050) state.qday.likely = qp;
  const sp = p.get("sensitivity");
  if (sp && state.meta.sensitivities[sp] !== undefined) state.sensitivity = sp;

  $("sensitivity").value = state.sensitivity;
  $("qday-likely").value = state.qday.likely;
  $("qday-out").textContent = state.qday.likely;

  $("sensitivity").addEventListener("change", (e) => {
    state.sensitivity = e.target.value; renderMosca(); scheduleQday(true);
  });
  $("qday-likely").addEventListener("input", (e) => {
    state.qday.likely = Number(e.target.value);
    $("qday-out").textContent = e.target.value;
    renderMosca(); scheduleQday(false);
  });
  $("qday-likely").addEventListener("change", () => scheduleQday(true));

  buildSensors();
  initTheme();

  $("run-scan").addEventListener("click", startScan);
  $("filter-q").addEventListener("input", () => { renderTable(); renderFacets(); });
  $("clear-filters").addEventListener("click", clearFilters);
  $("btn-cbom").addEventListener("click", () => {
    if (state.scanId) location.href = `/api/scan/${state.scanId}/cbom?download=true`;
  });
  $("btn-report").addEventListener("click", () => {
    if (state.scanId) window.open(`/api/scan/${state.scanId}/report`, "_blank");
  });
  $("btn-validate").addEventListener("click", validateCbom);
  $("explain-toggle").addEventListener("click", toggleExplain);

  for (const th of document.querySelectorAll("th.sortable")) {
    th.addEventListener("click", () => {
      const k = th.dataset.sort;
      state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : -1 };
      renderTable();
    });
  }

  document.addEventListener("keydown", onKey);
  let rt = null;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(renderMosca, 150); });

  let wantExplain = p.get("explain") === "1";
  if (!wantExplain) { try { wantExplain = localStorage.getItem("cd-explain") === "1"; } catch (_) {} }
  if (wantExplain) toggleExplain();

  renderMosca();
  if (pre?.scan) {
    applyScan(pre.scan.scan.id, pre.scan);
    $("scan-path").value = pre.scan.scan.target_value || "";
    await reconcile();
  } else {
    await loadLatest();
  }
}

/* ══ theme ══════════════════════════════════════════════════════════ */

const isDark = () => {
  const s = document.documentElement.getAttribute("data-theme");
  return s ? s === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
};

function initTheme() {
  const forced = new URLSearchParams(location.search).get("theme");
  let saved = null;
  try { saved = localStorage.getItem("cd-theme"); } catch (_) {}
  const pick = (forced === "dark" || forced === "light") ? forced : saved;
  if (pick === "dark" || pick === "light") document.documentElement.setAttribute("data-theme", pick);
  $("theme-toggle").textContent = isDark() ? "Light" : "Dark";
  $("theme-toggle").addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("cd-theme", next); } catch (_) {}
    $("theme-toggle").textContent = isDark() ? "Light" : "Dark";
    renderMosca(); renderFacets(); renderTable();
    if (state.selected) renderDetail(byId(state.selected));
  });
}

function toggleExplain() {
  const on = document.body.classList.toggle("explaining");
  $("explain-toggle").setAttribute("aria-pressed", String(on));
  try { localStorage.setItem("cd-explain", on ? "1" : "0"); } catch (_) {}
}

/* ══ scanning ═══════════════════════════════════════════════════════ */

function buildSensors() {
  const host = $("sensors");
  host.textContent = "";
  for (const [k, label] of Object.entries(SENSOR_LABEL)) {
    const el = document.createElement("span");
    el.className = "sensor"; el.dataset.sensor = k; el.dataset.state = "idle";
    el.append(document.createElement("i"), document.createTextNode(label));
    host.appendChild(el);
  }
}

function reflectSensors(phase) {
  const t = (phase || "").toLowerCase();
  const m = { source: "source code", dependency: "dependency", certificate: "certificate",
              config: "configuration", binary: "binaries", network: "endpoint" };
  const els = Array.from(document.querySelectorAll(".sensor"));
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
  } catch (e) {
    setProgress(0, "Error: " + e.message);
    $("run-scan").disabled = false;
  }
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
      await loadScan(id);
      setTimeout(() => { $("scan-progress").hidden = true; }, 1500);
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
  state.selected = null;
  $("validate-result").hidden = true;
  renderAll();
}

async function reconcile() {
  const m = state.findings[0]?.extra?.mosca;
  if (!m) return;
  const wantZ = state.qday.likely - NOW_YEAR;
  const wantX = state.meta?.sensitivities?.[state.sensitivity];
  if (Math.abs(m.years_to_qday - wantZ) > 0.01
      || (wantX !== undefined && Math.abs(m.shelf_life - wantX) > 0.01)) {
    await recomputeQday(false);
  }
}

async function loadScan(id) { applyScan(id, await api(`/api/scan/${id}`)); await reconcile(); }

/* ══ Q-Day ══════════════════════════════════════════════════════════ */

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
        scan_id: state.scanId, earliest: state.qday.earliest, likely: state.qday.likely,
        latest: state.qday.latest, sensitivity: state.sensitivity, persist: Boolean(persist),
      }),
    });
    const byIdMap = new Map(state.findings.map((f) => [f.id, f]));
    for (const d of data.deltas) {
      const f = byIdMap.get(d.id);
      if (!f) continue;
      f.risk_score = d.risk_score; f.quantum_class = d.quantum_class;
      f.exposure_years = d.exposure_years; f.extra = f.extra || {};
      if (d.mosca) f.extra.mosca = d.mosca;
      if (d.factors) f.extra.factors = d.factors;
    }
    state.summary = data.summary;
    renderAll();
  } catch (e) { console.error("Q-Day recompute failed", e); }
}

/* ══ render ═════════════════════════════════════════════════════════ */

const byId = (id) => state.findings.find((f) => f.id === id);

function renderAll() {
  renderStatus();
  renderFacets();
  renderMosca();
  renderTable();

  // Open on the highest-risk asset rather than an empty pane: the console
  // should show what it does the moment it loads.
  if (!state.selected || !byId(state.selected)) {
    const first = visible()[0];
    if (first) { select(first.id); return; }
  }
  const f = byId(state.selected);
  renderDetail(f || null);
}

function renderStatus() {
  const s = state.summary, st = state.scanMeta?.stats || {};
  $("st-target").textContent = state.scanMeta?.target_label || "no scan";
  if (!s) return;
  const set = (id, label, value) => {
    const el = $(id); el.textContent = "";
    el.append(document.createTextNode(label + " "), Object.assign(document.createElement("b"), { textContent: value }));
  };
  set("st-assets", "assets", String(s.total));
  set("st-vuln", "vulnerable", `${s.quantum_vulnerable} (${s.vulnerable_pct}%)`);
  set("st-crit", "critical", String(s.by_severity?.critical || 0));
  set("st-exposure", "peak exposure", `${s.max_exposure_years} yr`);
  const bits = [];
  if (st.raw_hits) bits.push(`${st.raw_hits.toLocaleString()} hits`);
  if (st.files_scanned) bits.push(`${st.files_scanned.toLocaleString()} files`);
  if (st.sensors_run) bits.push(`${st.sensors_run.length} sensors`);
  if (state.scanMeta?.duration) bits.push(`${state.scanMeta.duration.toFixed(1)}s`);
  $("st-scan").textContent = bits.join(" · ");
}

/* ── facets ────────────────────────────────────────────────────────── */

function facetRow(host, key, value, label, count, colourVar) {
  const row = document.createElement("div");
  row.className = "frow" + (count === 0 ? " off" : "");
  row.setAttribute("role", "button");
  row.tabIndex = 0;
  row.setAttribute("aria-pressed", String(state.filters[key].has(value)));
  const dot = document.createElement("span");
  dot.className = "dot";
  dot.style.background = colourVar ? tok(colourVar) : "transparent";
  const name = document.createElement("span");
  name.className = "fname"; name.textContent = label;
  const n = document.createElement("span");
  n.className = "fn"; n.textContent = count.toLocaleString();
  row.append(dot, name, n);
  const toggle = () => {
    const set = state.filters[key];
    set.has(value) ? set.delete(value) : set.add(value);
    state.selected = null;
    renderFacets(); renderTable(); renderDetail(null);
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
  });
  host.appendChild(row);
}

/** Counts ignore the facet being drawn, so a facet always shows what
 *  selecting it would yield rather than collapsing to its own selection. */
function countsFor(dimension) {
  const out = {};
  for (const f of state.findings) {
    if (!passes(f, dimension)) continue;
    const k = dimension === "cls" ? f.quantum_class
      : dimension === "sev" ? sevOf(f.risk_score)
      : dimension === "sensor" ? f.scanner
      : (f.extra?.context || "production");
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function renderFacets() {
  const cls = countsFor("cls");
  const host1 = $("facet-class"); host1.textContent = "";
  for (const k of CLASS_ORDER) facetRow(host1, "cls", k, CLASS_LABEL[k], cls[k] || 0, CLASS_VAR[k]);

  const sev = countsFor("sev");
  const host2 = $("facet-sev"); host2.textContent = "";
  for (const k of SEV_ORDER) {
    facetRow(host2, "sev", k, k[0].toUpperCase() + k.slice(1), sev[k] || 0, SEV_VAR[k]);
  }

  const sen = countsFor("sensor");
  const host3 = $("facet-sensor"); host3.textContent = "";
  for (const k of Object.keys(SENSOR_LABEL)) facetRow(host3, "sensor", k, SENSOR_LABEL[k], sen[k] || 0, null);

  const ctx = countsFor("ctx");
  const host4 = $("facet-ctx"); host4.textContent = "";
  for (const k of ["production", "vendored", "test"]) facetRow(host4, "ctx", k, k, ctx[k] || 0, null);

  const any = Object.values(state.filters).some((s) => s.size) || $("filter-q").value.trim();
  $("clear-filters").hidden = !any;
}

function clearFilters() {
  for (const s of Object.values(state.filters)) s.clear();
  $("filter-q").value = "";
  state.selected = null;
  renderFacets(); renderTable(); renderDetail(null);
}

/** Does a finding pass every filter except the named dimension? */
function passes(f, except) {
  const F = state.filters;
  if (except !== "cls" && F.cls.size && !F.cls.has(f.quantum_class)) return false;
  if (except !== "sev" && F.sev.size && !F.sev.has(sevOf(f.risk_score))) return false;
  if (except !== "sensor" && F.sensor.size && !F.sensor.has(f.scanner)) return false;
  if (except !== "ctx" && F.ctx.size && !F.ctx.has(f.extra?.context || "production")) return false;
  const q = $("filter-q").value.trim().toLowerCase();
  if (q && !`${f.algorithm} ${f.title} ${f.primary_location}`.toLowerCase().includes(q)) return false;
  return true;
}

/* ── table ─────────────────────────────────────────────────────────── */

function visible() {
  const rows = state.findings.filter((f) => passes(f, null));
  const { key, dir } = state.sort;
  const val = (f) => key === "target" ? (f.recommendation?.target_name || "")
    : key === "quantum_class" ? CLASS_ORDER.indexOf(f.quantum_class)
    : f[key];
  rows.sort((a, b) => {
    const x = val(a), y = val(b);
    if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
    return String(x).localeCompare(String(y)) * dir;
  });
  return rows;
}

function renderTable() {
  const body = $("findings-body");
  body.textContent = "";
  const rows = visible();

  $("findings-hint").textContent = state.findings.length
    ? `${rows.length} of ${state.findings.length}` : "—";

  for (const th of document.querySelectorAll("th.sortable")) {
    const old = th.querySelector(".car");
    if (old) old.remove();
    if (th.dataset.sort === state.sort.key) {
      const c = document.createElement("span");
      c.className = "car"; c.textContent = state.sort.dir < 0 ? "▼" : "▲";
      th.appendChild(c);
    }
  }

  if (!rows.length) {
    const tr = document.createElement("tr");
    tr.className = "empty";
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = state.findings.length ? "Nothing matches the current filters." : "No scan loaded.";
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }

  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.dataset.sev = sevOf(f.risk_score);
    tr.dataset.id = f.id;
    tr.setAttribute("aria-selected", String(state.selected === f.id));

    const cell = (cls, text) => {
      const td = document.createElement("td");
      if (cls) td.className = cls;
      if (text !== undefined) td.textContent = text;
      return td;
    };

    const clsTd = cell();
    const c = document.createElement("span");
    c.className = "cls " + f.quantum_class;
    const dot = document.createElement("span");
    dot.className = "dot";
    dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
    c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
    clsTd.appendChild(c);

    const ev = f.evidence?.[0];
    const where = ev ? (ev.line ? `${ev.location}:${ev.line}` : ev.location) : "";
    const target = f.recommendation?.target_name || "";

    tr.append(
      cell("num risk", f.risk_score.toFixed(0)),
      cell("algo", f.algorithm),
      clsTd,
      cell(null, f.title),
      cell("num", f.occurrences.toLocaleString()),
      cell("sensor-c", SENSOR_LABEL[f.scanner] || f.scanner),
      Object.assign(cell("loc", where), { title: where }),
      Object.assign(cell("to", target), { title: target }),
    );
    tr.addEventListener("click", () => select(f.id));
    frag.appendChild(tr);
  }
  body.appendChild(frag);
}

function select(id) {
  state.selected = id;
  for (const tr of document.querySelectorAll("#findings-body tr")) {
    tr.setAttribute("aria-selected", String(tr.dataset.id === id));
  }
  const row = document.querySelector(`#findings-body tr[data-id="${id}"]`);
  if (row) row.scrollIntoView({ block: "nearest" });
  renderDetail(byId(id));
}

function onKey(e) {
  if (e.target.matches("input, select, textarea")) {
    if (e.key === "Escape") e.target.blur();
    return;
  }
  const rows = visible();
  if (!rows.length) return;
  const i = rows.findIndex((f) => f.id === state.selected);
  if (e.key === "ArrowDown" || e.key === "j") {
    e.preventDefault(); select(rows[Math.min(rows.length - 1, i + 1)].id);
  } else if (e.key === "ArrowUp" || e.key === "k") {
    e.preventDefault(); select(rows[Math.max(0, i <= 0 ? 0 : i - 1)].id);
  } else if (e.key === "Escape") {
    state.selected = null; renderTable(); renderDetail(null);
  } else if (e.key === "/") {
    e.preventDefault(); $("filter-q").focus();
  }
}

/* ── detail pane ───────────────────────────────────────────────────── */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function sec(title) { const s = el("div", "dsec"); s.appendChild(el("h3", null, title)); return s; }
function kv(pairs) {
  const dl = el("dl", "kv");
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, String(v)));
  }
  return dl;
}

function renderDetail(f) {
  const body = $("detail-body"), empty = $("detail-empty");
  if (!f) { body.hidden = true; empty.hidden = false; body.textContent = ""; return; }
  empty.hidden = true; body.hidden = false;
  body.textContent = "";

  const head = el("div", "dhead");
  head.appendChild(el("div", "dtitle", f.algorithm));
  head.appendChild(el("div", "dsub", f.title));
  const meta = el("div", "dmeta");
  const c = el("span", "cls " + f.quantum_class);
  const dot = el("span", "dot");
  dot.style.background = tok(CLASS_VAR[f.quantum_class] || "--unknown");
  c.append(dot, document.createTextNode(CLASS_LABEL[f.quantum_class] || f.quantum_class));
  meta.appendChild(c);
  const sv = el("span", null, `${sevOf(f.risk_score)} · ${f.risk_score.toFixed(1)}`);
  sv.style.color = tok(SEV_VAR[sevOf(f.risk_score)]);
  meta.append(sv, el("span", null, f.extra?.context || "production"));
  head.appendChild(meta);
  body.appendChild(head);

  if (f.detail) { const s = sec("Assessment"); s.appendChild(el("p", "said", f.detail)); body.appendChild(s); }

  const m = f.extra?.mosca;
  if (m) {
    const s = sec("Mosca exposure");
    s.appendChild(kv([
      ["Secrecy (X)", `${m.shelf_life} yr`], ["Migration (Y)", `${m.migration_years} yr`],
      ["To Q-Day (Z)", `${m.years_to_qday} yr`], ["Exposure", `${m.exposure_years} yr`],
      ["P(exposed)", `${(m.probability_exposed * 100).toFixed(0)}%`],
    ]));
    s.appendChild(el("p", "said", m.verdict));
    body.appendChild(s);
  }

  const r = f.recommendation;
  if (r) {
    const s = sec("Recommended migration");
    s.appendChild(kv([
      ["Target", r.target_name], ["Effort", r.effort], ["Hybrid", r.hybrid ? "yes" : "no"],
      ["Size delta", (r.size_delta_bytes === null || r.size_delta_bytes === undefined)
        ? "" : `${r.size_delta_bytes > 0 ? "+" : ""}${r.size_delta_bytes} B`],
      ["Libraries", r.library_support],
    ]));
    if (r.rationale) s.appendChild(el("p", "said", r.rationale));
    if (r.action) s.appendChild(el("p", "said act", r.action));
    if (r.size_note) s.appendChild(el("p", "said warn", r.size_note));
    if (r.agility_note) s.appendChild(el("p", "said", r.agility_note));
    body.appendChild(s);
  }

  const fac = f.extra?.factors;
  if (fac) {
    const s = sec("Score composition");
    s.appendChild(kv(Object.entries(fac).map(([k, v]) => [
      k.replace(/_/g, " "), typeof v === "number" ? String(Number(v.toFixed(3))) : v])));
    body.appendChild(s);
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
  body.appendChild(s);
}

/* ── Mosca strip ───────────────────────────────────────────────────── */

const NS = "http://www.w3.org/2000/svg";
function sv(n, a, t) {
  const e = document.createElementNS(NS, n);
  for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v);
  if (t !== undefined) e.textContent = t;
  return e;
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

  const W = 240, L = 14, R = 6;
  const span = Math.max(X + Y, Z, 8) * 1.04;
  const px = (y) => L + (y / span) * (W - L - R);
  const MONO = "ui-monospace, Menlo, monospace";
  const bad = tok("--crit"), ink3 = tok("--ink-3"), hair = tok("--hair-2");

  if (exposure > 0) {
    svg.appendChild(sv("rect", { x: px(Z), y: 4, width: Math.max(0, px(X + Y) - px(Z)),
      height: 40, fill: bad, opacity: "0.13" }));
  }
  svg.appendChild(sv("line", { x1: L, y1: 46, x2: W - R, y2: 46, stroke: hair, "stroke-width": "1" }));

  const bar = (label, y, x1, x2, colour) => {
    svg.appendChild(sv("text", { x: 0, y: y + 8, fill: ink3, "font-size": "8.5",
      "font-family": MONO }, label));
    svg.appendChild(sv("rect", { x: x1, y, width: Math.max(1.5, x2 - x1), height: 10, rx: 2, fill: colour }));
  };
  bar("Y", 8, px(0), px(Y), tok("--ink-3"));
  bar("X", 26, px(Y), px(Y + X), tok("--weakened"));

  svg.appendChild(sv("line", { x1: px(Z), y1: 2, x2: px(Z), y2: 46,
    stroke: bad, "stroke-width": "1.5", "stroke-dasharray": "3 3" }));

  svg.appendChild(sv("text", { x: L, y: 62, fill: ink3, "font-size": "9",
    "font-family": MONO }, String(NOW_YEAR)));
  const flip = px(Z) > W - 50;
  svg.appendChild(sv("text", { x: px(Z) + (flip ? -4 : 4), y: 62, fill: bad, "font-size": "9",
    "font-family": MONO, "text-anchor": flip ? "end" : "start" }, String(state.qday.likely)));

  $("formula").textContent = `X ${X} + Y ${Y} − Z ${Z} = ${exposure.toFixed(1)} yr`;

  const out = $("mosca-verdict");
  const p = state.findings.reduce((a, f) => Math.max(a, f.extra?.mosca?.probability_exposed || 0), 0);
  if (exposure > 0) {
    out.className = "rverdict";
    out.textContent = `Worst asset stays readable ${exposure.toFixed(1)} yr past Q-Day`
      + (state.findings.length ? ` · P(exposed) ${(p * 100).toFixed(0)}%` : "") + ".";
  } else {
    out.className = "rverdict ok";
    out.textContent = "Within tolerance at these assumptions.";
  }
}

/* ── CBOM ──────────────────────────────────────────────────────────── */

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
  } catch (e) {
    box.className = "banner fail";
    box.textContent = "Validation failed: " + e.message;
  }
}

boot();
