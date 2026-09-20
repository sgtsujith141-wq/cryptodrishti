"""Executive report.

The CBOM is the machine-readable deliverable. This is the human one: what a
CISO or a programme director receives, and what gets attached to a compliance
submission. It answers three questions in order -- how exposed are we, what do
we fix first, and what does fixing it involve.

Self-contained HTML with inline styles and no external assets, so it opens
anywhere, prints to PDF from the browser, and survives an air-gapped network.
"""

from __future__ import annotations

import html
import time
from typing import Any

from . import config
from .engine import risk
from . import models as M
from .knowledge import algorithms as K
from .knowledge import purposes as P
from .models import ScanResult

_CLASS_COLOUR = {
    K.BROKEN: "#B3261E",
    K.WEAKENED: "#8A5806",
    K.SAFE: "#14664C",
    K.HYBRID: "#1B4E82",
    K.UNKNOWN: "#5C6270",
}

_SEV_COLOUR = {
    "critical": "#B3261E", "high": "#B35A00",
    "medium": "#8A6D0B", "low": "#14664C",
}


_ASSURANCE_COLOUR = {
    M.ASSURANCE_CAPABILITY: "#8A8DA8",
    M.ASSURANCE_DECLARED: "#3F7DBF",
    M.ASSURANCE_USED: "#B8860B",
    M.ASSURANCE_OBSERVED: "#B2453C",
}


def _e(v: Any) -> str:
    return html.escape(str(v if v is not None else ""))


def _bar(count: int, total: int, colour: str) -> str:
    pct = (100.0 * count / total) if total else 0.0
    width = max(pct, 0.8 if count else 0)
    return (
        f'<div class="bar"><div class="fill" style="width:{width:.1f}%;'
        f'background:{colour}"></div></div>'
    )


def build(result: ScanResult, summary: dict[str, Any] | None = None) -> str:
    findings = result.findings
    summary = summary or risk.portfolio_summary(findings)
    total = summary["total"] or 1

    generated = time.strftime("%d %B %Y, %H:%M", time.localtime())
    worst = findings[:15]

    # Group the remediation work by recommended target, because that is how a
    # migration programme is actually staffed -- one workstream per target
    # algorithm, not one per finding.
    waves: dict[str, dict[str, Any]] = {}
    for f in findings:
        rec = f.recommendation or {}
        target = rec.get("target_name") or "Manual review required"
        if K.get(f.algorithm).quantum_class in (K.SAFE, K.HYBRID):
            continue
        w = waves.setdefault(target, {
            "assets": 0, "occurrences": 0, "effort": rec.get("effort", "medium"),
            "action": rec.get("action", ""), "max_score": 0.0,
            "capability_only": 0, "unresolved": 0,
        })
        w["assets"] += 1
        w["occurrences"] += f.occurrences
        w["max_score"] = max(w["max_score"], f.risk_score)
        if not f.proves_use:
            w["capability_only"] += 1
        if rec.get("unresolved"):
            w["unresolved"] += 1

    def _wave_caveat(w: dict[str, Any]) -> str:
        notes = []
        if w["capability_only"]:
            notes.append(f"{w['capability_only']} of these are library capability "
                         f"only — confirm a call site before scheduling work")
        if w["unresolved"]:
            notes.append(f"{w['unresolved']} have an unresolved cryptographic purpose")
        return (f"<div class='muted'>{_e('; '.join(notes))}.</div>") if notes else ""

    wave_rows = "".join(
        f"<tr><td><strong>{_e(name)}</strong><div class='muted'>{_e(w['action'])}</div>"
        f"{_wave_caveat(w)}</td>"
        f"<td class='num'>{w['assets']}</td><td class='num'>{w['occurrences']:,}</td>"
        f"<td>{_e(w['effort'])}</td><td class='num'>{w['max_score']:.0f}</td></tr>"
        for name, w in sorted(waves.items(), key=lambda kv: -kv[1]["max_score"])
    )

    # Assurance and purpose breakdowns. These exist so a reader cannot come
    # away with a headline total that silently mixes what the estate runs with
    # what it merely has available.
    assurance_rows = "".join(
        f"<tr><td>{_e(M.ASSURANCE_LABEL[a])}</td>"
        f"<td style='width:38%'>{_bar(summary.get('by_assurance', {}).get(a, 0), total, _ASSURANCE_COLOUR[a])}</td>"
        f"<td class='num'>{summary.get('by_assurance', {}).get(a, 0)}</td>"
        f"<td class='small muted'>{_e(M.ASSURANCE_DESCRIPTION[a])}</td></tr>"
        for a in M.ASSURANCE_ORDER if summary.get("by_assurance", {}).get(a)
    )

    purpose_rows = "".join(
        f"<tr><td>{_e(P.LABEL[k])}</td>"
        f"<td style='width:52%'>{_bar(v, total, '#63667E')}</td>"
        f"<td class='num'>{v}</td></tr>"
        for k, v in sorted(summary.get("by_purpose", {}).items(), key=lambda kv: -kv[1])
        if k in P.LABEL
    )

    finding_rows = "".join(
        f"<tr><td class='num' style='color:{_SEV_COLOUR[risk.severity(f.risk_score)]};"
        f"font-weight:600'>{f.risk_score:.0f}</td>"
        f"<td class='mono'>{_e(f.algorithm)}</td>"
        f"<td><span class='pill' style='color:{_CLASS_COLOUR.get(f.quantum_class, '#555')}'>"
        f"{_e(K.CLASS_LABEL.get(f.quantum_class, f.quantum_class))}</span></td>"
        f"<td>{_e(f.title)}</td>"
        f"<td><span class='pill' style='color:{_ASSURANCE_COLOUR.get(f.assurance, '#555')}'>"
        f"{_e(M.ASSURANCE_LABEL.get(f.assurance, f.assurance))}</span></td>"
        f"<td class='small'>{_e(P.LABEL.get(P.normalise(f.purpose), '—'))}</td>"
        f"<td class='num'>{f.occurrences:,}</td>"
        f"<td class='mono small'>{_e(f.primary_location)}</td>"
        f"<td>{_e((f.recommendation or {}).get('target_name', '') or 'unresolved')}</td></tr>"
        for f in worst
    )

    class_rows = "".join(
        f"<tr><td>{_e(K.CLASS_LABEL.get(c, c))}</td>"
        f"<td style='width:52%'>{_bar(summary['by_class'].get(c, 0), total, _CLASS_COLOUR.get(c, '#888'))}</td>"
        f"<td class='num'>{summary['by_class'].get(c, 0)}</td></tr>"
        for c in K.CLASS_ORDER if summary["by_class"].get(c)
    )

    sev_rows = "".join(
        f"<tr><td>{s.title()}</td>"
        f"<td style='width:52%'>{_bar(summary['by_severity'].get(s, 0), total, _SEV_COLOUR[s])}</td>"
        f"<td class='num'>{summary['by_severity'].get(s, 0)}</td></tr>"
        for s in ("critical", "high", "medium", "low")
    )

    stats = result.stats or {}
    sensors = ", ".join(stats.get("sensors_run", [])) or "source"

    exposure = summary["max_exposure_years"]
    verdict = (
        "Within tolerance at the current assumptions."
        if exposure <= 0 else
        f"Data sealed today remains readable for up to {exposure:.0f} years after a "
        f"cryptographically relevant quantum computer becomes available."
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Cryptographic Risk Assessment — {_e(result.target.label)}</title>
<style>
  @page {{ margin: 18mm; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px 40px 60px; background:#fff; color:#16171F;
         font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .mono {{ font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }}
  .small {{ font-size:11px; }}
  .muted {{ color:#63667E; font-size:11.5px; margin-top:2px; }}
  h1 {{ font-size:24px; margin:0 0 4px; letter-spacing:-0.02em; }}
  h2 {{ font-size:15px; margin:30px 0 10px; padding-bottom:6px; border-bottom:2px solid #16171F; }}
  header {{ border-bottom:3px solid #16171F; padding-bottom:14px; margin-bottom:8px; }}
  .sub {{ color:#63667E; font-size:12.5px; }}
  .tag {{ display:inline-block; background:#16171F; color:#fff; padding:2px 7px;
          border-radius:2px; font-family:ui-monospace,monospace; font-size:11px; letter-spacing:.06em; }}
  .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:#D3D5E1;
           border:1px solid #D3D5E1; margin:18px 0; }}
  .cell {{ background:#fff; padding:11px 13px; }}
  .cell .k {{ font-size:10px; letter-spacing:.11em; text-transform:uppercase; color:#63667E; }}
  .cell .v {{ font-family:ui-monospace,monospace; font-size:25px; font-weight:600; line-height:1.2; }}
  .cell .s {{ font-size:11px; color:#63667E; }}
  .verdict {{ border-left:3px solid #B3261E; background:#F9EDEC; padding:11px 14px; margin:16px 0; font-size:13px; }}
  table {{ border-collapse:collapse; width:100%; font-size:12.5px; }}
  th {{ text-align:left; font-size:10px; letter-spacing:.1em; text-transform:uppercase;
        color:#63667E; font-weight:500; padding:6px 8px; border-bottom:1.5px solid #16171F; }}
  td {{ padding:6px 8px; border-bottom:1px solid #E4E5EE; vertical-align:top; }}
  td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums;
                    font-family:ui-monospace,monospace; white-space:nowrap; }}
  .bar {{ height:9px; background:#EDEEF4; border-radius:2px; overflow:hidden; }}
  .fill {{ height:100%; border-radius:2px; }}
  .pill {{ font-size:11px; font-weight:600; }}
  .cols {{ display:grid; grid-template-columns:1fr 1fr; gap:26px; }}
  footer {{ margin-top:34px; padding-top:12px; border-top:1px solid #D3D5E1;
            font-size:11px; color:#63667E; }}
  @media print {{ body {{ padding:0; }} h2 {{ page-break-after:avoid; }} tr {{ page-break-inside:avoid; }} }}
</style></head><body>

<header>
  <span class="tag">{_e(config.PS_ID)}</span>
  <h1 style="margin-top:8px">Cryptographic Risk Assessment</h1>
  <div class="sub">{_e(result.target.label)} &middot; generated {generated} by
    {_e(config.PRODUCT_NAME)} {_e(config.PRODUCT_VERSION)}</div>
</header>

<div class="grid">
  <div class="cell"><div class="k">Cryptographic assets</div>
    <div class="v">{summary['total']}</div>
    <div class="s">from {stats.get('raw_hits', 0):,} detector observations</div></div>
  <div class="cell"><div class="k">Quantum vulnerable</div>
    <div class="v" style="color:#B3261E">{summary['quantum_vulnerable']}</div>
    <div class="s">{summary['vulnerable_pct']}% of the estate</div></div>
  <div class="cell"><div class="k">Critical</div>
    <div class="v">{summary['by_severity'].get('critical', 0)}</div>
    <div class="s">{summary['by_severity'].get('high', 0)} high severity</div></div>
  <div class="cell"><div class="k">Peak exposure</div>
    <div class="v">{exposure:.1f}</div>
    <div class="s">years readable after Q-Day</div></div>
</div>

<div class="verdict"><strong>Assessment.</strong> {_e(verdict)}
Exposure is computed with Mosca's inequality: the confidentiality lifetime of the
data plus the time required to migrate, measured against the expected arrival of a
cryptographically relevant quantum computer. The arrival year is modelled as a
distribution rather than asserted as a date.</div>

<div class="cols">
  <div><h2>Composition by quantum exposure</h2>
    <table>{class_rows}</table></div>
  <div><h2>Composition by severity</h2>
    <table>{sev_rows}</table></div>
</div>

<h2>Migration programme</h2>
<p class="sub" style="margin:0 0 10px">Work grouped by target algorithm, which is how a
migration is staffed: one workstream per replacement, not one per finding.</p>
<table>
  <thead><tr><th>Recommended target and action</th><th class="num">Assets</th>
    <th class="num">Call sites</th><th>Effort</th><th class="num">Peak risk</th></tr></thead>
  <tbody>{wave_rows or '<tr><td colspan="5">No migration required.</td></tr>'}</tbody>
</table>

<h2>Highest-risk findings</h2>
<table>
  <thead><tr><th class="num">Score</th><th>Algorithm</th><th>Exposure class</th>
    <th>Finding</th><th>Assurance</th><th>Purpose</th><th class="num">Uses</th>
    <th>First location</th><th>Migrate to</th></tr></thead>
  <tbody>{finding_rows}</tbody>
</table>

<h2>What the evidence establishes</h2>
<p class="sub">Confidence asks whether an identification is correct. Assurance asks
what a correct identification proves. A dependency on a library that implements RSA
can be a certain identification of something that shows only that RSA is reachable,
and a total that mixes the two describes an estate that does not exist.</p>
<table>{assurance_rows or '<tr><td>No findings.</td></tr>'}</table>
<p class="sub"><strong>{summary.get('proven_use', 0)}</strong> of
{summary.get('total', 0)} assets are backed by a call site or a live observation;
<strong>{summary.get('capability_only', 0)}</strong> are reachable capability or
declared configuration only.</p>

<h2>Cryptographic purpose</h2>
<p class="sub">The replacement for an algorithm depends on what it is used for, not
on its name. RSA signing is replaced by ML-DSA and RSA key transport by ML-KEM;
neither substitutes for the other. Where the evidence did not establish the purpose,
the asset is listed as unresolved and no target is named.</p>
<table>{purpose_rows or '<tr><td>No findings.</td></tr>'}</table>
<p class="sub"><strong>{summary.get('unresolved_purpose', 0)}</strong> assets have an
unresolved purpose and need a human to determine it before they can be scheduled.</p>

<h2>Method and limitations</h2>
<table>
  <tr><td style="width:34%"><strong>Sensors run</strong></td><td class="mono">{_e(sensors)}</td></tr>
  <tr><td><strong>Scan duration</strong></td><td class="mono">{result.duration:.1f} seconds</td></tr>
  <tr><td><strong>Machine-readable output</strong></td>
      <td>CycloneDX 1.6 CBOM, standardised as ECMA-424</td></tr>
  <tr><td><strong>Confidence</strong></td>
      <td>Every finding carries a per-detector confidence score. Artefacts that could
      not be resolved to a specific algorithm are reported as <em>unresolved</em>
      rather than inferred. Confidence is the strongest single piece of evidence and
      is never raised by repetition: forty matches from one rule are forty chances for
      that rule to be wrong in the same way, not independent corroboration.</td></tr>
  <tr><td><strong>Certificate trust</strong></td>
      <td>Parsing a certificate establishes what it contains, never that it is
      trusted. Where trust was tested, it was tested by a separate verifying
      handshake and is reported as its own result.</td></tr>
  <tr><td><strong>Known limitations</strong></td>
      <td>Detection for languages other than Python uses pattern rules rather than full
      parsing, which lowers precision. Cryptography executing inside a hardware security
      module or a managed key service is enumerated at its boundary only. Findings in
      test fixtures are inventoried but weighted down, so they do not lead the
      remediation queue.</td></tr>
</table>

<footer>
  Prepared for problem statement {_e(config.PS_ID)} &middot; {_e(config.PS_ORG)}.
  Risk scores are a transparent product of named factors -- quantum exposure class,
  data sensitivity, blast radius, detector confidence and the Mosca gap -- each of
  which is visible against its input value in the analysis console.
</footer>

</body></html>"""
