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


def _optional_row(label: str, value: str) -> str:
    """A table row, or nothing at all when there is nothing to say."""
    if not value:
        return ""
    return (f"<tr><td><strong>{_e(label)}</strong></td>"
            f"<td class='mono'>{_e(value)}</td></tr>")


def _status_cell(stats: dict[str, Any]) -> str:
    """Complete or partial, and why. Never silently complete."""
    if stats.get("complete", True):
        return ("<strong>Complete.</strong> Every selected sensor ran to "
                "completion and nothing was refused.")
    reasons = stats.get("incomplete_reasons") or ["reason not recorded"]
    items = "".join(f"<li>{_e(r)}</li>" for r in reasons)
    return (f"<strong class='bad'>PARTIAL — this inventory is incomplete.</strong>"
            f"<ul class='reasons'>{items}</ul>"
            f"<div class='muted'>Absence of a finding below is not evidence of "
            f"absence in the estate.</div>")


def _sensor_error_rows(stats: dict[str, Any]) -> str:
    errors = stats.get("sensor_errors") or {}
    if not errors:
        return ""
    items = "".join(f"<li><span class='mono'>{_e(name)}</span> — {_e(msg)}</li>"
                    for name, msg in errors.items())
    return (f"<tr><td><strong>Sensor failures</strong></td>"
            f"<td><ul class='reasons'>{items}</ul></td></tr>")


def _refusal_rows(stats: dict[str, Any]) -> str:
    """Policy refusals: endpoints, filesystem paths and archive members."""
    rows = []

    endpoints = stats.get("endpoints_refused") or []
    if endpoints:
        items = "".join(
            f"<li><span class='mono'>{_e(r.get('destination', ''))}</span> — "
            f"{_e(r.get('reason', ''))}</li>" for r in endpoints[:20])
        rows.append(f"<tr><td><strong>Endpoints refused</strong></td>"
                    f"<td><ul class='reasons'>{items}</ul></td></tr>")

    skipped = (stats.get("filesystem_policy") or {}).get("skipped") or {}
    if skipped:
        items = "".join(f"<li>{v} × {_e(k)}</li>" for k, v in skipped.items())
        rows.append(f"<tr><td><strong>Paths skipped by policy</strong></td>"
                    f"<td><ul class='reasons'>{items}</ul></td></tr>")

    archive = (stats.get("container_archive_stats") or {}).get("refused") or {}
    if archive:
        items = "".join(f"<li>{v} × {_e(k)}</li>" for k, v in archive.items())
        rows.append(f"<tr><td><strong>Archive members refused</strong></td>"
                    f"<td><ul class='reasons'>{items}</ul></td></tr>")
    return "".join(rows)


def _coverage_rows(stats: dict[str, Any]) -> str:
    """What the scan could and could not read, stated rather than implied."""
    rows = []
    if stats.get("container_format"):
        rows.append(
            f"<tr><td><strong>Image</strong></td><td>"
            f"<span class='mono'>{_e(stats.get('container_image', ''))}</span>"
            f"<div class='muted'>{_e(stats.get('container_format_description', ''))} · "
            f"{stats.get('container_layers', 0)} layer(s) · "
            f"{stats.get('container_files_analysed', 0)} file(s) analysed</div></td></tr>")
        rows.append(
            "<tr><td><strong>Formats not supported</strong></td><td class='muted'>"
            "Registry pulls, Windows images, zstd-compressed layers, and "
            "signature or attestation verification are out of scope and were "
            "not attempted.</td></tr>")
    if stats.get("files_scanned") is not None:
        rows.append(
            f"<tr><td><strong>Files read</strong></td>"
            f"<td class='mono'>{stats.get('files_scanned', 0):,}"
            f"{' of ' + format(stats['files_enumerated'], ',') + ' enumerated' if stats.get('files_enumerated') else ''}"
            f"</td></tr>")
    return "".join(rows)


def _correlation_section(findings: list, stats: dict[str, Any]) -> str:
    """Logical assets the evidence linked, and where linked evidence disagrees."""
    assets = stats.get("logical_assets") or []
    if not assets:
        return ""
    rows = []
    for a in assets[:40]:
        conflicts = "".join(f"<div class='muted warn'>{_e(c)}</div>"
                            for c in (a.get("conflicts") or []))
        rows.append(
            f"<tr><td class='mono'>{_e(a.get('algorithm', ''))}"
            f"<div class='muted'>{_e(a.get('purpose', ''))}</div></td>"
            f"<td class='mono small'>{_e(', '.join(a.get('basis') or []))}</td>"
            f"<td class='small'>{_e(', '.join(a.get('detectors') or []))}</td>"
            f"<td class='small'>{_e(str(a.get('assurance_states') or {}))}"
            f"{'<div class=\'muted\'>capability corroborated by observed use</div>' if a.get('corroborated_by_use') else ''}"
            f"{conflicts}</td></tr>")
    return (
        "<h2>Correlated evidence</h2>"
        "<p class='sub'>Findings that more than one detector appears to have seen. "
        "A link records agreement; it never merges the findings, never raises "
        "confidence and never promotes a declared capability to an observation. "
        "Disagreements between linked findings are shown rather than resolved.</p>"
        "<table><thead><tr><th>Algorithm / purpose</th><th>Linked by</th>"
        "<th>Detectors</th><th>Evidence states</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>")


def _chain_block(f) -> str:
    """One asset's complete chain: evidence to action, nothing skipped."""
    extra = f.extra or {}
    rec = f.recommendation or {}
    mosca = extra.get("mosca") or {}
    model = extra.get("exposure_model") or {}
    inputs = extra.get("risk_inputs") or {}
    container = extra.get("container") or {}
    link = extra.get("correlation") or {}

    evidence_items = "".join(
        f"<li><span class='mono'>{_e(e.location)}"
        f"{':' + str(e.line) if e.line else ''}</span>"
        f"<span class='muted'> · {_e(e.technique)} · {_e(e.assurance)} · "
        f"confidence {e.confidence:.2f}</span></li>"
        for e in f.evidence[:12])
    more = (f"<li class='muted'>… and {f.occurrences - 12:,} further occurrence(s)</li>"
            if f.occurrences > 12 else "")

    input_rows = "".join(
        f"<tr><td>{_e(name.replace('_', ' '))}</td>"
        f"<td class='mono'>{_e(v.get('value'))}</td>"
        f"<td><span class='prov prov-{_e(v.get('provenance'))}'>"
        f"{_e(v.get('provenance'))}</span></td>"
        f"<td class='muted small'>{_e(v.get('source'))}</td></tr>"
        for name, v in sorted(inputs.items()))

    unknowns = "".join(f"<li>{_e(u)}</li>" for u in (rec.get("unknowns") or []))
    validation = "".join(f"<li>{_e(v)}</li>" for v in (rec.get("validation_steps") or []))
    compat = "".join(f"<li>{_e(c)}</li>" for c in (rec.get("compatibility") or []))
    warnings = "".join(f"<li class='warn'>{_e(w)}</li>"
                       for w in (rec.get("constraint_warnings") or []))

    state = ""
    if container:
        effective = container.get("effective")
        label = ("in the image's final filesystem" if effective
                 else "historical layer only — not running, but still "
                      "extractable from the image archive")
        state = (f"<div class='chain-state{'' if effective else ' warn'}'>"
                 f"Container: <span class='mono'>{_e(container.get('image', ''))}"
                 f":/{_e(container.get('path', ''))}</span> · layer "
                 f"{_e(container.get('layer_index'))} · {_e(label)}</div>")

    target = rec.get("target_name") or "—"
    if rec.get("unresolved"):
        target = f"{target} (no target named)"

    return f"""
<article class="chain">
  <header class="chain-h">
    <span class="chain-score" style="color:{_SEV_COLOUR[risk.severity(f.risk_score)]}">{f.risk_score:.0f}</span>
    <span class="chain-alg mono">{_e(f.algorithm)}</span>
    <span class="pill" style="color:{_CLASS_COLOUR.get(f.quantum_class, '#555')}">{_e(K.CLASS_LABEL.get(f.quantum_class, f.quantum_class))}</span>
    <span class="chain-title">{_e(f.title)}</span>
  </header>
  {state}

  <div class="chain-step"><h4>1 · Detection evidence</h4>
    <ul class="ev">{evidence_items}{more}</ul>
    <p class="muted">{_e(rec.get('evidence_summary', ''))}</p></div>

  <div class="chain-step"><h4>2 · Purpose and assurance</h4>
    <p>Purpose: <strong>{_e(P.LABEL.get(P.normalise(f.purpose), f.purpose))}</strong>
       {('— ' + _e(f.purpose_evidence)) if f.purpose_evidence else ''}</p>
    <p>Assurance: <strong>{_e(M.ASSURANCE_LABEL.get(f.assurance, f.assurance))}</strong>
       · confidence {f.confidence:.2f}
       <span class="muted">{_e(M.ASSURANCE_DESCRIPTION.get(f.assurance, ''))}</span></p></div>

  <div class="chain-step"><h4>3 · Quantum classification</h4>
    <p>{_e(K.CLASS_DESCRIPTION.get(f.quantum_class, ''))}</p>
    <p class="muted">{_e(rec.get('exposure_explanation', ''))}</p></div>

  <div class="chain-step"><h4>4 · Risk inputs and assumptions</h4>
    <p class="muted">Exposure model: <strong>{_e(model.get('label', '—'))}</strong>.
       X means {_e(model.get('x_label', '—'))}.
       {_e(model.get('assumptions', ''))}</p>
    <table class="inputs-t"><thead><tr><th>Input</th><th>Value</th>
      <th>Origin</th><th>Why</th></tr></thead><tbody>{input_rows}</tbody></table>
    <p class="muted">X {_e(mosca.get('shelf_life'))} + Y {_e(mosca.get('migration_years'))}
       − Z {_e(mosca.get('years_to_qday'))} = <strong>{_e(mosca.get('exposure_years'))} years exposed</strong>.
       Probability {_e(mosca.get('probability_exposed'))} — {_e(mosca.get('conditional_on', ''))}</p></div>

  <div class="chain-step"><h4>5 · Recommended alternative</h4>
    <p>Target: <strong>{_e(target)}</strong> · effort {_e(rec.get('effort', '—'))}</p>
    <p class="muted">{_e(rec.get('rationale', ''))}</p>
    {('<ul class="ev">' + compat + '</ul>') if compat else ''}
    {('<ul class="ev">' + warnings + '</ul>') if warnings else ''}
    <p class="muted">Latency: <strong>{_e((rec.get('latency') or {}).get('status', 'unknown'))}</strong>.
       Cost: <strong>{_e((rec.get('cost') or {}).get('status', 'unknown'))}</strong>.
       Neither is estimated by this tool.</p></div>

  <div class="chain-step"><h4>6 · Action and validation</h4>
    <p>{_e(rec.get('action', ''))}</p>
    {('<p class="warn">' + _e(rec.get('validate_before', '')) + '</p>') if rec.get('validate_before') else ''}
    {('<ul class="ev">' + validation + '</ul>') if validation else ''}
    {('<h5>Unresolved</h5><ul class="ev">' + unknowns + '</ul>') if unknowns else ''}
    {('<p class="muted">Correlated with ' + _e(', '.join(link.get('peer_detectors') or [])) + ' via ' + _e(', '.join(link.get('basis') or [])) + '. This link does not change the assurance above.</p>') if link else ''}
  </div>
</article>"""


def _full_inventory(findings: list) -> str:
    if not findings:
        return "<p class='sub'>No cryptographic assets were found.</p>"
    return "".join(_chain_block(f) for f in findings)


def build(result: ScanResult, summary: dict[str, Any] | None = None) -> str:
    findings = result.findings
    summary = summary or risk.portfolio_summary(findings)
    total = summary["total"] or 1

    generated = time.strftime("%d %B %Y, %H:%M", time.localtime())
    worst = findings[:15]
    # The executive table shows the worst; the full inventory below shows
    # everything. A report that only ever shows fifteen rows of an estate with
    # four hundred assets is a summary being passed off as an inventory.
    full = findings

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

    from .engine import risk as _risk

    # The date the findings were assessed on, read off the findings. Calling
    # assessment_date() here would restate *today*, so a report regenerated in
    # 2029 from a 2026 assessment would claim to be a 2029 assessment. Only
    # when nothing carries a date do we fall back to today, and a scan with no
    # scored findings has no assessment to misrepresent.
    assessed_on = next(
        (f.extra["assessment"]["assessed_on"] for f in findings
         if (f.extra or {}).get("assessment", {}).get("assessed_on")),
        _risk.assessment_date().isoformat())

    # The Q-Day scenario every number below is conditional on, read off the
    # findings rather than re-derived, so the report cannot disagree with the
    # assessment it is reporting.
    sample = next((f.extra.get("assessment") for f in findings
                   if (f.extra or {}).get("assessment")), None)
    qday = (sample or {}).get("qday") or {}
    overrides_applied = sum(
        1 for f in findings
        if ((f.extra or {}).get("assessment") or {}).get("override_applied"))
    defaulted = sum(
        1 for f in findings
        if any(v.get("provenance") == "default"
               for v in ((f.extra or {}).get("risk_inputs") or {}).values()))

    # Container deployment state, where the scan had one.
    historical = [f for f in findings
                  if ((f.extra or {}).get("container") or {}).get("effective") is False]

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
  /* Full inventory: one block per asset, each a traceable chain. Sized to
     break cleanly when the browser prints to PDF. */
  .chain {{ border:1px solid #D3D5E1; border-left:3px solid #16171F; padding:12px 14px;
           margin:14px 0; break-inside:avoid; page-break-inside:avoid; }}
  .chain-h {{ display:flex; align-items:baseline; gap:10px; flex-wrap:wrap;
             border-bottom:1px solid #E7E8F0; padding-bottom:7px; margin-bottom:9px; }}
  .chain-score {{ font-size:19px; font-weight:700; min-width:2.1em; }}
  .chain-alg {{ font-size:13px; font-weight:600; }}
  .chain-title {{ color:#63667E; font-size:12.5px; }}
  .chain-state {{ font-size:11.5px; color:#63667E; margin:-3px 0 9px; }}
  .chain-state.warn {{ color:#B2453C; }}
  .chain-step {{ margin:9px 0; }}
  .chain-step h4 {{ font-size:11px; letter-spacing:.09em; text-transform:uppercase;
                   color:#8A8DA8; margin:0 0 4px; font-weight:600; }}
  .chain-step h5 {{ font-size:11px; margin:7px 0 3px; color:#63667E; }}
  .chain-step p {{ margin:3px 0; font-size:12.5px; }}
  ul.ev {{ margin:4px 0; padding-left:17px; font-size:11.5px; }}
  ul.ev li {{ margin:2px 0; }}
  ul.reasons {{ margin:3px 0; padding-left:17px; font-size:11.5px; }}
  .warn {{ color:#B2453C; }}
  .bad {{ color:#B2453C; }}
  table.inputs-t {{ font-size:11.5px; margin:5px 0; }}
  table.inputs-t th {{ font-size:10px; letter-spacing:.06em; text-transform:uppercase;
                      color:#8A8DA8; }}
  .prov {{ font-family:ui-monospace,monospace; font-size:9.5px; text-transform:uppercase;
          letter-spacing:.04em; border:1px solid currentColor; border-radius:2px;
          padding:0 3px; white-space:nowrap; }}
  .prov-observed {{ color:#16171F; }} .prov-operator {{ color:#2F7D52; }}
  .prov-derived  {{ color:#63667E; }} .prov-default  {{ color:#8A8DA8; }}

  /* Print: the report is meant to survive Ctrl-P without a service. */
  @media print {{
    body {{ padding:0; }}
    h2 {{ break-after:avoid; page-break-after:avoid; }}
    .chain {{ break-inside:avoid; page-break-inside:avoid; }}
    table {{ break-inside:auto; }}
    tr {{ break-inside:avoid; page-break-inside:avoid; }}
  }}

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

<h2>Assumptions this assessment rests on</h2>
<p class="sub">Everything below is conditional on these inputs. They are
assumptions, not measurements, and they are stated first because a risk number
quoted without them is not a risk number.</p>
<table>
  <tr><td style="width:34%"><strong>Assessment date</strong></td>
      <td class="mono">{_e(assessed_on)}</td></tr>
  <tr><td><strong>Q-Day scenario</strong></td>
      <td>Earliest <strong>{_e(str(qday.get('earliest', '—')))}</strong>,
          most likely <strong>{_e(str(qday.get('likely', '—')))}</strong>,
          latest <strong>{_e(str(qday.get('latest', '—')))}</strong>.
          <div class="muted">"Most likely" is the <em>mode</em> of a triangular
          distribution — its peak — not its median. The median of this scenario is
          {_e(str(qday.get('median_year', '—')))}. Exposure below is computed at the
          {_e(str(qday.get('basis', 'mode')))}.</div></td></tr>
  <tr><td><strong>Is this a forecast?</strong></td>
      <td><strong>No.</strong> Nobody knows when, or whether, a cryptographically
      relevant quantum computer will exist. This is an operator-selected scenario;
      every probability in this report is conditional on it and on nothing else.</td></tr>
  <tr><td><strong>Operator-supplied inputs</strong></td>
      <td>{overrides_applied} of {summary.get('total', 0)} assets have inputs a person
      set by hand. {defaulted} still rest on at least one unreviewed default —
      treat those scores as provisional.</td></tr>
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

<h2>Deployment state</h2>
<p class="sub">An artefact in a container image layer that a later layer deleted is
not running — but it is still extractable from the image archive by anyone who can
pull it. Neither "active file" nor "not there" describes it, so it is reported as
what it is.</p>
<table>
  <tr><td style="width:34%"><strong>Historical-layer artefacts</strong></td>
      <td><strong>{len(historical)}</strong>
      {"— listed in the inventory, scored at reduced weight, and never described as part of the running filesystem." if historical else "— none in this scan."}</td></tr>
  {"".join(
      f"<tr><td class='mono small'>{_e((f.extra.get('container') or {}).get('path',''))}</td>"
      f"<td>{_e(f.title)}<div class='muted'>removed by layer "
      f"{_e(str((f.extra.get('container') or {}).get('superseded_by_layer','?')))} — "
      f"recoverable from the archive</div></td></tr>"
      for f in historical[:10])}
</table>

<h2>Scan integrity and coverage</h2>
<p class="sub">What this scan actually read, and what it did not. An
inventory whose gaps are not stated reads as though it had none.</p>
<table>
  <tr><td style="width:34%"><strong>Target</strong></td>
      <td class="mono">{_e(result.target.value)}<div class="muted">{_e(result.target.kind)}</div></td></tr>
  <tr><td><strong>Status</strong></td>
      <td>{_status_cell(stats)}</td></tr>
  <tr><td><strong>Sensors run</strong></td><td class="mono">{_e(sensors)}</td></tr>
  {_optional_row("Sensors skipped", ", ".join(stats.get("sensors_skipped") or []))}
  {_sensor_error_rows(stats)}
  {_refusal_rows(stats)}
  {_coverage_rows(stats)}
  <tr><td><strong>Raw detector hits</strong></td>
      <td class="mono">{stats.get('raw_hits', 0):,} hits &rarr; {len(findings):,} distinct assets after normalisation</td></tr>
</table>

{_correlation_section(findings, stats)}

<h2>Complete inventory — every asset, with its full evidence chain</h2>
<p class="sub">All {len(full):,} assets, each traced from the evidence that
found it through to the action it implies. The summary above is a ranking of
these, not a different set.</p>
{_full_inventory(full)}

<h2>Method and limitations</h2>
<table>
  <tr><td style="width:34%"><strong>Sensors run</strong></td><td class="mono">{_e(sensors)}</td></tr>
  <tr><td><strong>Scan duration</strong></td><td class="mono">{result.duration:.1f} seconds</td></tr>
  <tr><td><strong>Machine-readable output</strong></td>
      <td>CycloneDX 1.6 CBOM, standardised as ECMA-424. Validated
      <em>structurally</em> — required fields, enum membership, reference
      integrity — not against the official JSON Schema.</td></tr>
  <tr><td><strong>Latency and cost</strong></td>
      <td>Not estimated anywhere in this report. This tool has never run a
      benchmark or priced an engineer; published post-quantum latency figures
      vary by more than an order of magnitude across platforms. Measure on your
      own hardware. Migration effort is given as a band, not a number.</td></tr>
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
