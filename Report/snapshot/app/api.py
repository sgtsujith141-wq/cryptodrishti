"""HTTP API and static console.

Scans run in a background thread so the console stays responsive and can show
progress; the alternative -- a synchronous request that blocks for thirty
seconds -- is unusable in a live demonstration.

Every route is local. The application makes no outbound network connections
except when a scan explicitly probes a host the operator named.
"""

from __future__ import annotations

import json
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import cbom, config, orchestrator, report, store
from .engine import recommend, risk
from .knowledge import algorithms as K
from .models import ScanResult, ScanTarget

app = FastAPI(title=config.PRODUCT_NAME, version=config.PRODUCT_VERSION)

# In-flight scan progress, keyed by scan id.
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------

class ScanRequest(BaseModel):
    path: str
    label: str = ""
    profile: str = recommend.PROFILE_GENERAL
    max_files: int = 0
    sensors: list[str] | None = None
    endpoints: list[str] = []


class QDayRequest(BaseModel):
    scan_id: str
    earliest: int = config.QDAY_EARLIEST
    likely: int = config.QDAY_LIKELY
    latest: int = config.QDAY_LATEST
    sensitivity: str = config.DEFAULT_SENSITIVITY
    # A slider drag fires many of these. Persisting each one writes the whole
    # scan back to disk for a value the operator is still moving, so the
    # default is to recompute without saving and persist only on release.
    persist: bool = False


# --------------------------------------------------------------------------
# Scan execution
# --------------------------------------------------------------------------

def _set_job(scan_id: str, **fields: Any) -> None:
    with _JOBS_LOCK:
        _JOBS.setdefault(scan_id, {}).update(fields)


def _run_scan(scan_id: str, req: ScanRequest) -> None:
    try:
        root = Path(req.path).expanduser().resolve()
        if not root.exists():
            _set_job(scan_id, state="error", error=f"Path not found: {root}")
            return

        _set_job(scan_id, state="running", phase="Starting sensors", progress=3,
                 detail="", tick=0)

        # `tick` increments on every report. The console watches it to tell a
        # slow sensor apart from a stalled one, which a percentage alone cannot.
        counter = {"n": 0}

        def progress(pct: int, phase: str, detail: str = "") -> None:
            counter["n"] += 1
            _set_job(scan_id, progress=pct, phase=phase, detail=detail,
                     tick=counter["n"])

        result = orchestrator.scan_target(
            root,
            label=req.label,
            endpoints=req.endpoints,
            sensors=req.sensors,
            profile=req.profile,
            max_files=req.max_files,
            progress=progress,
        )
        result.id = scan_id

        summary = risk.portfolio_summary(result.findings)
        store.save_scan(result, summary)

        _set_job(scan_id, state="done", progress=100, phase="Complete", detail="",
                 tick=counter["n"] + 1,
                 findings=len(result.findings), duration=round(result.duration, 2))
    except Exception as exc:                      # surface the real error
        _set_job(scan_id, state="error", error=str(exc),
                 trace=traceback.format_exc()[-2000:])


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> dict[str, Any]:
    result = ScanResult(target=ScanTarget(kind="repository", value=req.path))
    scan_id = result.id
    _set_job(scan_id, state="queued", progress=0, phase="Queued",
             label=req.label or Path(req.path).name)
    threading.Thread(target=_run_scan, args=(scan_id, req), daemon=True).start()
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}/status")
def scan_status(scan_id: str) -> dict[str, Any]:
    with _JOBS_LOCK:
        job = dict(_JOBS.get(scan_id, {}))
    if not job:
        # Not in memory: it may be a scan from a previous run of the server.
        if store.get_scan(scan_id):
            return {"state": "done", "progress": 100, "phase": "Complete"}
        raise HTTPException(status_code=404, detail="Unknown scan")
    return job


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

@app.get("/api/scans")
def list_scans() -> dict[str, Any]:
    return {"scans": store.list_scans()}


def scan_payload(scan_id: str, min_score: float = 0.0, quantum_class: str = "",
                 scanner: str = "", context: str = "", q: str = "",
                 rescore_default: bool = False) -> dict[str, Any]:
    """Build the console's view of a scan.

    A plain function rather than only a route, so the index page can inline the
    same payload -- calling a FastAPI route directly would hand it Query objects
    instead of values.
    """
    meta_row = store.get_scan(scan_id)
    if not meta_row:
        raise HTTPException(status_code=404, detail="Unknown scan")

    findings = store.get_findings(scan_id)

    if rescore_default:
        # A stored scan carries whatever Q-Day it was last scored under. The
        # console opens with the slider at the configured default, so score the
        # inlined copy to match -- otherwise the first paint contradicts the
        # control right beside it.
        for f in findings:
            f.sensitivity = config.DEFAULT_SENSITIVITY
            f.extra.pop("mosca", None)
            f.extra.pop("factors", None)
        risk.score_all(findings, risk.QDayModel())
        findings.sort(key=lambda f: -f.risk_score)

    def keep(f) -> bool:
        if f.risk_score < min_score:
            return False
        if quantum_class and f.quantum_class != quantum_class:
            return False
        if scanner and f.scanner != scanner:
            return False
        if context and f.extra.get("context") != context:
            return False
        if q:
            hay = " ".join([f.algorithm, f.title, f.primary_location]).lower()
            if q.lower() not in hay:
                return False
        return True

    filtered = [f for f in findings if keep(f)]
    return {
        "scan": meta_row,
        "summary": risk.portfolio_summary(findings),
        "filtered_summary": risk.portfolio_summary(filtered),
        "findings": [f.to_dict() for f in filtered],
        "severity_of": {f.id: risk.severity(f.risk_score) for f in filtered},
    }


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str,
             min_score: float = Query(0.0),
             quantum_class: str = Query(""),
             scanner: str = Query(""),
             context: str = Query(""),
             q: str = Query("")) -> dict[str, Any]:
    return scan_payload(scan_id, min_score, quantum_class, scanner, context, q)


@app.post("/api/qday")
def recompute_qday(req: QDayRequest) -> dict[str, Any]:
    """Re-score an existing scan under a different Q-Day assumption.

    This is the interaction that makes Mosca's inequality tangible: move the
    arrival estimate and watch the whole estate re-rank. It therefore has to
    feel instant, which is why the response carries only what changed --
    scores and their Mosca terms -- rather than every finding with its full
    evidence, which is roughly fifty times larger.
    """
    result = store.load_result(req.scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Unknown scan")

    if not (req.earliest <= req.likely <= req.latest):
        raise HTTPException(status_code=400,
                            detail="Require earliest <= likely <= latest")

    model = risk.QDayModel(earliest=req.earliest, likely=req.likely, latest=req.latest)
    for f in result.findings:
        f.sensitivity = req.sensitivity
        f.extra.pop("mosca", None)
        f.extra.pop("factors", None)
    risk.score_all(result.findings, model)
    result.findings.sort(key=lambda f: -f.risk_score)

    summary = risk.portfolio_summary(result.findings)

    if req.persist:
        store.save_scan(result, summary)

    return {
        "summary": summary,
        "qday": model.to_dict(),
        "sensitivity": req.sensitivity,
        "order": [f.id for f in result.findings],
        "deltas": [
            {
                "id": f.id,
                "risk_score": f.risk_score,
                "quantum_class": f.quantum_class,
                "exposure_years": f.exposure_years,
                "mosca": f.extra.get("mosca"),
                "factors": f.extra.get("factors"),
            }
            for f in result.findings
        ],
    }


# --------------------------------------------------------------------------
# CBOM export
# --------------------------------------------------------------------------

@app.get("/api/scan/{scan_id}/cbom")
def get_cbom(scan_id: str, download: bool = Query(False)) -> Response:
    result = store.load_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Unknown scan")
    doc = cbom.build(result)
    body = json.dumps(doc, indent=2)
    headers = {}
    if download:
        name = (result.target.label or "cbom").replace(" ", "-").lower()
        headers["Content-Disposition"] = f'attachment; filename="{name}-cbom.json"'
    return Response(content=body, media_type="application/json", headers=headers)


@app.get("/api/scan/{scan_id}/report")
def get_report(scan_id: str, download: bool = Query(False)) -> Response:
    """Executive report: the deliverable for a human decision maker."""
    result = store.load_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Unknown scan")
    meta = store.get_scan(scan_id) or {}
    body = report.build(result, meta.get("summary") or None)
    headers = {}
    if download:
        name = (result.target.label or "report").replace(" ", "-").lower()
        headers["Content-Disposition"] = f'attachment; filename="{name}-crypto-risk.html"'
    return HTMLResponse(content=body, headers=headers)


@app.get("/api/scan/{scan_id}/cbom/validate")
def validate_cbom(scan_id: str) -> dict[str, Any]:
    result = store.load_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Unknown scan")
    doc = cbom.build(result)
    ok, problems = cbom.validate(doc)
    return {
        "valid": ok,
        "spec": f"CycloneDX {cbom.SPEC_VERSION} (ECMA-424)",
        "components": len(doc["components"]),
        "problems": problems,
        "note": ("Structural conformance check: required fields, enum membership and "
                 "bom-ref uniqueness. Not a full JSON-Schema validation."),
    }


# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# ── directory browser ───────────────────────────────────────────────
# The tool is only useful if it can be pointed at anything on the machine, and
# typing an absolute path from memory is not something to do on stage. This
# walks the local filesystem server-side, which keeps the whole thing offline.

_REPO_MARKERS = (".git", "package.json", "setup.py", "pyproject.toml", "go.mod",
                 "Cargo.toml", "pom.xml", "build.gradle", "CMakeLists.txt", "Makefile")


_KIND_BY_MARKER = (
    (".git", "git repository"), ("pyproject.toml", "python"), ("setup.py", "python"),
    ("requirements.txt", "python"), ("package.json", "node"), ("go.mod", "go"),
    ("Cargo.toml", "rust"), ("pom.xml", "java / maven"), ("build.gradle", "java / gradle"),
    ("CMakeLists.txt", "c / cmake"), ("Makefile", "make"),
)


def _describe(d: Path) -> dict[str, Any]:
    """Label a directory by probing for a handful of marker files.

    This used to list every child directory in full, which meant browsing a
    home folder walked Library and Downloads end to end and appeared to hang.
    A dozen stat calls per entry is bounded work no matter how large the
    directory turns out to be.
    """
    kind = ""
    for marker, label in _KIND_BY_MARKER:
        try:
            if (d / marker).exists():
                kind = label
                break
        except OSError:
            kind = "unreadable"
            break
    return {"name": d.name, "path": str(d), "kind": kind}


@app.get("/api/browse")
def browse(path: str = Query("")) -> dict[str, Any]:
    """List the directories inside `path`, for the console's folder picker."""
    base = Path(path).expanduser() if path else Path.home()
    try:
        base = base.resolve()
    except OSError:
        raise HTTPException(400, "That path cannot be resolved.")
    if not base.exists():
        raise HTTPException(404, f"No such directory: {base}")
    if not base.is_dir():
        base = base.parent

    try:
        kids = sorted(
            (e for e in base.iterdir() if e.is_dir() and not e.name.startswith(".")),
            key=lambda e: e.name.lower(),
        )[:250]
    except PermissionError:
        raise HTTPException(403, f"Not readable: {base}")
    except OSError as exc:
        raise HTTPException(400, str(exc))

    return {
        "path": str(base),
        "parent": None if base.parent == base else str(base.parent),
        "entries": [_describe(d) for d in kids],
        "places": [p for p in (
            {"name": "Home", "path": str(Path.home())},
            {"name": "Demo targets", "path": str(config.TARGETS_DIR)},
            {"name": "Project", "path": str(config.ROOT)},
            {"name": "/usr/local/lib", "path": "/usr/local/lib"},
            {"name": "/", "path": "/"},
        ) if Path(p["path"]).is_dir()],
    }


@app.get("/api/knowledge/algorithms")
def knowledge_algorithms() -> dict[str, Any]:
    return {
        "algorithms": [
            {
                "key": a.key, "name": a.name, "family": a.family,
                "primitive": a.primitive, "quantum_class": a.quantum_class,
                "classical_bits": a.classical_bits, "nist_level": a.nist_level,
                "standard": a.standard, "oid": a.oid, "note": a.note,
                "public_key_bytes": a.public_key_bytes,
                "signature_bytes": a.signature_bytes,
                "deprecated_after": a.deprecated_after,
                "disallowed_after": a.disallowed_after,
            }
            for a in sorted(K.ALGORITHMS.values(), key=lambda x: (x.quantum_class, x.family))
        ],
        "classes": {c: {"label": K.CLASS_LABEL[c], "description": K.CLASS_DESCRIPTION[c]}
                    for c in K.CLASS_ORDER},
    }


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return {
        "product": config.PRODUCT_NAME,
        "tagline": config.PRODUCT_TAGLINE,
        "version": config.PRODUCT_VERSION,
        "ps_id": config.PS_ID,
        "ps_org": config.PS_ORG,
        "profiles": recommend.PROFILES,
        "qday_default": risk.QDayModel().to_dict(),
        "sensitivities": config.SHELF_LIFE_BY_SENSITIVITY,
        "suggested_targets": _suggested_targets(),
        "sensors": {name: label for name, (_, _, label) in orchestrator.SENSORS.items()},
    }


def _suggested_targets() -> list[dict[str, str]]:
    """One-click scan targets: cloned repositories plus real system libraries.

    The system library paths matter for the binary sensor -- a freshly cloned
    source repository contains no compiled objects, so scanning one would show
    an empty result for a sensor that actually works.
    """
    out = []
    if config.TARGETS_DIR.exists():
        for p in sorted(config.TARGETS_DIR.iterdir()):
            if p.is_dir() and not p.name.startswith("."):
                out.append({"label": p.name, "path": str(p)})
    for label, path in (("system libraries (binary scan)", "/usr/local/lib"),
                        ("system binaries (binary scan)", "/usr/local/bin")):
        if Path(path).is_dir():
            out.append({"label": label, "path": path})
    return out


# --------------------------------------------------------------------------
# Static console
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    """Serve the console with the latest scan already inlined.

    Without this the page paints an empty shell -- blank dropdowns, an empty
    treemap -- for as long as the first round of fetches takes, which is the
    first thing anyone watching sees. Inlining the data the first render needs
    means the console opens fully populated on the first frame.
    """
    html = (config.WEB_DIR / "index.html").read_text(encoding="utf-8")

    preload: dict[str, Any] = {"meta": meta()}
    scan_id = store.latest_scan_id()
    if scan_id:
        try:
            preload["scan"] = scan_payload(scan_id, rescore_default=True)
        except HTTPException:
            pass

    blob = json.dumps(preload).replace("</", "<\\/")
    tag = f'<script>window.__PRELOAD__ = {blob};</script>'
    html = html.replace('<script src="/static/app.js"></script>',
                        tag + '\n<script src="/static/app.js"></script>')
    return HTMLResponse(html)


app.mount("/static", StaticFiles(directory=str(config.WEB_DIR)), name="static")


@app.on_event("startup")
def _startup() -> None:
    config.ensure_dirs()
    store.init()
