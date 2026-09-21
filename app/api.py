"""HTTP API and static console.

Scans run in a background thread so the console stays responsive and can show
progress; the alternative -- a synchronous request that blocks for thirty
seconds -- is unusable in a live demonstration.

Every route is local. The application makes no outbound network connections
except when a scan explicitly probes a host the operator named.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import (
    auth, cbom, config, container, fspolicy, netpolicy, orchestrator, report, store,
)
from .container import ContainerError
from .engine import recommend, risk
from .fspolicy import PathRefused
from .knowledge import algorithms as K
from .models import ScanResult, ScanTarget

log = logging.getLogger(__name__)

app = FastAPI(title=config.PRODUCT_NAME, version=config.PRODUCT_VERSION)

# In-flight scan progress, keyed by scan id.
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()

# Scans that may run at once. Each is a thread pool over a filesystem walk;
# without this, N requests is N walks and the machine running the console is
# the thing that falls over.
_SCAN_SLOTS = threading.Semaphore(config.MAX_CONCURRENT_SCANS)


# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------

@app.middleware("http")
async def _require_token(request: Request, call_next):
    """Gate every API route when an access token is configured.

    Silent when no token is set, which is the single-operator localhost case.
    ``run.py`` refuses to start on a non-loopback bind without one, so "no
    token" and "not reachable from the network" stay the same condition.
    """
    path = request.url.path
    if auth.configured_token() and path.startswith("/api") and not auth.path_is_open(path):
        supplied = auth.token_from_request(
            request.headers, request.cookies, request.query_params)
        if not auth.token_matches(supplied):
            return JSONResponse(
                {"detail": "Access token required. Open the console once as "
                           "/?token=YOUR_TOKEN, or send an Authorization: Bearer header."},
                status_code=401)
    return await call_next(request)


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------

class ScanRequest(BaseModel):
    path: str
    label: str = Field("", max_length=200)
    profile: str = recommend.PROFILE_GENERAL
    max_files: int = Field(0, ge=0, le=config.MAX_FILES)
    sensors: list[str] | None = None
    # Bounded at the schema so an oversized list is rejected before it reaches
    # the policy layer; the policy then vets each entry that survives.
    endpoints: list[str] = Field(default_factory=list, max_length=64)
    # A container archive is a different kind of target, not a directory with
    # an odd name, so it is selected explicitly rather than sniffed. `image`
    # names which manifest to read when the archive holds more than one.
    target_kind: Literal["directory", "image"] = "directory"
    image: str = Field("", max_length=300)


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
        # Evict the oldest finished jobs. Without this the map is a slow leak
        # for a process that is expected to stay up across a whole working day.
        if len(_JOBS) > config.MAX_TRACKED_JOBS:
            finished = [k for k, v in _JOBS.items()
                        if v.get("state") in ("done", "error", "refused")]
            for k in finished[:len(_JOBS) - config.MAX_TRACKED_JOBS]:
                _JOBS.pop(k, None)


def _run_scan(scan_id: str, req: ScanRequest) -> None:
    acquired = _SCAN_SLOTS.acquire(timeout=1.0)
    if not acquired:
        _set_job(scan_id, state="refused", progress=0, phase="Refused",
                 error=(f"{config.MAX_CONCURRENT_SCANS} scans are already running. "
                        f"Wait for one to finish, or raise CD_MAX_CONCURRENT_SCANS."))
        return
    try:
        _set_job(scan_id, state="running", phase="Starting sensors", progress=3,
                 detail="", tick=0)

        # `tick` increments on every report. The console watches it to tell a
        # slow sensor apart from a stalled one, which a percentage alone cannot.
        counter = {"n": 0}

        def progress(pct: int, phase: str, detail: str = "") -> None:
            counter["n"] += 1
            _set_job(scan_id, progress=pct, phase=phase, detail=detail,
                     tick=counter["n"])

        if req.target_kind == "image":
            result = orchestrator.scan_image(
                req.path, image=req.image, label=req.label,
                profile=req.profile, progress=progress,
            )
        else:
            result = orchestrator.scan_target(
                req.path,
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
                 findings=len(result.findings), duration=round(result.duration, 2),
                 complete=result.stats.get("complete", True),
                 warnings=_scan_warnings(result.stats))
    except (PathRefused, ContainerError) as exc:
        # A policy refusal or an unreadable archive is the operator's problem
        # to fix, and the message names what to do, so it is reported verbatim
        # rather than flattened into a generic error.
        _set_job(scan_id, state="error", error=str(exc), refused=True)
    except Exception as exc:
        # The operator gets the error class, the message and a reference; the
        # traceback goes to the server log. Shipping internal paths and frames
        # to an HTTP client is an information leak with no operational value.
        ref = uuid.uuid4().hex[:8]
        log.exception("scan %s failed (ref %s)", scan_id, ref)
        _set_job(scan_id, state="error", error=f"{type(exc).__name__}: {exc}",
                 error_ref=ref,
                 hint="Full traceback is in the server log under this reference.")
    finally:
        _SCAN_SLOTS.release()


def _container_summary(stats: dict[str, Any]) -> dict[str, Any]:
    """Image provenance for the console, or {} for a directory scan."""
    if not stats.get("container_format"):
        return {}
    return {
        "format": stats.get("container_format"),
        "format_description": stats.get("container_format_description"),
        "image": stats.get("container_image"),
        "image_digest": stats.get("container_image_digest"),
        "platform": stats.get("container_platform"),
        "images_available": stats.get("container_images_available") or [],
        "layers": stats.get("container_layers"),
        "files_analysed": stats.get("container_files_analysed"),
        "findings_effective": stats.get("container_findings_effective"),
        "findings_historical": stats.get("container_findings_historical"),
        "archive": stats.get("container_archive_stats") or {},
    }


def _scan_warnings(stats: dict[str, Any]) -> list[str]:
    """Everything the operator must know before trusting this inventory.

    A scan that silently declined to read part of the tree, skipped a sensor or
    refused an endpoint has produced a partial estate. Reporting it as complete
    is the most damaging thing this tool could do, so the warnings travel with
    the result rather than being left in the stats for someone to find.
    """
    out: list[str] = list(stats.get("incomplete_reasons") or [])
    for name, message in (stats.get("sensor_errors") or {}).items():
        out.append(f"sensor '{name}' failed: {message}")
    for refusal in (stats.get("endpoints_refused") or []):
        out.append(f"endpoint refused: {refusal['destination']} — {refusal['reason']}")
    fs = stats.get("filesystem_policy") or {}
    for reason, count in (fs.get("skipped") or {}).items():
        out.append(f"{count} path(s) skipped: {reason}")
    archive = stats.get("container_archive_stats") or {}
    for reason, count in (archive.get("refused") or {}).items():
        out.append(f"{count} archive member(s) refused: {reason}")
    if archive.get("truncated"):
        out.append(f"image archive: {archive['truncated']}")
    for note in archive.get("notes") or []:
        out.append(f"image archive: {note}")
    return out


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> dict[str, Any]:
    # Vet the target synchronously so a bad one is a 400 the operator sees
    # immediately, not a background job that fails a second later. For an
    # image this also settles the manifest question up front: an ambiguous
    # archive is rejected here, with the available images named.
    try:
        root = fspolicy.resolve_root(req.path)
    except PathRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if req.target_kind == "image":
        try:
            archive = container.open_archive(root)
            try:
                container.select_image(archive, req.image)
            finally:
                archive.close()
        except ContainerError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    kind = "image" if req.target_kind == "image" else "repository"
    result = ScanResult(target=ScanTarget(kind=kind, value=str(root)))
    scan_id = result.id
    _set_job(scan_id, state="queued", progress=0, phase="Queued",
             target_kind=req.target_kind,
             label=req.label or (req.image or root.name))
    threading.Thread(target=_run_scan, args=(scan_id, req), daemon=True).start()
    return {"scan_id": scan_id}


@app.get("/api/container/inspect")
def inspect_container(path: str = Query("", max_length=4096)) -> dict[str, Any]:
    """Describe a local image archive without reading a single layer.

    Cheap enough to drive the console's image picker, and it is where an
    unsupported file fails with a reason instead of halfway through a scan.
    """
    if not path:
        raise HTTPException(400, "A path to a local image archive is required.")
    try:
        resolved = fspolicy.resolve_root(path)
    except PathRefused as exc:
        raise HTTPException(400, str(exc))
    try:
        return container.inspect(resolved)
    except ContainerError as exc:
        raise HTTPException(400, str(exc))


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
    stats = meta_row.get("stats") or {}
    return {
        "scan": meta_row,
        "summary": risk.portfolio_summary(findings),
        "filtered_summary": risk.portfolio_summary(filtered),
        "findings": [f.to_dict() for f in filtered],
        "severity_of": {f.id: risk.severity(f.risk_score) for f in filtered},
        # Completeness travels with every view of the scan. An inventory the
        # reader believes is complete when it is not is the worst output this
        # tool can produce, so it is never something you have to go looking for.
        "complete": stats.get("complete", True),
        "warnings": _scan_warnings(stats),
        # Correlation is a view over the findings, not a change to them, so it
        # travels beside them rather than being folded in.
        "correlation": stats.get("correlation") or {},
        "logical_assets": stats.get("logical_assets") or [],
        "container": _container_summary(stats),
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
def browse(path: str = Query("", max_length=4096)) -> dict[str, Any]:
    """List the directories inside `path`, for the console's folder picker.

    This walks the operator's own filesystem, which is exactly what a local
    tool should do and exactly what must not be reachable from the network.
    The access-control middleware is what makes that distinction; here we only
    decline to enumerate synthetic filesystems, which would be meaningless.
    """
    base = Path(path).expanduser() if path else Path.home()
    try:
        base = base.resolve()
    except OSError:
        raise HTTPException(400, "That path cannot be resolved.")
    if not base.exists():
        raise HTTPException(404, f"No such directory: {base}")
    if not base.is_dir():
        base = base.parent
    if not fspolicy.should_traverse(str(base)):
        raise HTTPException(
            400, f"{base} is a synthetic or system filesystem this tool will not walk.")

    try:
        kids = sorted(
            (e for e in base.iterdir()
             if e.is_dir() and not e.name.startswith(".")
             and fspolicy.should_traverse(str(e))),
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
        # The operator should be able to read the rules the tool is running
        # under without going to the source or the environment.
        "policy": {
            "network": netpolicy.NetPolicy.from_env().describe(),
            "scan_time_budget_seconds": config.SCAN_TIME_BUDGET,
            "max_concurrent_scans": config.MAX_CONCURRENT_SCANS,
            "max_files": config.MAX_FILES,
            "max_entries": config.MAX_ENTRIES,
            "access_control": "token" if auth.configured_token() else "none (localhost only)",
        },
        # Advertised so the console never offers a format the sensor cannot
        # actually read, and so the documented coverage has one source.
        "container_formats": container.SUPPORTED_FORMATS,
        "container_suffixes": list(container.SUPPORTED_SUFFIXES),
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

@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness only. Carries no estate data, so it stays open."""
    return {"status": "ok", "product": config.PRODUCT_NAME,
            "version": config.PRODUCT_VERSION}


@app.get("/", response_class=HTMLResponse)
def index(token: str = Query("")) -> HTMLResponse:
    """Serve the console with the latest scan already inlined.

    Without this the page paints an empty shell -- blank dropdowns, an empty
    treemap -- for as long as the first round of fetches takes, which is the
    first thing anyone watching sees. Inlining the data the first render needs
    means the console opens fully populated on the first frame.
    """
    # When a token is configured the console has no way to send one, so the
    # index exchanges ?token= for a strict same-site cookie. Deliberately
    # modest: this is an access control for a single-operator tool, not a
    # user system, and it is documented as such.
    expected = auth.configured_token()
    if expected and not auth.token_matches(token):
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8>"
            "<title>Access token required</title>"
            "<body style='font:15px/1.6 system-ui;margin:4rem auto;max-width:34rem'>"
            "<h1>Access token required</h1>"
            "<p>This console is bound beyond localhost, so it is protected by "
            "the token in <code>CD_TOKEN</code>.</p>"
            "<p>Open it as <code>/?token=YOUR_TOKEN</code>.</p>",
            status_code=401)

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
    response = HTMLResponse(html)
    if expected:
        response.set_cookie(auth.COOKIE_NAME, expected, httponly=True,
                            samesite="strict", max_age=12 * 3600, path="/")
    return response


app.mount("/static", StaticFiles(directory=str(config.WEB_DIR)), name="static")


@app.on_event("startup")
def _startup() -> None:
    config.ensure_dirs()
    store.init()
