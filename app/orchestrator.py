"""Scan orchestration: run every sensor over a target and assemble the result.

Sensors are deliberately independent. One failing must never take the scan
down -- a malformed binary or an unreachable host is a normal condition in a
real estate, not an error, and an inventory tool that stops on the first odd
file is useless.
"""

from __future__ import annotations

import logging
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from . import assessment as A
from . import config, fspolicy
from .container import ArchiveLimits, ContainerError
from .engine import correlate, normalize, recommend, risk
from .fspolicy import FsPolicy, PathRefused
from .models import Finding, ScanResult, ScanTarget
from .netpolicy import NetPolicy
from .scanners import binary, certs, configs, container, deps, network, source

log = logging.getLogger(__name__)

# name -> (callable, weight for progress reporting, human label)
SENSORS: dict[str, tuple[Callable, int, str]] = {
    "source": (source.scan, 40, "Scanning source code"),
    "dependency": (deps.scan, 5, "Reading dependency manifests"),
    "certificate": (certs.scan, 10, "Parsing certificates and key material"),
    "config": (configs.scan, 5, "Reading cryptographic configuration"),
    "binary": (binary.scan, 20, "Analysing binaries"),
}

DEFAULT_SENSORS = list(SENSORS)

# Sensors that can report their own inner progress.
_SUB_PROGRESS = {"source", "binary"}


def _finish(raw: list[Finding], result: ScanResult, stats: dict[str, Any],
            profile: str, qday, progress) -> list[Finding]:
    """The half of a scan that is the same whatever produced the findings.

    Normalise, correlate, score, recommend. Shared by the directory and the
    image entry points so a container finding travels exactly the same path as
    one from a source tree -- there is no second pipeline to drift.
    """
    if progress:
        progress(80, "Normalising cryptographic assets", "")
    assets = normalize.normalize(raw)

    if progress:
        progress(84, "Correlating evidence across sensors", "")
    # Correlation runs before scoring and changes nothing it scores: it links
    # findings and records why, leaving every assurance and confidence value
    # exactly as the detector set it.
    links = correlate.correlate(assets)
    stats["correlation"] = correlate.summary(links)
    stats["logical_assets"] = [a.to_dict() for a in links]

    if progress:
        progress(88, "Scoring quantum risk", "")
    # Operator overrides outlive scans, so a rescan of an estate somebody has
    # already assessed keeps their numbers instead of reverting to defaults.
    try:
        from . import store
        overrides = store.list_overrides()
    except Exception:                       # a scan must not fail on this
        overrides = {}
    stats["overrides_applied"] = sum(
        1 for f in assets if A.asset_key(f) in overrides)
    risk.score_all(assets, qday or risk.QDayModel(), overrides=overrides)

    if progress:
        progress(94, "Selecting migration targets", "")
    recommend.recommend_all(assets, profile, overrides=overrides)

    assets.sort(key=lambda f: -f.risk_score)

    result.findings = assets
    result.stats = stats
    return assets


def scan_target(
    path: str | Path,
    label: str = "",
    endpoints: Optional[list[str]] = None,
    sensors: Optional[Iterable[str]] = None,
    profile: str = recommend.PROFILE_GENERAL,
    qday: Optional[risk.QDayModel] = None,
    max_files: int = 0,
    progress: Optional[Callable[[int, str], None]] = None,
    time_budget: Optional[float] = None,
    net_policy: Optional[NetPolicy] = None,
) -> ScanResult:
    """Run the selected sensors over one target and return a scored result.

    The scan root is vetted before any sensor runs -- a bad target fails loudly
    at the start rather than producing a thin result that reads like a clean
    estate. A wall-clock budget bounds the whole run; when it expires the scan
    ends cleanly and says so rather than being killed, because a partial
    inventory the operator knows is partial is useful and one they do not is
    dangerous.
    """
    root = fspolicy.resolve_root(path)
    chosen = [s for s in (sensors or DEFAULT_SENSORS) if s in SENSORS]

    budget = time_budget if time_budget is not None else config.SCAN_TIME_BUDGET
    fs = FsPolicy(
        root=root,
        deadline=(time.monotonic() + budget) if budget else None,
        max_entries=config.MAX_ENTRIES,
    )

    target = ScanTarget(kind="repository", value=str(root), label=label or root.name)
    result = ScanResult(target=target)

    raw: list[Finding] = []
    stats: dict[str, Any] = {
        "sensors_run": [], "sensor_errors": {},
        "scan_root": str(root),
        "time_budget_seconds": budget,
    }

    total_weight = sum(SENSORS[s][1] for s in chosen) + (12 if endpoints else 0)
    done_weight = 0

    def report(label_text: str, detail: str = "") -> None:
        if progress:
            pct = 5 + int(70 * done_weight / max(total_weight, 1))
            progress(min(pct, 75), label_text, detail)

    def sub_reporter(phase: str, weight: int):
        """Advance within one sensor's slice of the bar, not just between them."""
        def cb(done: int, total: int, noun: str = "items") -> None:
            if not progress or not total:
                return
            frac = min(1.0, done / total)
            pct = 5 + int(70 * (done_weight + weight * frac) / max(total_weight, 1))
            progress(min(pct, 75),
                     phase, f"{done:,} of {total:,} {noun}")
        return cb

    for name in chosen:
        fn, weight, phase = SENSORS[name]
        if fs.expired():
            stats["sensors_skipped"] = stats.get("sensors_skipped", [])
            stats["sensors_skipped"].append(name)
            done_weight += weight
            continue
        report(phase)
        try:
            kwargs: dict[str, Any] = {"policy": fs}
            if max_files:
                kwargs["max_files"] = max_files
            if name in _SUB_PROGRESS:
                kwargs["on_progress"] = sub_reporter(phase, weight)
            found, sstats = fn(root, **kwargs)
            raw.extend(found)
            stats.update(sstats)
            stats["sensors_run"].append(name)
        except Exception as exc:
            # The message reaches the operator; the traceback goes to the log.
            # A sensor failing is a normal condition in a real estate, but a
            # silent one would mean reporting an incomplete estate as complete.
            stats["sensor_errors"][name] = f"{type(exc).__name__}: {exc}"
            log.exception("sensor %s failed on %s", name, root)
        done_weight += weight

    if endpoints:
        report("Probing live TLS endpoints")
        try:
            found, sstats = network.scan(endpoints, policy=net_policy)
            raw.extend(found)
            stats.update(sstats)
            stats["sensors_run"].append("network")
        except Exception as exc:
            stats["sensor_errors"]["network"] = f"{type(exc).__name__}: {exc}"
            log.exception("network sensor failed")
        done_weight += 12

    assets = _finish(raw, result, stats, profile, qday, progress)
    result.stats["raw_hits"] = len(raw)
    result.stats["filesystem_policy"] = fs.report()

    # One explicit flag the UI, the report and the CBOM can all read, rather
    # than each of them re-deriving "was this scan complete?" differently.
    incomplete: list[str] = []
    if stats["sensor_errors"]:
        incomplete.append(f"{len(stats['sensor_errors'])} sensor(s) failed")
    if stats.get("sensors_skipped"):
        incomplete.append(
            f"{len(stats['sensors_skipped'])} sensor(s) skipped: time budget reached")
    for key in ("source_incomplete", "binary_incomplete"):
        if stats.get(key):
            incomplete.append(stats[key])
    if fs.report().get("incomplete"):
        incomplete.append(fs.report()["incomplete"])
    if stats.get("endpoints_refused"):
        incomplete.append(
            f"{len(stats['endpoints_refused'])} endpoint(s) refused by network policy")
    result.stats["complete"] = not incomplete
    if incomplete:
        result.stats["incomplete_reasons"] = incomplete

    result.finished_at = time.time()
    return result


# --------------------------------------------------------------------------
# Container images
#
# An image archive is not a directory and is deliberately not treated as one.
# A directory scan walks a filesystem the operator already has; an image scan
# reads an untrusted archive, resolves a manifest, replays layers and has to
# decide which of several images was meant. Disguising the second as the first
# would mean either lying about the target kind or quietly extracting the
# archive somewhere, and we do neither.
# --------------------------------------------------------------------------

def inspect_image(archive_path: str | Path) -> dict[str, Any]:
    """Describe an archive without scanning it, for the console's picker."""
    from . import container as container_mod
    return container_mod.inspect(archive_path)


def scan_image(
    archive_path: str | Path,
    image: str = "",
    label: str = "",
    profile: str = recommend.PROFILE_GENERAL,
    qday: Optional[risk.QDayModel] = None,
    progress: Optional[Callable[[int, str], None]] = None,
    time_budget: Optional[float] = None,
    limits: Optional[ArchiveLimits] = None,
) -> ScanResult:
    """Scan one image inside one local container archive.

    Runs the container sensor, then the same normalise -> correlate -> score ->
    recommend pipeline a directory scan runs, so a container finding reaches
    the CBOM by the identical route.
    """
    path = Path(archive_path).expanduser().resolve()
    if not path.exists():
        raise PathRefused(f"Image archive not found: {path}")

    budget = time_budget if time_budget is not None else config.SCAN_TIME_BUDGET
    limits = limits or ArchiveLimits()
    if budget:
        limits.deadline = time.monotonic() + budget

    target = ScanTarget(kind="image", value=str(path),
                        label=label or (image or path.name))
    result = ScanResult(target=target)

    stats: dict[str, Any] = {
        "sensors_run": [], "sensor_errors": {},
        "scan_root": str(path),
        "time_budget_seconds": budget,
        "target_kind": "image",
    }

    def report(phase: str, pct: int, detail: str = "") -> None:
        if progress:
            progress(pct, phase, detail)

    def layer_progress(done: int, total: int, noun: str) -> None:
        if progress and total:
            pct = 5 + int(70 * done / total)
            progress(min(pct, 75), "Reading image layers",
                     f"{done} of {total} {noun}")

    raw: list[Finding] = []
    report("Opening image archive", 5)
    try:
        found, sstats = container.scan(path, image=image, limits=limits,
                                       on_progress=layer_progress)
        raw.extend(found)
        stats.update(sstats)
        stats["sensors_run"].append("container")
    except ContainerError as exc:
        # An unreadable or ambiguous archive is the operator's problem to fix
        # and the message names what to do, so it is raised rather than
        # flattened into an empty result that reads like a clean image.
        raise
    except Exception as exc:
        stats["sensor_errors"]["container"] = f"{type(exc).__name__}: {exc}"
        log.exception("container sensor failed on %s", path)

    assets = _finish(raw, result, stats, profile, qday, progress)

    # Recount after normalisation. The sensor counts raw detections; the
    # inventory counts assets, and publishing one number labelled as the other
    # makes the CBOM's own totals disagree with each other.
    effective = sum(1 for f in assets
                    if (f.extra.get("container") or {}).get("effective", True))
    result.stats["container_findings_effective"] = effective
    result.stats["container_findings_historical"] = len(assets) - effective

    incomplete: list[str] = []
    if stats["sensor_errors"]:
        incomplete.append(f"{len(stats['sensor_errors'])} sensor(s) failed")
    if stats.get("container_incomplete"):
        incomplete.append(stats["container_incomplete"])
    archive_stats = stats.get("container_archive_stats") or {}
    if archive_stats.get("refused"):
        total = sum(archive_stats["refused"].values())
        incomplete.append(
            f"{total} archive member(s) refused by the archive policy")
    result.stats["complete"] = not incomplete
    if incomplete:
        result.stats["incomplete_reasons"] = incomplete

    result.finished_at = time.time()
    return result
