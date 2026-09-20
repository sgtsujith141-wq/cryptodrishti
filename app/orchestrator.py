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

from . import config, fspolicy
from .engine import normalize, recommend, risk
from .fspolicy import FsPolicy, PathRefused
from .models import Finding, ScanResult, ScanTarget
from .netpolicy import NetPolicy
from .scanners import binary, certs, configs, deps, network, source

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

    if progress:
        progress(80, "Normalising cryptographic assets", "")
    assets = normalize.normalize(raw)

    if progress:
        progress(88, "Scoring quantum risk", "")
    risk.score_all(assets, qday or risk.QDayModel())

    if progress:
        progress(94, "Selecting migration targets", "")
    recommend.recommend_all(assets, profile)

    assets.sort(key=lambda f: -f.risk_score)

    result.findings = assets
    result.stats = stats
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
