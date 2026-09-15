"""Scan orchestration: run every sensor over a target and assemble the result.

Sensors are deliberately independent. One failing must never take the scan
down -- a malformed binary or an unreachable host is a normal condition in a
real estate, not an error, and an inventory tool that stops on the first odd
file is useless.
"""

from __future__ import annotations

import time
import traceback
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .engine import normalize, recommend, risk
from .models import Finding, ScanResult, ScanTarget
from .scanners import binary, certs, configs, deps, network, source

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
) -> ScanResult:
    """Run the selected sensors over one target and return a scored result."""
    root = Path(path).expanduser().resolve()
    chosen = [s for s in (sensors or DEFAULT_SENSORS) if s in SENSORS]

    target = ScanTarget(kind="repository", value=str(root), label=label or root.name)
    result = ScanResult(target=target)

    raw: list[Finding] = []
    stats: dict[str, Any] = {"sensors_run": [], "sensor_errors": {}}

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
        report(phase)
        try:
            kwargs = {"max_files": max_files} if max_files else {}
            if name in _SUB_PROGRESS:
                kwargs["on_progress"] = sub_reporter(phase, weight)
            found, sstats = fn(root, **kwargs)
            raw.extend(found)
            stats.update(sstats)
            stats["sensors_run"].append(name)
        except Exception as exc:
            stats["sensor_errors"][name] = str(exc)
            traceback.print_exc()
        done_weight += weight

    if endpoints:
        report("Probing live TLS endpoints")
        try:
            found, sstats = network.scan(endpoints)
            raw.extend(found)
            stats.update(sstats)
            stats["sensors_run"].append("network")
        except Exception as exc:
            stats["sensor_errors"]["network"] = str(exc)
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
    result.finished_at = time.time()
    return result
