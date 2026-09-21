#!/usr/bin/env python3
"""Measure CryptoDrishti against the hand-labelled corpus.

    python benchmark/run.py                    print the report
    python benchmark/run.py --json out.json    also save machine-readable results
    python benchmark/run.py --baseline b.json  compare against an earlier run
    python benchmark/run.py --detail           list every FP and FN

**What these numbers are.** Precision and recall over the fixtures in
``benchmark/corpus``, which were written by hand to exercise the detectors.
They measure this corpus. They are **not** an estimate of accuracy on
real-world code, which this project has never measured and does not claim.

**Matching.** The unit is a distinct ``(file, line, algorithm)``. Actual
findings are reduced to that set before matching, so one artefact reported by
two rules counts once and cannot inflate the true positives. Algorithms must
match exactly as registry keys -- ``sha3-512`` does not satisfy an expectation
of ``sha3-256``, which is the whole reason the identity work in M2 happened.

Purpose and assurance are scored separately, over the true positives only:
getting the purpose of something you never found is not an achievement.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
sys.path.insert(0, str(ROOT))

import generate  # noqa: E402
from app.engine import normalize  # noqa: E402
from app.scanners import binary, certs, configs, container, deps, source  # noqa: E402


_MANIFEST_PATH = ROOT / "manifest.json"


def load_manifest(path: Optional[Path] = None) -> dict[str, Any]:
    return json.loads(Path(path or _MANIFEST_PATH).read_text())


# --------------------------------------------------------------------------
# Collecting what the tool actually reports
# --------------------------------------------------------------------------

def _rel(location: str, root: Path) -> str:
    """Normalise a finding's location to a corpus-relative path."""
    text = str(location).replace("\\", "/")
    if ":/" in text:                       # container: image:/path
        text = "images/benchmark-image.tar::" + text.split(":/", 1)[1]
    text = text.removeprefix(str(root).replace("\\", "/")).lstrip("/")
    return text


def collect(root: Path) -> list[dict[str, Any]]:
    """Run every scanner over the corpus and flatten to evidence-level rows."""
    rows: list[dict[str, Any]] = []

    def add(findings, scanner_label: str) -> None:
        for f in normalize.normalize(list(findings)):
            for e in f.evidence:
                rows.append({
                    "file": _rel(e.location, root),
                    "line": e.line,
                    "algorithm": f.algorithm,
                    "purpose": f.purpose,
                    "assurance": e.assurance,
                    "scanner": scanner_label,
                    "rule_id": f.rule_id,
                })

    add(source.scan(root)[0], "source")
    add(deps.scan(root)[0], "dependency")
    add(configs.scan(root)[0], "config")
    add(binary.scan(root)[0], "binary")
    add(certs.scan(root)[0], "certificate")

    image = root / "generated" / "images" / "benchmark-image.tar"
    if image.is_file():
        add(container.scan(image)[0], "container")

    return rows


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def key_of(row: dict[str, Any]) -> tuple:
    return (row["file"], row.get("line"), row["algorithm"])


def score(expected: list[dict], actual: list[dict],
          negative_files: set[str]) -> dict[str, Any]:
    """One-to-one matching on (file, line, algorithm), deduped both sides."""
    positive_files = {e["file"] for e in expected}

    # Only judge findings in files the corpus actually labels. A finding in an
    # unlabelled file is out of scope, not a false positive.
    #
    # Negative files are deliberately NOT in this set: every finding in one is
    # a false positive and is counted once, below. Including them here counted
    # each negative hit twice -- once as an unmatched key and once in the
    # negative pass -- which understated precision.
    in_scope = [a for a in actual
                if a["file"] in positive_files and a["file"] not in negative_files]

    # Dedupe. Several rules reporting one artefact is one detection.
    actual_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for a in in_scope:
        actual_by_key[key_of(a)].append(a)

    expected_by_key: dict[tuple, dict] = {}
    for e in expected:
        expected_by_key[(e["file"], e.get("line"), e["algorithm"])] = e

    # A file-level expectation (line: null) is satisfied by a finding anywhere
    # in that file, because a manifest line number is meaningless there.
    file_level = {k for k in expected_by_key if k[1] is None}
    for key in list(actual_by_key):
        if key[1] is not None and (key[0], None, key[2]) in file_level:
            actual_by_key[(key[0], None, key[2])].extend(actual_by_key.pop(key))

    matched = set(expected_by_key) & set(actual_by_key)
    missed = set(expected_by_key) - set(actual_by_key)
    spurious = set(actual_by_key) - set(expected_by_key)

    per_scanner: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0})
    for key in matched:
        per_scanner[expected_by_key[key]["scanner"]]["tp"] += 1
    for key in missed:
        per_scanner[expected_by_key[key]["scanner"]]["fn"] += 1
    for key in spurious:
        scanner = actual_by_key[key][0]["scanner"]
        per_scanner[scanner]["fp"] += 1

    # Purpose and assurance, over true positives only.
    purpose_total = purpose_ok = 0
    assurance_total = assurance_ok = 0
    purpose_ambiguous = 0
    purpose_wrong: list[dict] = []
    assurance_wrong: list[dict] = []

    for key in matched:
        exp = expected_by_key[key]
        found = actual_by_key[key]
        if exp.get("purpose_ambiguous"):
            purpose_ambiguous += 1
        else:
            purpose_total += 1
            # Correct if any finding at this key carries the expected purpose:
            # the tool may legitimately emit a cipher and its mode separately.
            if any(f["purpose"] == exp["purpose"] for f in found):
                purpose_ok += 1
            else:
                purpose_wrong.append({"key": list(key), "expected": exp["purpose"],
                                      "got": sorted({f["purpose"] for f in found})})
        assurance_total += 1
        if any(f["assurance"] == exp["assurance"] for f in found):
            assurance_ok += 1
        else:
            assurance_wrong.append({"key": list(key), "expected": exp["assurance"],
                                    "got": sorted({f["assurance"] for f in found})})

    # Negative files: any finding at all is a false positive.
    negative_hits = [a for a in actual if a["file"] in negative_files]
    for hit in negative_hits:
        per_scanner[hit["scanner"]]["fp"] += 1

    return {
        "per_scanner": {k: dict(v) for k, v in sorted(per_scanner.items())},
        "matched": sorted(matched),
        "missed": [expected_by_key[k] for k in sorted(missed)],
        "spurious": [{"key": list(k), "findings": actual_by_key[k]}
                     for k in sorted(spurious)],
        "negative_hits": negative_hits,
        "purpose": {"scored": purpose_total, "correct": purpose_ok,
                    "ambiguous_excluded": purpose_ambiguous,
                    "wrong": purpose_wrong},
        "assurance": {"scored": assurance_total, "correct": assurance_ok,
                      "wrong": assurance_wrong},
    }


def metrics(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision and recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0 if (precision is not None and recall is not None) else None
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None}


def probe_local_tls() -> dict[str, Any]:
    """Probe a loopback TLS server with the network sensor.

    Reported, but **excluded from the precision and recall figures**. What a
    TLS handshake negotiates depends on the local OpenSSL build: this machine
    offers X25519MLKEM768 and another may not, so an expected-results label
    for the negotiated group would be a label for one laptop. Counting a
    correct observation as a false positive because the CI runner has an older
    library would be worse than not scoring it.

    The loopback relaxation is set for the probe and removed afterwards. The
    benchmark does not get to leave the SSRF guard weakened.
    """
    import os
    import tempfile as _tf

    out: dict[str, Any] = {"ran": False,
                           "excluded_from_metrics": True,
                           "why_excluded": (
                               "negotiated TLS parameters depend on the local "
                               "OpenSSL build, so they cannot carry a stable "
                               "expected-results label")}
    previous = {k: os.environ.get(k)
                for k in ("CD_ALLOW_PRIVATE_TARGETS", "CD_ALLOWED_PORTS")}
    work = Path(_tf.mkdtemp(prefix="cryptodrishti-tls-"))
    try:
        from app.scanners import network

        with generate.LocalTLS(work) as server:
            os.environ["CD_ALLOW_PRIVATE_TARGETS"] = "1"
            os.environ["CD_ALLOWED_PORTS"] = str(server.port)
            findings, stats = network.scan([f"127.0.0.1:{server.port}"])

        out["ran"] = True
        out["endpoints_probed"] = stats.get("endpoints_probed", 0)
        out["observations"] = [
            {"rule": f.rule_id, "algorithm": f.algorithm, "purpose": f.purpose,
             "assurance": f.assurance, "title": f.title}
            for f in findings]

        # The checks that *are* stable across TLS stacks: the sensor must
        # separate version from suite from key exchange, and must never claim
        # trust it did not verify.
        rules = {f.rule_id for f in findings}
        out["structural_checks"] = {
            "reported_protocol_versions": "net.tlsversion" in rules,
            "reported_cipher_suite_separately": "net.ciphersuite" in rules,
            "reported_key_exchange_separately": "net.pqgroup" in rules,
            "certificate_trust_not_assumed": all(
                f.extra.get("trust_verified") is not True
                for f in findings if f.rule_id == "net.cert"),
        }
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(work, ignore_errors=True)
    return out


def run(detail: bool = False, tls: bool = True,
        manifest_path: Optional[Path] = None) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    work = Path(tempfile.mkdtemp(prefix="cryptodrishti-benchmark-"))
    try:
        shutil.copytree(ROOT / "corpus", work, dirs_exist_ok=True)
        generate.build(work)
        actual = collect(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    negative_files = {n["file"] for n in manifest["negative_files"]}
    result = score(manifest["expected"], actual, negative_files)

    totals = {"tp": 0, "fp": 0, "fn": 0}
    per_scanner = {}
    for scanner, counts in result["per_scanner"].items():
        per_scanner[scanner] = metrics(**counts)
        for k in totals:
            totals[k] += counts[k]

    out = {
        "manifest_version": manifest["manifest_version"],
        "scope_note": manifest["scope_note"],
        "overall": metrics(**totals),
        "per_scanner": per_scanner,
        "purpose_accuracy": _ratio(result["purpose"]["correct"],
                                   result["purpose"]["scored"]),
        "purpose_ambiguous_excluded": result["purpose"]["ambiguous_excluded"],
        "assurance_accuracy": _ratio(result["assurance"]["correct"],
                                     result["assurance"]["scored"]),
        "false_negatives": result["missed"],
        "false_positives": result["spurious"],
        "negative_file_hits": result["negative_hits"],
        "purpose_errors": result["purpose"]["wrong"],
        "assurance_errors": result["assurance"]["wrong"],
        "network": probe_local_tls() if tls else {"ran": False, "skipped": True},
    }
    if not detail:
        for key in ("false_negatives", "false_positives", "negative_file_hits"):
            out[key + "_count"] = len(out[key])
    return out


def _ratio(correct: int, total: int) -> dict[str, Any]:
    return {"correct": correct, "scored": total,
            "accuracy": round(correct / total, 4) if total else None}


def render(result: dict[str, Any]) -> str:
    lines = [
        "CryptoDrishti detection benchmark",
        "=" * 72,
        f"corpus manifest {result['manifest_version']}",
        "",
        result["scope_note"],
        "",
        f"{'scanner':<14}{'TP':>6}{'FP':>6}{'FN':>6}{'precision':>12}"
        f"{'recall':>10}{'F1':>8}",
        "-" * 72,
    ]

    def row(name: str, m: dict) -> str:
        def fmt(v):
            return f"{v:.3f}" if isinstance(v, float) else "     —"
        return (f"{name:<14}{m['tp']:>6}{m['fp']:>6}{m['fn']:>6}"
                f"{fmt(m['precision']):>12}{fmt(m['recall']):>10}{fmt(m['f1']):>8}")

    for scanner, m in result["per_scanner"].items():
        lines.append(row(scanner, m))
    lines.append("-" * 72)
    lines.append(row("OVERALL", result["overall"]))
    lines.append("")

    p, a = result["purpose_accuracy"], result["assurance_accuracy"]
    lines.append(f"purpose    {p['correct']}/{p['scored']} correct"
                 f"  ({p['accuracy']:.3f})" if p["accuracy"] is not None else
                 "purpose    not scored")
    lines.append(f"           {result['purpose_ambiguous_excluded']} case(s) "
                 f"excluded as genuinely ambiguous")
    lines.append(f"assurance  {a['correct']}/{a['scored']} correct"
                 f"  ({a['accuracy']:.3f})" if a["accuracy"] is not None else
                 "assurance  not scored")

    fn = result.get("false_negatives", [])
    fp = result.get("false_positives", [])
    nh = result.get("negative_file_hits", [])
    lines += ["", f"false negatives: {len(fn)}   false positives: {len(fp)}"
                  f"   hits in negative files: {len(nh)}"]

    if fn:
        lines += ["", "MISSED (false negatives):"]
        for e in fn[:40]:
            where = f"{e['file']}:{e['line']}" if e.get("line") else e["file"]
            lines.append(f"  - {e['algorithm']:<14} {where}"
                         + (f"   [{e['note']}]" if e.get("note") else ""))
    if fp:
        lines += ["", "SPURIOUS (false positives):"]
        for s in fp[:40]:
            f, line, alg = s["key"]
            rules = sorted({x["rule_id"] for x in s["findings"]})
            lines.append(f"  - {alg:<14} {f}:{line}   via {', '.join(rules)}")
    if nh:
        lines += ["", "HITS IN NEGATIVE FILES (should be none):"]
        for h in nh[:40]:
            lines.append(f"  - {h['algorithm']:<14} {h['file']}:{h['line']}"
                         f"   via {h['rule_id']}")

    net = result.get("network") or {}
    if net.get("ran"):
        lines += ["", "NETWORK SENSOR (local loopback TLS, excluded from the metrics above)"]
        lines.append(f"  {net['why_excluded']}")
        for check, ok in (net.get("structural_checks") or {}).items():
            lines.append(f"    {'PASS' if ok else 'FAIL'}  {check.replace('_', ' ')}")
        for o in net.get("observations", []):
            lines.append(f"    observed  {o['rule']:16} {o['algorithm']:20} {o['title'][:46]}")
    elif net.get("error"):
        lines += ["", f"NETWORK SENSOR: not run — {net['error']}"]

    perr = result.get("purpose_errors", [])
    if perr:
        lines += ["", "PURPOSE MISMATCHES:"]
        for e in perr[:30]:
            f, line, alg = e["key"]
            lines.append(f"  - {alg:<14} {f}:{line}  expected {e['expected']},"
                         f" got {', '.join(e['got'])}")
    aerr = result.get("assurance_errors", [])
    if aerr:
        lines += ["", "ASSURANCE MISMATCHES:"]
        for e in aerr[:30]:
            f, line, alg = e["key"]
            lines.append(f"  - {alg:<14} {f}:{line}  expected {e['expected']},"
                         f" got {', '.join(e['got'])}")
    return "\n".join(lines)


def compare(current: dict, baseline: dict) -> str:
    lines = ["", "BEFORE / AFTER", "=" * 72,
             f"{'scanner':<14}{'precision':>22}{'recall':>18}{'F1':>16}",
             "-" * 72]

    def delta(now, was):
        if now is None or was is None:
            return f"{'—':>8}"
        d = now - was
        return f"{now:.3f} ({d:+.3f})"

    names = sorted(set(current["per_scanner"]) | set(baseline["per_scanner"]))
    for name in names:
        c = current["per_scanner"].get(name, {})
        b = baseline["per_scanner"].get(name, {})
        lines.append(
            f"{name:<14}{delta(c.get('precision'), b.get('precision')):>22}"
            f"{delta(c.get('recall'), b.get('recall')):>18}"
            f"{delta(c.get('f1'), b.get('f1')):>16}")
    lines.append("-" * 72)
    c, b = current["overall"], baseline["overall"]
    lines.append(f"{'OVERALL':<14}{delta(c['precision'], b['precision']):>22}"
                 f"{delta(c['recall'], b['recall']):>18}"
                 f"{delta(c['f1'], b['f1']):>16}")
    lines.append(f"{'':14}TP {b['tp']}→{c['tp']}   "
                 f"FP {b['fp']}→{c['fp']}   FN {b['fn']}→{c['fn']}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", default="", help="write results here")
    ap.add_argument("--baseline", default="", help="compare against an earlier run")
    ap.add_argument("--manifest", default="",
                    help="use a different ground-truth manifest (for "
                         "like-for-like comparison against an earlier corpus)")
    ap.add_argument("--no-tls", action="store_true",
                    help="skip the loopback TLS probe")
    ap.add_argument("--detail", action="store_true",
                    help="list every false positive and false negative")
    args = ap.parse_args(argv)

    result = run(detail=True, tls=not args.no_tls,
                 manifest_path=Path(args.manifest) if args.manifest else None)
    print(render(result))

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text())
        print(compare(result, baseline))

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, sort_keys=True))
        print(f"\nresults written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
