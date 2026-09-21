"""Command line entry point. Used for development and for the demo dry-run."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import cbom, config, schema_validation
from .engine import normalize, risk
from .models import ScanResult, ScanTarget
from .scanners import source


def cmd_scan(args: argparse.Namespace) -> int:
    target = ScanTarget(kind="repository", value=str(Path(args.path).resolve()),
                        label=args.label or Path(args.path).name)
    result = ScanResult(target=target)

    t0 = time.time()
    findings, stats = source.scan(args.path, max_files=args.max_files)
    result.findings = normalize.normalize(findings)
    result.stats = stats
    result.stats["raw_hits"] = len(findings)
    result.finished_at = time.time()

    risk.score_all(result.findings, risk.QDayModel())
    result.findings.sort(key=lambda f: -f.risk_score)

    summary = risk.portfolio_summary(result.findings)

    print(f"\n{config.PRODUCT_NAME} {config.PRODUCT_VERSION} — {target.label}")
    print("=" * 68)
    print(f"  files scanned      {stats['files_scanned']:,}")
    print(f"  languages          {', '.join(f'{k}:{v}' for k, v in list(stats['languages'].items())[:6])}")
    print(f"  scan duration      {result.duration:.2f}s")
    print(f"  raw detector hits  {stats['raw_hits']:,}")
    print(f"  crypto assets      {summary['total']:,}")
    print(f"  quantum vulnerable {summary['quantum_vulnerable']:,}  ({summary['vulnerable_pct']}%)")
    print(f"  by class           {summary['by_class']}")
    print(f"  by severity        {summary['by_severity']}")
    print("=" * 68)

    for f in result.findings[:args.top]:
        ev = f.evidence[0] if f.evidence else None
        loc = f"{ev.location}:{ev.line}" if ev and ev.line else (ev.location if ev else "")
        ctx = f.extra.get("context", "")
        print(f"  {f.risk_score:5.1f}  {risk.severity(f.risk_score):8s}  "
              f"{f.algorithm:16s}  {f.occurrences:4d}x  {ctx:10s}  "
              f"{f.title[:30]:30s}  {loc[:40]}")

    if args.cbom:
        try:
            doc = cbom.build(result, spec_version=args.cbom_version)
        except ValueError as exc:
            print(f"\n  {exc}", file=sys.stderr)
            return 2
        ok, problems = cbom.validate(doc)
        Path(args.cbom).write_text(json.dumps(doc, indent=2))
        print(f"\n  CBOM written to {args.cbom}  ({len(doc['components'])} components)")
        print(f"  CycloneDX {args.cbom_version} structural validation: "
              f"{'PASS' if ok else 'FAIL'}")
        for problem in problems[:10]:
            print(f"     - {problem}")

        # The official schema check is reported separately and never conflated
        # with the structural one above.
        official = schema_validation.report(doc, args.cbom_version)
        if official["checked"]:
            print(f"  Official CycloneDX {args.cbom_version} JSON Schema: "
                  f"{'PASS' if official['valid'] else 'FAIL'}")
            for problem in official["problems"][:10]:
                print(f"     - {problem}")
            if not official["valid"]:
                return 1
        else:
            print(f"  Official schema validation not run: "
                  f"{official['reason_unavailable']}")
        if not ok:
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cryptodrishti")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a source tree")
    s.add_argument("path")
    s.add_argument("--label", default="")
    s.add_argument("--top", type=int, default=20)
    s.add_argument("--max-files", type=int, default=config.MAX_FILES)
    s.add_argument("--cbom", default="", help="write a CycloneDX CBOM here")
    s.add_argument("--cbom-version", default=cbom.SPEC_VERSION,
                   choices=list(cbom.SUPPORTED_SPEC_VERSIONS),
                   help="CycloneDX specification version to emit")
    s.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
