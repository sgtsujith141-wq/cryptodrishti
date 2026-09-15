#!/usr/bin/env python3
"""Single entry point.

    python run.py            start the console on http://127.0.0.1:8000
    python run.py --seed     run a scan first so the console opens populated
"""

from __future__ import annotations

import argparse
import sys
import time
import webbrowser
from pathlib import Path

from app import config


def seed(path: str, label: str, endpoints: list[str] | None = None) -> None:
    """Pre-run a full multi-sensor scan so the console opens populated.

    A live scan must never be the thing standing between the operator and a
    populated screen during a demonstration.
    """
    from app import orchestrator, store
    from app.engine import risk

    store.init()
    print(f"  seeding from {path} ...", flush=True)
    result = orchestrator.scan_target(
        path, label=label, endpoints=endpoints or [],
        progress=lambda pct, phase, detail="": print(
            f"    {pct:3d}%  {phase}" + (f"  ({detail})" if detail else ""), flush=True),
    )
    summary = risk.portfolio_summary(result.findings)
    store.save_scan(result, summary)
    print(f"  seeded {summary['total']} assets from {result.stats['raw_hits']} hits "
          f"across {len(result.stats['sensors_run'])} sensors "
          f"in {result.duration:.1f}s", flush=True)


def demo_reset(seed_path: str = "", endpoints_csv: str = "") -> int:
    """Restore the exact state the presentation script expects.

    One command, so recovering from a mid-rehearsal mess is not a sequence of
    remembered steps at two in the morning.
    """
    from app import store

    store.init()
    for s in store.list_scans():
        store.delete_scan(s["id"])
    print("  cleared previous scans", flush=True)

    path = seed_path or str(config.TARGETS_DIR / "openssl")
    if not Path(path).exists():
        print(f"  target not found: {path}", file=sys.stderr)
        return 1

    endpoints = [e.strip() for e in (endpoints_csv or "www.google.com").split(",") if e.strip()]
    try:
        seed(path, Path(path).name, endpoints)
    except Exception as exc:
        print(f"  live endpoint probe failed ({exc}); re-seeding offline", flush=True)
        seed(path, Path(path).name, [])
    print("\n  demo state restored. Start the console with: python run.py\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.PORT)
    ap.add_argument("--seed", action="store_true",
                    help="pre-run a scan so the console opens with data")
    ap.add_argument("--seed-path", default="")
    ap.add_argument("--seed-endpoints", default="",
                    help="comma separated TLS endpoints to probe while seeding")
    ap.add_argument("--open", action="store_true", help="open a browser")
    ap.add_argument("--preflight", action="store_true",
                    help="check everything the demo depends on, then exit")
    ap.add_argument("--demo-reset", action="store_true",
                    help="wipe scans and re-seed the exact demo state, then exit")
    args = ap.parse_args()

    config.ensure_dirs()

    if args.preflight:
        from app.preflight import run as preflight_run
        return preflight_run(f"http://{args.host}:{args.port}")

    if args.demo_reset:
        return demo_reset(args.seed_path, args.seed_endpoints)

    if args.seed:
        path = args.seed_path
        if not path:
            candidates = sorted(p for p in config.TARGETS_DIR.glob("*") if p.is_dir())
            if not candidates:
                print("  no targets in demo/targets — pass --seed-path", file=sys.stderr)
                return 1
            path = str(candidates[0])
        endpoints = [e.strip() for e in args.seed_endpoints.split(",") if e.strip()]
        seed(path, Path(path).name, endpoints)

    import uvicorn
    url = f"http://{args.host}:{args.port}"
    print(f"\n  {config.PRODUCT_NAME} {config.PRODUCT_VERSION}")
    print(f"  {url}\n")
    if args.open:
        webbrowser.open(url)
    uvicorn.run("app.api:app", host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
