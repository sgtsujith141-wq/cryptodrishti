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

from app import auth, config


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


def build_demo(endpoints_csv: str = "") -> int:
    """One command: build the fixtures, run both scans, save an override.

    Leaves the console showing every behaviour the presenter script walks
    through — an RSA signing finding and an RSA key-transport finding from the
    same algorithm, a capability-only dependency, a container image with a
    deleted key in a historical layer, an operator override, and a partial
    scan. Offline: nothing here opens a socket unless the operator names an
    endpoint themselves.
    """
    import sys as _sys
    from pathlib import Path as _Path

    _sys.path.insert(0, str(_Path(__file__).resolve().parent / "demo"))
    import build as demo_build                       # noqa: E402

    from app import assessment, orchestrator, store  # noqa: E402
    from app.engine import risk                      # noqa: E402

    store.init()
    print("\n  building demo fixtures (offline, synthetic) ...")
    built = demo_build.build(quiet=True)

    for scan in store.list_scans():
        store.delete_scan(scan["id"])
    print("  cleared previous scans")

    endpoints = [e.strip() for e in endpoints_csv.split(",") if e.strip()]
    if not endpoints:
        # Demonstration 8: a partial scan. This address is the cloud metadata
        # service; the destination policy refuses it, the scan completes with
        # the findings it did get, and the console says it is incomplete.
        endpoints = ["169.254.169.254"]

    print(f"  scanning the estate at {built['estate']} ...")
    estate = orchestrator.scan_target(
        built["estate"], label="demo-estate", endpoints=endpoints,
        progress=lambda pct, phase, detail="": None)
    store.save_scan(estate, risk.portfolio_summary(estate.findings))
    print(f"    {len(estate.findings)} assets"
          f"  complete={estate.stats.get('complete')}")

    print(f"  scanning the container image {built['image'].name} ...")
    image = orchestrator.scan_image(built["image"], label="checkout-service:2.4")
    store.save_scan(image, risk.portfolio_summary(image.findings))
    historical = image.stats.get("container_findings_historical", 0)
    print(f"    {len(image.findings)} assets across "
          f"{image.stats.get('container_layers')} layers"
          f"  ({historical} historical)")

    # Demonstration 7: a saved operator override on the RSA signing asset.
    signing = next((f for f in estate.findings
                    if f.algorithm.startswith("rsa")
                    and f.purpose == "signature"), None)
    if signing is not None:
        key = assessment.asset_key(signing)
        store.save_override(assessment.AssetOverride(
            asset_key=key, shelf_life_years=25.0, criticality=1.8,
            sensitivity="restricted", constraints=["hardware-backed"],
            note="payments signing key, HSM-backed — set for the demo"))
        rescored = orchestrator.scan_target(
            built["estate"], label="demo-estate", endpoints=endpoints,
            progress=lambda pct, phase, detail="": None)
        rescored.id = estate.id
        store.save_scan(rescored, risk.portfolio_summary(rescored.findings))
        print(f"    saved an operator override on {key[:12]} and rescored")
    else:
        print("    WARNING: no RSA signing asset found; override not saved",
              file=sys.stderr)

    print("\n  demo ready. Start the console with:  python run.py\n")
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
    ap.add_argument("--preflight-offline", action="store_true",
                    help="check the demo's fixtures and dependencies without "
                         "needing the server to be running")
    ap.add_argument("--demo", action="store_true",
                    help="build the demo fixtures, run both scans and save an "
                         "override, then exit. Offline.")
    ap.add_argument("--demo-reset", action="store_true",
                    help="wipe scans and re-seed the exact demo state, then exit")
    args = ap.parse_args()

    config.ensure_dirs()

    # Refuse to expose the console beyond this machine without an access
    # control. The API can enumerate directories, carry file contents into
    # scan evidence and open outbound connections on request; none of that
    # should be reachable from the network because someone set CD_HOST to
    # demonstrate the tool on a projector.
    try:
        auth.check_binding(args.host)
    except auth.InsecureBinding as exc:
        print(f"\n  {exc}\n", file=sys.stderr)
        return 2

    if args.preflight or args.preflight_offline:
        from app.preflight import run as preflight_run
        return preflight_run(f"http://{args.host}:{args.port}",
                             demo_only=args.preflight_offline)

    if args.demo:
        return build_demo(args.seed_endpoints)

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
    token = auth.configured_token()
    if token:
        url += f"/?token={token}"
    print(f"\n  {config.PRODUCT_NAME} {config.PRODUCT_VERSION}")
    print(f"  {url}")
    print(f"  access control: {'token (CD_TOKEN)' if token else 'none — bound to localhost'}\n")
    if args.open:
        webbrowser.open(url)
    uvicorn.run("app.api:app", host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
