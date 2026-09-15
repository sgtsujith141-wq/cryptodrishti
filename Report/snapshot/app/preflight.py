"""Pre-presentation self-test.

Run this before you walk into the room. It exercises every path the demo
depends on and prints a single verdict, so the question "is it working?" has
an answer that is not "let me click around and find out".

Checks are ordered by how badly they break the demonstration.
"""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import config

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

OK, WARN, FAIL = "ok", "warn", "fail"


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.rows.append((status, name, detail))

    @property
    def failures(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == WARN)

    def render(self) -> None:
        mark = {OK: f"{GREEN}  ok  {RESET}", WARN: f"{YELLOW} warn {RESET}",
                FAIL: f"{RED} FAIL {RESET}"}
        for status, name, detail in self.rows:
            line = f"  [{mark[status]}] {name}"
            if detail:
                line += f"\n           {DIM}{detail}{RESET}"
            print(line)


def _get(url: str, timeout: float = 20.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read()


def _post(url: str, payload: dict, timeout: float = 30.0):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read())


def run(base: str = "") -> int:
    base = base or f"http://{config.HOST}:{config.PORT}"
    rep = Report()

    print(f"\n{BOLD}  {config.PRODUCT_NAME} preflight{RESET}  {DIM}{base}{RESET}\n")

    # ---- 1. Is the server up at all? ------------------------------------
    try:
        status, body = _get(base + "/api/meta", timeout=6)
        meta = json.loads(body)
        rep.add(OK if status == 200 else FAIL, "Server responding",
                f"{meta['product']} {meta['version']}")
    except Exception as exc:
        rep.add(FAIL, "Server responding", f"{exc} -- start it with: python run.py --seed")
        rep.render()
        print(f"\n  {RED}Nothing else can be checked until the server is up.{RESET}\n")
        return 1

    # ---- 2. Console assets ----------------------------------------------
    for path, label in (("/", "console page"),
                        ("/static/app.js", "console script"),
                        ("/static/style.css", "console stylesheet")):
        try:
            status, body = _get(base + path, timeout=6)
            rep.add(OK if status == 200 and body else FAIL,
                    f"Serves {label}", f"{len(body):,} bytes")
        except Exception as exc:
            rep.add(FAIL, f"Serves {label}", str(exc))

    # ---- 3. Is there a seeded scan to open onto? -------------------------
    scan_id = ""
    try:
        _, body = _get(base + "/api/scans", timeout=8)
        scans = json.loads(body)["scans"]
        if scans:
            scan_id = scans[0]["id"]
            top = scans[0]
            rep.add(OK, "Seeded scan present",
                    f"{top['target_label']} -- {top['finding_count']} assets, "
                    f"{top['duration']:.1f}s")
            if top["finding_count"] < 20:
                rep.add(WARN, "Seeded scan is thin",
                        "Fewer than 20 assets; re-seed against demo/targets/openssl")
        else:
            rep.add(FAIL, "Seeded scan present",
                    "No scan in the database. The console will open empty. "
                    "Run: python run.py --seed --seed-path demo/targets/openssl")
    except Exception as exc:
        rep.add(FAIL, "Seeded scan present", str(exc))

    # ---- 4. The two beats that must never fail --------------------------
    if scan_id:
        try:
            _, body = _get(f"{base}/api/scan/{scan_id}/cbom/validate", timeout=20)
            v = json.loads(body)
            rep.add(OK if v["valid"] else FAIL, "CBOM validates",
                    f"{v['components']} components, {v['spec']}"
                    + ("" if v["valid"] else f" -- {v['problems'][:2]}"))
        except Exception as exc:
            rep.add(FAIL, "CBOM validates", str(exc))

        try:
            t0 = time.time()
            _, data = _post(base + "/api/qday", {
                "scan_id": scan_id, "earliest": 2028, "likely": 2030,
                "latest": 2040, "sensitivity": "restricted"}, timeout=30)
            after = data["summary"]
            _, data = _post(base + "/api/qday", {
                "scan_id": scan_id, "earliest": 2030, "likely": 2034,
                "latest": 2044, "sensitivity": "confidential"}, timeout=30)
            before = data["summary"]
            moved = after["by_severity"]["high"] - before["by_severity"]["high"]
            rep.add(OK if moved > 0 else WARN, "Q-Day slider re-ranks the estate",
                    f"2034->2030 moves {moved} assets into high; exposure "
                    f"{before['max_exposure_years']} -> {after['max_exposure_years']} years "
                    f"({time.time() - t0:.1f}s round trip)")
        except Exception as exc:
            rep.add(FAIL, "Q-Day slider re-ranks the estate", str(exc))

        try:
            _, body = _get(f"{base}/api/scan/{scan_id}/cbom?download=true", timeout=20)
            doc = json.loads(body)
            rep.add(OK, "CBOM downloads",
                    f"{len(doc.get('components', []))} components, {len(body):,} bytes")
        except Exception as exc:
            rep.add(FAIL, "CBOM downloads", str(exc))

    # ---- 5. Demo targets present ----------------------------------------
    targets = [p for p in config.TARGETS_DIR.glob("*") if p.is_dir()] \
        if config.TARGETS_DIR.exists() else []
    rep.add(OK if targets else FAIL, "Demo repositories present",
            ", ".join(p.name for p in targets) or "demo/targets is empty")

    binary_dirs = [p for p in ("/usr/local/lib", "/usr/lib") if Path(p).is_dir()]
    rep.add(OK if binary_dirs else WARN, "Binary scan target available",
            binary_dirs[0] if binary_dirs else "no system library directory found")

    # ---- 6. Air-gap ------------------------------------------------------
    #
    # XML namespace URIs are identifiers, not addresses: createElementNS needs
    # the SVG namespace string but never fetches it. Excluding them keeps the
    # check meaningful rather than noisy -- a check that cries wolf gets
    # ignored, which is worse than not having it.
    NAMESPACE_URIS = {"www.w3.org"}

    hosts = set()
    for f in list(config.WEB_DIR.glob("*")) + [Path("deck/index.html")]:
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        import re
        for m in re.finditer(r"https?://([a-zA-Z0-9.\-]+)", text):
            host = m.group(1)
            if host.startswith("127.") or host in ("localhost", *NAMESPACE_URIS):
                continue
            hosts.add(host)
    rep.add(OK if not hosts else FAIL, "Air-gap: no external hosts in the UI",
            "none" if not hosts else f"found {sorted(hosts)} -- the cable-pull will fail")

    # ---- 7. Presenter kit -----------------------------------------------
    for f, label in ((Path("deck/index.html"), "slide deck"),
                     (Path("presenter/script.md"), "timed script"),
                     (Path("presenter/qa.md"), "Q&A sheet")):
        rep.add(OK if f.is_file() else FAIL, f"Presenter {label}",
                f"{f} ({f.stat().st_size:,} bytes)" if f.is_file() else f"missing: {f}")

    # ---- 8. Optional: network sensor ------------------------------------
    try:
        socket.create_connection(("www.google.com", 443), timeout=3).close()
        from .scanners import network
        b = network.openssl_bin()
        rep.add(OK if b else WARN, "Live PQC probing available",
                f"using {b}" if b else
                "no OpenSSL 3.5+ found; the hybrid-PQC beat will report 'not determined'")
    except OSError:
        rep.add(WARN, "Network offline",
                "Expected if you have already pulled the cable. The demo does not "
                "need network -- only the live-endpoint beat does.")

    # ---- verdict ---------------------------------------------------------
    print()
    rep.render()
    print()
    if rep.failures:
        print(f"  {RED}{BOLD}{rep.failures} FAILURE(S){RESET} — fix before presenting.\n")
        return 1
    if rep.warnings:
        print(f"  {YELLOW}{BOLD}READY{RESET} with {rep.warnings} warning(s) — "
              f"none of them block the demo.\n")
        return 0
    print(f"  {GREEN}{BOLD}ALL CLEAR — you are ready to present.{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else ""))
