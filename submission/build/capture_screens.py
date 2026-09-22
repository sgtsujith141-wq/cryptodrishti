#!/usr/bin/env python3
"""Capture the console's screenshots for the deck, the README and the video.

    python run.py --demo                                   # populate the data
    python run.py --port 8140 &                            # serve it
    python submission/build/capture_screens.py --port 8140

Every image is a capture of the running application against the database that
`run.py --demo` produces. Nothing is mocked, composed or retouched.

Two deliberate choices:

* **Dark theme.** Forced through `?theme=dark` rather than by clicking the
  toggle, so a capture never depends on what the last person left in
  `localStorage`.
* **Element-tight.** Each shot is of the scene element itself, not the whole
  viewport. A viewport grab is mostly empty page, which is why the earlier
  captures had to be trimmed afterwards and still read small on a slide.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "submission" / "screenshots"

# scene element -> output name. The order is the console's own.
SCENES = [
    ("#s-verdict", "01-assessment.png"),
    ("#s-clock", "02-exposure.png"),
    ("#s-plan", "03-migration-plan.png"),
    ("#s-record", "04-inventory.png"),
    ("#s-out", "05-cbom-export.png"),
    ("#s-history", "06-scan-history.png"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8140)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is not installed in this environment:\n"
              "  .venv/bin/python -m pip install playwright\n"
              "  .venv/bin/python -m playwright install chromium",
              file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    url = f"http://127.0.0.1:{args.port}/?theme=dark"

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(
            viewport={"width": 1680, "height": 1050},
            device_scale_factor=2)
        page.goto(url, wait_until="networkidle")
        # The console loads the latest scan and renders every scene from it.
        page.wait_for_selector("#ledger .led", timeout=20_000)
        page.wait_for_timeout(900)

        for selector, name in SCENES:
            node = page.query_selector(selector)
            if node is None:
                print(f"  MISSING {selector}", file=sys.stderr)
                return 1
            node.scroll_into_view_if_needed()
            page.wait_for_timeout(450)
            node.screenshot(path=str(out / name))
            print(f"  {name}")

        # The evidence drawer is the product's whole argument in one panel, so
        # it is captured from the highest-risk finding rather than an arbitrary
        # one: the RSA signing call the demo also puts an override on.
        page.query_selector("#s-record").scroll_into_view_if_needed()
        page.wait_for_timeout(300)
        page.query_selector("#ledger .led").click()
        page.wait_for_selector("#drawer:not([hidden])", timeout=10_000)
        page.wait_for_timeout(900)
        page.query_selector("#drawer").screenshot(
            path=str(out / "07-evidence-drawer.png"))
        print("  07-evidence-drawer.png")

        browser.close()

    print(f"\n{len(SCENES) + 1} dark-theme captures written to "
          f"{out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
