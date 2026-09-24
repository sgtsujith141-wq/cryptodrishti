#!/usr/bin/env python3
"""Drive the running console through the demo walkthrough and record each state.

    python run.py --demo                                     # the demo data
    python run.py --port 8140 &                              # serve it
    python submission/build/capture_walkthrough.py --port 8140

`capture_screens.py` photographs each part of the console in isolation, which
is right for a slide and wrong for a film: a film has to show a person moving
through the product. This script does what a presenter does, in order, with
real DOM interactions -- it scrolls, hovers a row, clicks it, scrolls the
drawer that opens, presses Validate and waits for the answer, then presses
Open report and follows the tab it opens.

Each state is saved as a full-viewport frame together with the on-screen
position of the elements that matter in it (`walkthrough.json`). The film uses
those positions to aim its camera and to draw its focus ring, so the ring
lands on a real element the browser laid out, not on a rectangle guessed by
eye. Nothing is simulated: if an interaction fails, the capture fails.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "submission" / "walkthrough"

VIEW = {"width": 1440, "height": 810}   # 16:9, so a frame fills the film
SCALE = 2                               # 2880x1620 stills: crisp when cropped


def box(page, selector: str, nth: int = 0, view: dict = VIEW) -> dict | None:
    """An element's viewport rectangle, as fractions of the viewport."""
    rect = page.evaluate(
        """([s, n]) => {
             const el = document.querySelectorAll(s)[n];
             if (!el) return null;
             const r = el.getBoundingClientRect();
             return {x: r.left, y: r.top, w: r.width, h: r.height};
           }""", [selector, nth])
    if rect is None:
        return None
    return {k: round(v / (view["width"] if k in "xw" else view["height"]), 5)
            for k, v in rect.items()}


def box_text(page, needle: str) -> dict | None:
    """The block that carries `needle` -- for notices with no id of their own."""
    rect = page.evaluate(
        """n => {
             const hit = [...document.querySelectorAll('body *')].filter(e =>
               e.children.length === 0 && e.textContent.includes(n) &&
               e.getBoundingClientRect().height > 0)[0];
             if (!hit) return null;
             // climb to the notice itself: the block drawn with a rule
             let el = hit;
             while (el.parentElement &&
                    parseFloat(getComputedStyle(el).borderLeftWidth) === 0)
               el = el.parentElement;
             const r = el.getBoundingClientRect();
             return {x: r.left, y: r.top, w: r.width, h: r.height};
           }""", needle)
    if rect is None:
        return None
    return {k: round(v / (VIEW["width"] if k in "xw" else VIEW["height"]), 5)
            for k, v in rect.items()}


def top(page, selector: str, offset: int = 24) -> None:
    """Scroll so the element starts just below the top of the viewport."""
    page.evaluate(
        """([s, o]) => {
             const el = document.querySelector(s);
             window.scrollTo(0, el.getBoundingClientRect().top
                                + window.scrollY - o);
           }""", [selector, offset])
    page.wait_for_timeout(500)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8140)
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    states: list[dict] = []

    def shot(page, name: str, marks: dict, note: str) -> None:
        page.screenshot(path=str(OUT / f"{name}.png"))
        missing = [k for k, v in marks.items() if v is None]
        if missing:
            raise SystemExit(f"{name}: element(s) not on screen: {missing}")
        states.append({"name": name, "note": note, "marks": marks})
        print(f"  {name}.png  {note}")

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport=VIEW, device_scale_factor=SCALE)
        page = ctx.new_page()
        page.goto(f"http://127.0.0.1:{args.port}/?theme=dark",
                  wait_until="networkidle")
        page.wait_for_selector("#ledger .led", timeout=20_000)
        page.wait_for_timeout(900)
        # The console scrolls smoothly. A capture must not: Playwright aims
        # the pointer at where an element is when the scroll starts, so a
        # smooth scroll leaves the hover on whichever row slid under it --
        # an earlier capture showed md5 highlighted instead of the RSA row.
        page.add_style_tag(content="html{scroll-behavior:auto !important}")
        label = page.evaluate("document.getElementById('scan-path').value")
        if "demo/estate" not in label:
            raise SystemExit(f"console opened on {label!r}, not the demo "
                             "estate -- run `python run.py --demo` first")

        # 1. The assessment: what the scan found, and that it is incomplete.
        top(page, "#s-verdict", 8)
        shot(page, "w01-assessment", {
            "partial": box_text(page, "PARTIAL SCAN"),
            "vline": box(page, "#v-line"),
            "figs": box(page, "#figs"),
            "radial": box(page, "#radial"),
        }, "assessment, with the scan's own PARTIAL notice")

        # 2. The inventory, one row per distinct asset.
        top(page, "#s-record", 8)
        shot(page, "w02-inventory", {
            "row0": box(page, "#ledger .led", 0),
            "row1": box(page, "#ledger .led", 1),
            "ledger": box(page, "#ledger"),
        }, "inventory, highest risk first")

        # 3. Hover the top finding -- the RSA signing call.
        row = page.query_selector_all("#ledger .led")[0]
        first = row.inner_text()
        if "rsa" not in first.lower():
            raise SystemExit(f"top finding is not RSA: {first[:60]!r}")
        row.evaluate("r => r.scrollIntoView({block: 'start'})")
        page.wait_for_timeout(500)
        row.hover()
        page.wait_for_timeout(500)
        hovered = page.evaluate("""() => { const h = [...document
            .querySelectorAll('#ledger .led')].findIndex(r => r.matches(':hover'));
            return h; }""")
        if hovered != 0:
            raise SystemExit(f"pointer is on row {hovered}, not the RSA row")
        shot(page, "w03-hover", {"row0": box(page, "#ledger .led", 0)},
             "pointer on the RSA signing finding")

        # 4. Click it: the evidence drawer opens.
        row.click()
        page.wait_for_selector("#drawer:not([hidden])", timeout=10_000)
        page.wait_for_timeout(900)
        sections = page.evaluate(
            "document.querySelectorAll('#drawer .d-sec').length")
        marks = {"drawer": box(page, "#drawer"),
                 "head": box(page, "#drawer-body > *", 0)}
        for i in range(min(sections, 4)):
            marks[f"sec{i}"] = box(page, "#drawer .d-sec", i)
        shot(page, "w04-drawer", marks,
             "evidence drawer: purpose, assurance, proves use, exposure")

        # 5. Scroll the drawer to the exposure arithmetic.
        n = page.evaluate("""() => [...document.querySelectorAll(
            '#drawer .d-sec')].findIndex(s => /expos|mosca/i.test(
            s.querySelector('h3')?.textContent || ''))""")
        if n < 0:
            raise SystemExit("drawer has no exposure section")
        page.evaluate("""n => document.querySelectorAll('#drawer .d-sec')[n]
            .scrollIntoView({block: 'start'})""", n)
        page.wait_for_timeout(600)
        shot(page, "w05-drawer-exposure", {
            "drawer": box(page, "#drawer"),
            "exposure": box(page, "#drawer .d-sec", n),
        }, "drawer scrolled to the exposure arithmetic")
        page.click("#drawer-close")
        page.wait_for_timeout(500)

        # 6. The remediation programme.
        top(page, "#s-plan", 8)
        shot(page, "w06-plan", {"plan": box(page, "#plan-body"),
                                 "p0": box(page, "#plan-body tr", 0),
                                 "p1": box(page, "#plan-body tr", 1),
                                 "p3": box(page, "#plan-body tr", 3)},
             "remediation programme, grouped by replacement")

        # 7. Output: press Validate and wait for the verdict.
        top(page, "#s-out", 8)
        page.click("#btn-validate")
        page.wait_for_selector("#validate-result:not([hidden])",
                               timeout=20_000)
        page.wait_for_timeout(700)
        verdict = page.inner_text("#validate-result")
        shot(page, "w07-validated", {
            "result": box(page, "#validate-result"),
            "buttons": box(page, "#btn-validate"),
        }, f"CBOM validated: {verdict[:70]!r}")

        # 8. Open report: follow the tab the console opens.
        with ctx.expect_page() as popup:
            page.click("#btn-report")
        rep = popup.value
        rep.wait_for_load_state("networkidle")
        rep.wait_for_timeout(700)
        rep.screenshot(path=str(OUT / "w08-report.png"))
        states.append({"name": "w08-report", "note": "the report tab",
                       "marks": {"title": box(rep, "h1"),
                                 "grid": box(rep, ".grid"),
                                 "verdict": box(rep, ".verdict")},
                       "url": rep.url.replace(
                           f"127.0.0.1:{args.port}", "localhost")})
        print(f"  w08-report.png  {rep.url}")

        # 9. The same tab at a smaller window. At full width the report's
        #    headline is a thin strip across a wide page; at 960x540 its
        #    title, the four counts and the assessment fill one frame at a
        #    size a viewer can read without the camera cutting any of it off.
        small = {"width": 960, "height": 540}
        c3 = browser.new_context(viewport=small, device_scale_factor=3)
        near = c3.new_page()
        near.goto(rep.url, wait_until="networkidle")    # the tab's own URL
        near.wait_for_timeout(500)
        near.screenshot(path=str(OUT / "w09-report-close.png"))
        marks = {"title": box(near, "h1", view=small),
                 "grid": box(near, ".grid", view=small),
                 "verdict": box(near, ".verdict", view=small)}
        states.append({"name": "w09-report-close", "note": "the report tab, "
                       "narrower window", "marks": marks})
        print("  w09-report-close.png  the report at 960x540")

        browser.close()

    (OUT / "walkthrough.json").write_text(
        json.dumps({"viewport": VIEW, "scale": SCALE, "states": states},
                   indent=2) + "\n")
    print(f"\n{len(states)} states written to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
