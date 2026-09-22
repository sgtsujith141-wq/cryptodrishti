#!/usr/bin/env python3
"""Render the deck's custom diagram panels.

    python submission/build/render_panels.py

These are not screenshots and they are not decoration. Each one answers a
question the slide would otherwise need a paragraph for, and every value in
them is a value the application actually produced -- the file paths, the
assurance grades, the algorithm names and the migration targets are copied
from a `run.py --demo` scan, not written for effect.

They are authored in HTML and rendered through headless Chromium at 2x, which
buys real typography, real layout and a design that can be edited rather than
redrawn.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import design as D  # noqa: E402

OUT = Path(__file__).resolve().parent / "generated"


# ==========================================================================
# The evidence. Verified against `run.py --demo` -- see the module docstring.
# ==========================================================================

RSA_CASES = [
    {"where": "svc-payments/signing.py:15", "surface": "source",
     "assurance": "USED", "purpose": "signature",
     "target": "ML-DSA-65", "colour": D.BROKEN, "resolved": True,
     "why": "RSA-PSS padding is a signature scheme"},
    {"where": "svc-gateway/transport.py:16", "surface": "source",
     "assurance": "USED", "purpose": "key establishment",
     "target": "X25519MLKEM768", "colour": D.BROKEN, "resolved": True,
     "why": "RSA-OAEP padding wraps a key"},
    {"where": "legacy/nginx.conf:5", "surface": "configuration",
     "assurance": "DECLARED", "purpose": "unresolved",
     "target": "Purpose must be resolved first", "colour": D.UNKNOWN,
     "resolved": False,
     "why": "a cipher list permits RSA without saying what for"},
]

SURFACES = [
    ("source", "Python AST + 7 rule packs", "svc-payments/signing.py"),
    ("dependencies", "13 manifest formats", "requirements.txt"),
    ("binaries", "ELF symbols · constants", "libcrypto.so"),
    ("configuration", "nginx · sshd · OpenSSL", "legacy/nginx.conf"),
    ("certificates", "X.509 · PEM/DER · KeyUsage", "gateway.pem"),
    ("containers", "OCI · docker save · layers", "checkout-service.tar"),
]

STAGES = [
    ("Discover", "seven sensors read what is present",
     "23 assets from one estate scan"),
    ("Prioritise", "purpose-specific Mosca exposure",
     "16 quantum-vulnerable · 2 critical"),
    ("Plan", "a named target per resolved purpose",
     "grouped into 7 workstreams"),
    ("Export", "CycloneDX 1.6 / 1.7 + HTML report",
     "validated against the official schema"),
]


# ==========================================================================
# Panels
# ==========================================================================

def panel_rsa() -> tuple[str, str, int, int]:
    """The signature visual: one algorithm, three answers."""
    rows = []
    for case in RSA_CASES:
        target_cls = "t-open" if not case["resolved"] else "t-set"
        arrow = "→" if case["resolved"] else "?"
        rows.append(f"""
        <div class="row" style="--c:{case['colour']}">
          <div class="algo mono">rsa</div>
          <div class="ev">
            <div class="where mono">{case['where']}</div>
            <div class="sub"><span class="surface">{case['surface']}</span>
              <span class="asr mono">{case['assurance']}</span></div>
          </div>
          <div class="purpose">
            <div class="plabel">{case['purpose']}</div>
            <div class="why">{case['why']}</div>
          </div>
          <div class="arrow">{arrow}</div>
          <div class="target {target_cls} mono">{case['target']}</div>
        </div>""")

    css = f"""
    body {{ padding: 40px 46px; }}
    .head {{ display:flex; align-items:baseline; gap:18px; margin-bottom:6px; }}
    .head h1 {{ font-size:40px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .head .note {{ font-size:19px; color:{D.INK3}; }}
    .cols {{ display:grid; grid-template-columns:104px 1fr 1fr 44px 1.15fr;
             gap:0 26px; padding:22px 0 9px 22px; }}
    .cols div {{ font-family:{D.MONO}; font-size:13px; letter-spacing:.13em;
                 text-transform:uppercase; color:{D.INK4}; font-weight:600; }}
    .row {{ display:grid; grid-template-columns:104px 1fr 1fr 44px 1.15fr;
            gap:0 26px; align-items:center;
            padding:25px 0 25px 22px; border-top:1px solid {D.RULE};
            position:relative; }}
    .row::before {{ content:""; position:absolute; left:0; top:-1px; bottom:0;
                    width:4px; background:var(--c); }}
    .algo {{ font-size:32px; font-weight:600; color:{D.INK}; }}
    .where {{ font-size:20px; color:{D.INK}; }}
    .sub {{ margin-top:9px; display:flex; align-items:center; gap:12px; }}
    .surface {{ font-size:16px; color:{D.INK3}; }}
    .asr {{ font-size:12px; letter-spacing:.1em; color:{D.INK2};
            border:1px solid {D.RULE2}; border-radius:2px; padding:3px 8px; }}
    .plabel {{ font-size:25px; font-weight:600; color:var(--c); }}
    .why {{ font-size:16px; color:{D.INK3}; margin-top:7px; }}
    .arrow {{ font-size:27px; color:{D.INK4}; text-align:center; }}
    .target {{ font-size:22px; padding:13px 17px; border-radius:3px;
               background:{D.SURF}; border:1px solid {D.RULE}; }}
    .t-set {{ color:{D.SAFE}; border-color:rgba(63,174,134,.42); }}
    .t-open {{ color:{D.INK3}; font-style:italic; font-size:19px; }}
    """
    body = f"""
    <div class="head"><h1>Same algorithm. Three answers.</h1>
      <div class="note">One scan · five RSA findings</div></div>
    <div class="cols"><div>algorithm</div><div>evidence</div>
      <div>resolved purpose</div><div></div><div>migration target</div></div>
    {''.join(rows)}"""
    return body, css, 1680, 640


def panel_surfaces() -> tuple[str, str, int, int]:
    """Fragmented surfaces converge into one inventory."""
    chips = "".join(f"""
      <div class="surf">
        <div class="sname">{name}</div>
        <div class="sdesc">{desc}</div>
        <div class="sref mono">{ref}</div>
      </div>""" for name, desc, ref in SURFACES)

    css = f"""
    body {{ padding: 34px 40px; }}
    .wrap {{ display:grid; grid-template-columns:1fr 132px 1fr;
             align-items:start; gap:0 8px; }}
    .grid {{ display:grid; grid-template-columns:repeat(2,1fr); gap:13px; }}
    .surf {{ background:{D.SURF}; border:1px solid {D.RULE}; border-radius:3px;
             padding:15px 17px; }}
    .sname {{ font-size:20px; font-weight:600; color:{D.INK}; }}
    .sdesc {{ font-size:14px; color:{D.INK3}; margin-top:5px; }}
    .sref {{ font-size:13px; color:{D.INK4}; margin-top:9px; }}
    .mid {{ text-align:center; padding-top:170px; }}
    .mid .a {{ font-size:34px; color:{D.INK4}; line-height:1; }}
    .net {{ margin-top:14px; font-size:15px; color:{D.INK3};
            border-top:1px solid {D.RULE}; padding-top:13px; }}
    .net b {{ color:{D.INK2}; font-weight:600; }}
    .out {{ display:grid; gap:13px; }}
    .ocard {{ background:{D.SURF2}; border:1px solid {D.RULE2};
              border-left:4px solid {D.ACCENT}; border-radius:3px;
              padding:17px 19px; }}
    .otitle {{ font-size:21px; font-weight:600; }}
    .odesc {{ font-size:15px; color:{D.INK2}; margin-top:6px; }}
    """
    body = f"""
    <div class="wrap">
      <div>
        <div class="eyebrow" style="margin-bottom:13px">scattered evidence</div>
        <div class="grid">{chips}</div>
        <div class="net"><b>and one live TLS endpoint the operator names</b> —
          the only outbound path, refused unless it passes the destination
          policy. Everything above runs with the network unplugged.</div>
      </div>
      <div class="mid"><div class="a">→</div></div>
      <div>
        <div class="eyebrow" style="margin-bottom:13px">one explainable inventory</div>
        <div class="out">
          <div class="ocard"><div class="otitle">Distinct assets, not detector hits</div>
            <div class="odesc">Purpose and assurance are part of an asset's identity.</div></div>
          <div class="ocard"><div class="otitle">Exposure you can argue with</div>
            <div class="odesc">Mosca X+Y&gt;Z, every input labelled with where its value came from.</div></div>
          <div class="ocard"><div class="otitle">A CBOM a tool can consume</div>
            <div class="odesc">CycloneDX 1.6 / 1.7, validated against the official schema.</div></div>
        </div>
      </div>
    </div>"""
    return body, css, 1680, 700


def panel_pipeline() -> tuple[str, str, int, int]:
    """The implemented workflow, compact."""
    steps = [("evidence", "seven sensors"), ("normalise", "hits → assets"),
             ("classify", "Shor / Grover / safe"), ("risk", "purpose-specific Mosca"),
             ("recommend", "target or nothing"), ("CBOM", "schema-validated")]
    cells = "".join(f"""
      <div class="st"><div class="n mono">{i+1}</div>
        <div class="sn">{n}</div><div class="sd">{d}</div></div>"""
                    + ("" if i == len(steps) - 1 else '<div class="ar">→</div>')
                    for i, (n, d) in enumerate(steps))
    css = f"""
    body {{ padding:26px 34px; }}
    .strip {{ display:flex; align-items:center; gap:14px; }}
    .st {{ flex:1; background:{D.SURF}; border:1px solid {D.RULE};
           border-radius:3px; padding:15px 14px; }}
    .n {{ font-size:12px; color:{D.INK4}; }}
    .sn {{ font-size:20px; font-weight:600; margin-top:5px; }}
    .sd {{ font-size:14px; color:{D.INK3}; margin-top:5px; }}
    .ar {{ color:{D.INK4}; font-size:20px; }}
    """
    return f'<div class="strip">{cells}</div>', css, 1680, 150


def panel_workflow() -> tuple[str, str, int, int]:
    """Discover → prioritise → plan → export, each tied to a real result."""
    cells = "".join(f"""
      <div class="st">
        <div class="eyebrow">{i+1:02d}</div>
        <div class="sn">{name}</div>
        <div class="sd">{what}</div>
        <div class="sr mono">{proof}</div>
      </div>""" for i, (name, what, proof) in enumerate(STAGES))
    css = f"""
    body {{ padding:28px 34px; }}
    .strip {{ display:grid; grid-template-columns:repeat(4,1fr); gap:15px; }}
    .st {{ background:{D.SURF}; border:1px solid {D.RULE};
           border-top:3px solid {D.ACCENT}; border-radius:3px; padding:18px 17px; }}
    .sn {{ font-size:25px; font-weight:700; margin-top:9px; }}
    .sd {{ font-size:15px; color:{D.INK2}; margin-top:8px; min-height:42px; }}
    .sr {{ font-size:14px; color:{D.SAFE}; margin-top:11px;
           padding-top:11px; border-top:1px solid {D.RULE}; }}
    """
    return f'<div class="strip">{cells}</div>', css, 1680, 330


def panel_benchmark() -> tuple[str, str, int, int]:
    """Two corpora, reported separately, with the caveat attached."""
    css = f"""
    body {{ padding:28px 34px; }}
    .two {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
    .b {{ background:{D.SURF}; border:1px solid {D.RULE}; border-radius:3px;
          padding:19px 21px; }}
    .bt {{ font-size:19px; font-weight:700; }}
    .bs {{ font-size:14px; color:{D.INK3}; margin-top:5px; min-height:34px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:11px;
             font-family:{D.MONO}; font-size:15px; }}
    th {{ font-size:12px; letter-spacing:.1em; text-transform:uppercase;
          color:{D.INK4}; text-align:right; font-weight:600; padding:5px 0; }}
    th:first-child, td:first-child {{ text-align:left; }}
    td {{ text-align:right; padding:6px 0; border-top:1px solid {D.RULE};
          color:{D.INK}; }}
    .lab {{ color:{D.INK2}; }}
    .gain {{ color:{D.SAFE}; }}
    .caveat {{ margin-top:15px; font-size:15px; color:{D.INK2};
               border-left:3px solid {D.ACCENT}; padding-left:14px;
               line-height:1.5; }}
    """
    body = f"""
    <div class="two">
      <div class="b">
        <div class="bt">Did the work improve the detectors?</div>
        <div class="bs">Same corpus, before and after. This is the
          like-for-like comparison.</div>
        <table>
          <tr><th>corpus 1.0.0</th><th>TP</th><th>FP</th><th>FN</th><th>F1</th></tr>
          <tr><td class="lab">before</td><td>79</td><td>5</td><td>5</td><td>0.941</td></tr>
          <tr><td class="lab">after</td><td>84</td><td>3</td><td>0</td><td class="gain">0.983</td></tr>
        </table>
      </div>
      <div class="b">
        <div class="bt">What does the current corpus say?</div>
        <div class="bs">Expanded to cover three sensors the original did not
          exercise. Not comparable to the panel on the left.</div>
        <table>
          <tr><th>corpus 1.2.0</th><th>TP</th><th>FP</th><th>FN</th><th>F1</th></tr>
          <tr><td class="lab">six scanners</td><td>116</td><td>0</td><td>0</td><td>1.000</td></tr>
        </table>
      </div>
    </div>
    <div class="caveat"><strong>Both are synthetic corpora this project wrote.</strong>
      Neither measures accuracy on unseen enterprise repositories, which has not
      been measured and is not claimed. Network-sensor accuracy is excluded, because
      what a TLS handshake negotiates depends on the local library build.</div>
    """
    return body, css, 1680, 430


PANELS = {
    "rsa-answers": panel_rsa,
    "surfaces": panel_surfaces,
    "pipeline": panel_pipeline,
    "workflow": panel_workflow,
    "benchmark": panel_benchmark,
}


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright required: .venv/bin/python -m pip install playwright",
              file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for name, build in PANELS.items():
            body, css, w, h = build()
            page = browser.new_page(viewport={"width": w, "height": h},
                                    device_scale_factor=2)
            page.set_content(D.page(body, css, w, h), wait_until="load")
            page.wait_for_timeout(180)
            # Auto-fit: measure where the content actually ends and crop to it,
            # rather than guessing a height and shipping a band of empty panel.
            bottom = page.evaluate("""() => {
                let m = 0;
                for (const el of document.body.querySelectorAll('*')) {
                    const r = el.getBoundingClientRect();
                    if (r.width && r.height) m = Math.max(m, r.bottom);
                }
                const pad = parseFloat(getComputedStyle(document.body).paddingBottom) || 0;
                return Math.ceil(m + pad);
            }""")
            fitted = max(60, min(h, int(bottom)))
            path = OUT / f"{name}.png"
            page.screenshot(path=str(path),
                            clip={"x": 0, "y": 0, "width": w, "height": fitted})
            page.close()
            print(f"  {name:14s} {w}x{fitted} -> {path.relative_to(Path.cwd())}")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
