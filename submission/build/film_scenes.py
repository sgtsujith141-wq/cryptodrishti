#!/usr/bin/env python3
"""Scene definitions for the CryptoDrishti demonstration film.

Every value that appears on screen -- a file path, an algorithm name, a score,
a migration target, a count -- is a value `python run.py --demo` actually
produced. Nothing here is written for effect. Where the tool declines to
answer, the film shows it declining.

The film is designed **caption-first**: it has to carry its argument with the
sound off. Narration is a supporting layer, not the load-bearing one.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import design as D  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SHOTS = ROOT / "submission" / "screenshots"

def embed(path: Path, box: tuple[float, float, float, float] | None = None,
          max_w: int = 1600) -> str:
    """Inline an image as a data URI, optionally cropped by fractions.

    `page.set_content()` gives the document an `about:blank` base URL, and
    Chromium refuses to load `file://` subresources into such a page. Every
    screenshot in earlier cuts of this film therefore failed silently and
    rendered as an empty dark panel -- the film shipped with no product
    footage in it at all. Inlining the bytes removes the possibility.
    """
    import base64
    import io

    from PIL import Image

    im = Image.open(path).convert("RGB")
    if box:
        l, t, r, b = box
        im = im.crop((int(im.width * l), int(im.height * t),
                      int(im.width * r), int(im.height * b)))
    if im.width > max_w:
        im = im.resize((max_w, round(im.height * max_w / im.width)),
                       Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# --------------------------------------------------------------------------
# Verified evidence
# --------------------------------------------------------------------------

FRAGMENTS = [
    ("svc-payments/signing.py:15", "padding.PSS(...)"),
    ("svc-gateway/requirements.txt", "pycryptodome==3.19.0"),
    ("legacy/nginx.conf:5", "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;"),
    ("svc-cache/digest.py:12", "hashlib.md5(...)"),
    ("checkout-service:2.4", "/etc/ssl/private/deploy.key"),
    ("legacy/nginx.conf:4", "ssl_protocols TLSv1.1 TLSv1.2;"),
    ("svc-gateway/transport.py:16", "padding.OAEP(...)"),
    ("gateway.pem", "X.509 · sha256WithRSAEncryption"),
]

RSA = [
    dict(where="svc-payments/signing.py:15", surface="source", asr="USED",
         purpose="signature", why="RSA-PSS padding is a signature scheme",
         target="ML-DSA-65", open=False),
    dict(where="svc-gateway/transport.py:16", surface="source", asr="USED",
         purpose="key establishment", why="RSA-OAEP padding wraps a key",
         target="X25519MLKEM768", open=False),
    dict(where="legacy/nginx.conf:5", surface="configuration", asr="DECLARED",
         purpose="unresolved",
         why="a cipher list permits RSA without saying what for",
         target="Purpose must be resolved first", open=True),
]

CHAIN = [
    ("evidence", "svc-payments/signing.py:15", "the call site"),
    ("symbol", "padding.PSS", "what was matched"),
    ("technique", "source-ast-analysis", "how, not a guess"),
    ("confidence", "0.92", "how sure the sensor is"),
    ("assurance", "used", "a call site, not a manifest"),
    ("class", "shor-broken", "a quantum computer breaks it outright"),
    ("purpose", "signature", "resolved from the padding scheme"),
    ("exposure", "19.7 yr", "X 25 + Y 2 − Z 7.28, under the chosen scenario"),
    ("target", "ML-DSA-65", "the migration that matches the purpose"),
]


def _frag_positions():
    """Scatter the fragments without overlapping. Fixed, not random."""
    return [(6, 16), (52, 9), (10, 31), (58, 26), (4, 47), (46, 42),
            (14, 62), (55, 58)]


# --------------------------------------------------------------------------
# Scene builders -- each returns (body, css, beats_ms)
# --------------------------------------------------------------------------

def sc_open():
    frags = []
    for i, ((where, code), (x, y)) in enumerate(zip(FRAGMENTS, _frag_positions())):
        t = 120 + i * 560
        frags.append(f"""
        <div class="frag" style="left:{x}%; top:{y}%" data-in="{t}" data-dur="620" data-y="10">
          <div class="fc mono">{code}</div>
          <div class="fw mono">{where}</div>
        </div>""")
    css = f"""
    .stage {{ position:absolute; inset:0; }}
    .frag {{ position:absolute; opacity:0; max-width:34%; }}
    .fc {{ font-size:25px; color:{D.INK2}; }}
    .fw {{ font-size:17px; color:{D.INK4}; margin-top:6px; }}
    .line {{ position:absolute; left:8%; top:82%; opacity:0; font-size:34px;
             color:{D.INK}; font-weight:600; max-width:62%; line-height:1.34; }}
    """
    body = f"""<div class="stage">{''.join(frags)}
      <div class="line" data-in="4900" data-dur="900" data-y="14">
        Cryptography is not in one place.<br>It is in all of them.</div>
    </div>"""
    return body, css, 7000


def sc_name():
    css = f"""
    .wrap {{ position:absolute; left:8%; top:50%; transform:translateY(-50%); }}
    .nm {{ font-size:104px; font-weight:700; letter-spacing:-.025em;
           color:{D.INK}; opacity:0; }}
    .bar {{ width:0; height:5px; background:{D.ACCENT}; margin:26px 0 0; }}
    .sub {{ font-size:30px; color:{D.INK2}; margin-top:30px; opacity:0;
            line-height:1.5; }}
    """
    body = f"""<div class="wrap">
      <div class="nm" data-in="200" data-dur="850" data-y="18">CryptoDrishti</div>
      <div class="bar" data-in="900" data-dur="700" data-grow="230"></div>
      <div class="sub" data-in="1350" data-dur="800" data-y="12">
        Cryptographic discovery.  Quantum-risk analysis.<br>
        Evidence-backed migration planning.</div>
    </div>"""
    return body, css, 4200


def sc_structure():
    rows = []
    for i, (where, code) in enumerate(FRAGMENTS[:6]):
        rows.append(f"""
        <div class="r" data-in="{700 + i*260}" data-dur="560" data-y="16">
          <div class="c1 mono">{where}</div>
          <div class="c2 mono">{code}</div>
        </div>""")
    css = f"""
    .hd {{ position:absolute; left:8%; top:13%; opacity:0; }}
    .hd h2 {{ font-size:44px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .hd p {{ font-size:25px; color:{D.INK3}; margin:14px 0 0; }}
    .tbl {{ position:absolute; left:8%; right:8%; top:36%; }}
    .r {{ display:grid; grid-template-columns:1fr 1.25fr; gap:32px;
          padding:15px 0; border-top:1px solid {D.RULE}; opacity:0; }}
    .c1 {{ font-size:22px; color:{D.INK}; }}
    .c2 {{ font-size:22px; color:{D.INK3}; }}
    """
    body = f"""
    <div class="hd" data-in="120" data-dur="700" data-y="12">
      <h2>Scattered evidence becomes structure</h2>
      <p>Seven sensors. One row per distinct cryptographic asset.</p></div>
    <div class="tbl">{''.join(rows)}</div>"""
    return body, css, 3400


def sc_dashboard():
    css = f"""
    .cap {{ position:absolute; left:5%; top:6.5%; opacity:0; }}
    .cap h2 {{ font-size:38px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .cap p {{ font-size:21px; color:{D.INK3}; margin:10px 0 0; }}
    /* The screenshot is the subject: it is fitted inside the frame rather
       than scaled to full width, which previously pushed most of it below
       the bottom edge where it read as an empty dark panel. */
    .shot {{ position:absolute; left:5%; right:5%; top:23%; bottom:6%;
             opacity:0; border:1px solid {D.RULE2}; border-radius:5px;
             overflow:hidden; background:{D.SURF};
             display:flex; align-items:center; justify-content:center; }}
    .shot img {{ max-width:100%; max-height:100%; object-fit:contain;
                 display:block; }}
    """
    body = f"""
    <div class="cap" data-in="120" data-dur="700" data-y="12">
      <h2>One scan of the demo estate</h2>
      <p>23 distinct assets · 16 quantum-vulnerable · the scan's own
         completeness stated at the top</p></div>
    <div class="shot" data-in="700" data-dur="900" data-y="20" data-scale="1.03">
      <img src="{embed(SHOTS / '01-assessment.png', (0.055, 0.03, 1.0, 0.92))}"></div>"""
    return body, css, 4200


def sc_rsa():
    rows = []
    for i, c in enumerate(RSA):
        base = 600 + i * 2500
        tone = D.UNKNOWN if c["open"] else D.BROKEN
        tcls = "t-open" if c["open"] else "t-set"
        rows.append(f"""
        <div class="row" style="--c:{tone}">
          <div class="algo mono" data-in="{base}" data-dur="420" data-y="8">rsa</div>
          <div class="ev" data-in="{base+180}" data-dur="480" data-y="10">
            <div class="w mono">{c['where']}</div>
            <div class="s"><span>{c['surface']}</span>
              <span class="asr mono">{c['asr']}</span></div></div>
          <div class="pu" data-in="{base+900}" data-dur="520" data-y="10">
            <div class="pl">{c['purpose']}</div>
            <div class="wy">{c['why']}</div></div>
          <div class="ar" data-in="{base+1500}" data-dur="380">{'?' if c['open'] else '→'}</div>
          <div class="tg {tcls} mono" data-in="{base+1650}" data-dur="560" data-y="10">{c['target']}</div>
        </div>""")
    css = f"""
    .hd {{ position:absolute; left:5%; top:8%; opacity:0; }}
    .hd h2 {{ font-size:46px; margin:0; font-weight:700; letter-spacing:-.022em; }}
    .hd p {{ font-size:24px; color:{D.INK3}; margin:13px 0 0; }}
    .tbl {{ position:absolute; left:5%; right:5%; top:27%; }}
    .row {{ display:grid; grid-template-columns:110px 1.05fr 1.05fr 52px 1.1fr;
            gap:0 26px; align-items:center; padding:32px 0 32px 24px;
            border-top:1px solid {D.RULE}; position:relative; }}
    .row::before {{ content:""; position:absolute; left:0; top:-1px; bottom:0;
                    width:4px; background:var(--c); }}
    .row > * {{ opacity:0; }}
    .algo {{ font-size:34px; font-weight:600; }}
    .w {{ font-size:22px; }}
    .s {{ margin-top:9px; display:flex; gap:12px; align-items:center;
          font-size:17px; color:{D.INK3}; }}
    .asr {{ font-size:13px; letter-spacing:.1em; color:{D.INK2};
            border:1px solid {D.RULE2}; border-radius:2px; padding:3px 9px; }}
    .pl {{ font-size:27px; font-weight:600; color:var(--c); }}
    .wy {{ font-size:17px; color:{D.INK3}; margin-top:7px; }}
    .ar {{ font-size:29px; color:{D.INK4}; text-align:center; }}
    .tg {{ font-size:24px; padding:14px 18px; border-radius:3px;
           background:{D.SURF}; border:1px solid {D.RULE}; }}
    .t-set {{ color:{D.SAFE}; border-color:rgba(63,174,134,.42); }}
    .t-open {{ color:{D.INK3}; font-style:italic; font-size:20px; }}
    .kick {{ position:absolute; left:5%; bottom:15%; opacity:0;
             font-size:32px; font-weight:600; color:{D.INK}; }}
    .kick b {{ color:{D.ACCENT}; font-weight:600; }}
    """
    body = f"""
    <div class="hd" data-in="60" data-dur="640" data-y="12">
      <h2>Same algorithm. Three answers.</h2>
      <p>One scan · five RSA findings</p></div>
    <div class="tbl">{''.join(rows)}</div>
    <div class="kick" data-in="8400" data-dur="800" data-y="12">
      Knowing the algorithm is not enough. <b>Purpose decides the migration.</b></div>"""
    return body, css, 10200


def sc_chain():
    items = []
    for i, (k, v, note) in enumerate(CHAIN):
        t = 400 + i * 620
        items.append(f"""
        <div class="st" data-in="{t}" data-dur="480" data-y="12">
          <div class="k mono">{k}</div>
          <div class="v mono">{v}</div>
          <div class="n">{note}</div></div>""")
    css = f"""
    .hd {{ position:absolute; left:6%; top:9%; opacity:0; }}
    .hd h2 {{ font-size:42px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .hd p {{ font-size:23px; color:{D.INK3}; margin:12px 0 0; }}
    .col {{ position:absolute; left:6%; right:6%; top:25%;
            display:grid; grid-template-columns:repeat(3,1fr); gap:46px 26px; }}
    .st {{ opacity:0; border-left:3px solid {D.ACCENT}; padding:11px 0 11px 17px; }}
    .k {{ font-size:14px; letter-spacing:.12em; text-transform:uppercase;
          color:{D.INK4}; }}
    .v {{ font-size:29px; color:{D.INK}; margin-top:9px; }}
    .n {{ font-size:17px; color:{D.INK3}; margin-top:8px; }}
    """
    body = f"""
    <div class="hd" data-in="60" data-dur="640" data-y="12">
      <h2>One finding, followed all the way down</h2>
      <p>Nothing in this chain is inferred — each step is recorded against
         the asset</p></div>
    <div class="col">{''.join(items)}</div>"""
    return body, css, 6400


def sc_drawer():
    css = f"""
    .cap {{ position:absolute; left:5%; top:10%; opacity:0; width:33%; }}
    .cap h2 {{ font-size:36px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .cap p {{ font-size:20px; color:{D.INK3}; margin:16px 0 0; line-height:1.55; }}
    .shot {{ position:absolute; left:41%; right:5%; top:6%; bottom:6%;
             opacity:0; border:1px solid {D.RULE2}; border-radius:5px;
             overflow:hidden; background:{D.SURF};
             display:flex; align-items:center; justify-content:center; }}
    .shot img {{ max-width:100%; max-height:100%; object-fit:contain;
                 display:block; }}
    """
    body = f"""
    <div class="cap" data-in="200" data-dur="760" data-y="12">
      <h2>And it is in the product</h2>
      <p>The same chain, in the console. Every finding opens onto the evidence
         behind it and the arithmetic behind its score — including which
         inputs a human set by hand.</p></div>
    <div class="shot" data-in="500" data-dur="900" data-y="16" data-scale="1.02">
      <img src="{embed(SHOTS / '07-evidence-drawer.png', (0.0, 0.0, 1.0, 0.56), 900)}"></div>"""
    return body, css, 5000


def sc_honest():
    css = f"""
    .hd {{ position:absolute; left:6%; top:9%; opacity:0; }}
    .hd h2 {{ font-size:42px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .two {{ position:absolute; left:6%; right:6%; top:27%;
            display:grid; grid-template-columns:1fr 1fr; gap:30px; }}
    .b {{ opacity:0; background:{D.SURF}; border:1px solid {D.RULE};
          border-left:4px solid var(--c); border-radius:3px; padding:26px 28px; }}
    .bt {{ font-size:27px; font-weight:700; color:var(--c); }}
    .bd {{ font-size:20px; color:{D.INK2}; margin-top:14px; line-height:1.55; }}
    .bm {{ font-family:{D.MONO}; font-size:17px; color:{D.INK3}; margin-top:16px;
           padding-top:14px; border-top:1px solid {D.RULE}; }}
    """
    body = f"""
    <div class="hd" data-in="60" data-dur="640" data-y="12">
      <h2>What it did not see is on the record</h2></div>
    <div class="two">
      <div class="b" style="--c:{D.WEAKENED}" data-in="600" data-dur="700" data-y="14">
        <div class="bt">Deleted is not gone</div>
        <div class="bd">A container image is read layer by layer. A key written
          in one layer and removed in the next is reported as
          <b>historical</b> — not on the running filesystem, still extractable
          from the archive.</div>
        <div class="bm">checkout-service:2.4 · 15 assets · 2 layers · 1 historical</div>
      </div>
      <div class="b" style="--c:{D.BROKEN}" data-in="1500" data-dur="700" data-y="14">
        <div class="bt">Partial is not complete</div>
        <div class="bd">One endpoint was refused by the destination policy, so
          the scan is marked <b>PARTIAL</b> and says why. The flag travels into
          the console, the report and the CBOM.</div>
        <div class="bm">refused 169.254.169.254 — cloud instance metadata service</div>
      </div>
    </div>"""
    return body, css, 5600


def sc_cbom():
    fields = [("bomFormat", "CycloneDX"), ("specVersion", "1.6"),
              ("component.type", "cryptographic-asset"),
              ("cryptoProperties", "assetType · primitive · purpose"),
              ("evidence.occurrences", "location · line · technique")]
    rows = "".join(f"""
      <div class="f" data-in="{700+i*440}" data-dur="460" data-y="10">
        <span class="k mono">{k}</span><span class="v mono">{v}</span></div>"""
                   for i, (k, v) in enumerate(fields))
    css = f"""
    .hd {{ position:absolute; left:6%; top:9%; opacity:0; width:42%; }}
    .hd h2 {{ font-size:40px; margin:0; font-weight:700; letter-spacing:-.02em; }}
    .hd p {{ font-size:21px; color:{D.INK3}; margin:14px 0 0; line-height:1.55; }}
    .fl {{ position:absolute; left:6%; top:38%; width:42%; }}
    .f {{ opacity:0; display:flex; justify-content:space-between; gap:20px;
          padding:12px 0; border-top:1px solid {D.RULE}; }}
    .k {{ font-size:19px; color:{D.INK3}; }}
    .v {{ font-size:19px; color:{D.INK}; text-align:right; }}
    .pass {{ position:absolute; left:6%; bottom:11%; opacity:0;
             display:inline-flex; align-items:center; gap:14px;
             border:1px solid rgba(63,174,134,.45); border-radius:3px;
             padding:15px 22px; background:rgba(63,174,134,.08); }}
    .pass .d {{ width:11px; height:11px; border-radius:50%; background:{D.SAFE}; }}
    .pass .t {{ font-size:23px; color:{D.SAFE}; font-weight:600; }}
    .shot {{ position:absolute; right:4%; left:53%; top:24%; height:36%;
             opacity:0; border:1px solid {D.RULE2}; border-radius:5px;
             overflow:hidden; background:{D.SURF};
             display:flex; align-items:center; justify-content:center; }}
    .shot img {{ max-width:100%; max-height:100%; object-fit:contain;
                 display:block; }}
    """
    body = f"""
    <div class="hd" data-in="60" data-dur="640" data-y="12">
      <h2>An output a tool can consume</h2>
      <p>Not a bespoke report — CycloneDX, the published standard for a
         cryptographic bill of materials.</p></div>
    <div class="fl">{rows}</div>
    <div class="pass" data-in="3100" data-dur="620" data-y="10">
      <span class="d"></span><span class="t">Validated against the official
      CycloneDX JSON Schema — offline, at a pinned commit</span></div>
    <div class="shot" data-in="1400" data-dur="800" data-y="14" data-scale="1.02">
      <img src="{embed(SHOTS / '05-cbom-export.png', (0.055, 0.27, 1.0, 0.76))}"></div>"""
    return body, css, 5400


def sc_close():
    css = f"""
    .wrap {{ position:absolute; left:8%; top:50%; transform:translateY(-50%); }}
    .l {{ font-size:36px; color:{D.INK2}; opacity:0; line-height:1.5; }}
    .nm {{ font-size:84px; font-weight:700; letter-spacing:-.025em;
           color:{D.INK}; opacity:0; margin-top:42px; }}
    .bar {{ width:0; height:4px; background:{D.ACCENT}; margin:22px 0 0; }}
    .meta {{ font-size:25px; color:{D.INK3}; margin-top:26px; opacity:0;
             line-height:1.6; }}
    .meta .mono {{ color:{D.INK2}; }}
    """
    body = f"""<div class="wrap">
      <div class="l" data-in="200" data-dur="900" data-y="14">
        Scattered evidence. One explainable inventory.<br>
        A migration decision you can defend.</div>
      <div class="nm" data-in="1300" data-dur="800" data-y="14">CryptoDrishti</div>
      <div class="bar" data-in="1900" data-dur="700" data-grow="190"></div>
      <div class="meta" data-in="2300" data-dur="800" data-y="10">
        Team <span class="mono">146876 — Zero-Day</span><br>
        Problem statement <span class="mono">SIH26164</span> ·
        <span class="mono">github.com/sgtsujith141-wq/cryptodrishti</span></div>
    </div>"""
    return body, css, 6000


# `say` is spelled for the speech synthesiser; `cap` is spelled for a reader.
# They must carry the same meaning -- the caption is what survives with the
# sound off, and it is the version a viewer will quote.
#
# `beats` is a *minimum hold* for the scene, not its choreography length. The
# choreography end is whatever the builder returns, and the renderer maps one
# onto the other, so a reveal stretches across a long narration line instead of
# finishing early and leaving the frame dead.

SCENES = [
    dict(id="open", build=sc_open, beats=21500,
         say="Every organisation runs cryptography it cannot fully see. A "
             "call inside a payments service. A version pin in a dependency "
             "file. A cipher list nobody has opened in years. The signature "
             "algorithm on a certificate. A private key baked into a "
             "container image that shipped months ago. Six kinds of artefact, "
             "and no two of them describe cryptography the same way.",
         cap="Every organisation runs cryptography it cannot fully see. "
             "A call inside a payments service. A version pin in a dependency "
             "file. A cipher list in an nginx config nobody has opened in "
             "years. The signature algorithm on a certificate. A private key "
             "baked into a container image that shipped months ago. "
             "Six kinds of artefact — and no two describe cryptography the "
             "same way."),

    dict(id="name", build=sc_name, beats=7500,
         say="Crypto Drishti reads all of it, and turns it into one inventory "
             "you can defend.",
         cap="CryptoDrishti reads all of it, and turns it into one inventory "
             "you can defend."),

    dict(id="structure", build=sc_structure, beats=14000,
         say="Seven sensors: source, dependencies, binaries, certificates, "
             "configuration, containers, and one live T L S endpoint the "
             "operator names. Every hit becomes one distinct cryptographic "
             "asset — and purpose and assurance are part of that asset's "
             "identity.",
         cap="Seven sensors: source, dependencies, binaries, certificates, "
             "configuration, containers, and one live TLS endpoint the "
             "operator names. Every hit becomes one distinct cryptographic "
             "asset — and purpose and assurance are part of that asset's "
             "identity."),

    dict(id="dashboard", build=sc_dashboard, beats=16000,
         say="Here is a real scan of the demonstration estate. Twenty three "
             "distinct assets. Sixteen of them do not survive a quantum "
             "computer. And the scan states its own completeness at the top, "
             "before a single finding.",
         cap="A real scan of the demonstration estate. 23 distinct assets. "
             "16 of them do not survive a quantum computer. And the scan "
             "states its own completeness at the top, before a single "
             "finding."),

    dict(id="rsa", build=sc_rsa, beats=46000,
         say="Now the part that decides everything. That one scan found five "
             "R S A findings. Watch what happens to them. The first is in a "
             "payments service, at line fifteen. The padding scheme is P S S, "
             "which means this key signs. So the target is M L D S A sixty "
             "five. The second is in the gateway, at line sixteen. The "
             "padding is O A E P, which means this key wraps another key. "
             "That is key establishment, and the target is a hybrid key "
             "exchange. A completely different migration. The third is a "
             "cipher list in a configuration file. It permits R S A, but it "
             "never says what for. So the tool names no target at all. It "
             "says: purpose must be resolved first. Knowing the algorithm is "
             "not enough. Purpose decides the migration.",
         cap="That one scan found five RSA findings. The first is a signing "
             "call — RSA-PSS padding — so the target is ML-DSA-65. The second "
             "is RSA-OAEP wrapping a key: that is key establishment, and the "
             "target is a hybrid key exchange. A completely different "
             "migration. The third is a cipher list that permits RSA without "
             "ever saying what for — so the tool names no target at all. "
             "Knowing the algorithm is not enough. Purpose decides the "
             "migration."),

    dict(id="chain", build=sc_chain, beats=24000,
         say="Every finding carries the chain that produced it. The call "
             "site. The symbol that matched. The technique — an abstract "
             "syntax tree analysis, not a keyword guess. The sensor's "
             "confidence. How strong the evidence is that this key is really "
             "used. What a quantum computer does to it. The resolved purpose. "
             "The exposure arithmetic. And only at the end, a target.",
         cap="Every finding carries the chain that produced it. The call "
             "site. The symbol matched. The technique — an AST analysis, not "
             "a keyword guess. The confidence. How strong the evidence is "
             "that the key is really used. What a quantum computer does to "
             "it. The resolved purpose. The exposure arithmetic. And only at "
             "the end, a target."),

    dict(id="drawer", build=sc_drawer, beats=14000,
         say="That whole chain is in the product, on one screen, for every "
             "finding — including which inputs a human set by hand, and which "
             "are still defaults.",
         cap="That whole chain is in the product, on one screen, for every "
             "finding — including which inputs a human set by hand, and which "
             "are still defaults."),

    dict(id="honest", build=sc_honest, beats=28000,
         say="It is just as careful about what it did not see. A container "
             "image is replayed layer by layer, so a private key written in "
             "one layer and deleted in the next is reported as historical: "
             "gone at runtime, still extractable from the archive. And when "
             "the destination policy refused an endpoint, the scan is marked "
             "partial, and says which one and why. A partial scan presented "
             "as a complete inventory is the most damaging thing this tool "
             "could produce, so it cannot happen quietly.",
         cap="It is just as careful about what it did not see. A container "
             "image is replayed layer by layer, so a key written in one layer "
             "and deleted in the next is reported as historical: gone at "
             "runtime, still extractable from the archive. And when the "
             "destination policy refused an endpoint, the scan is marked "
             "PARTIAL — and says which one, and why."),

    dict(id="cbom", build=sc_cbom, beats=26000,
         say="The output is not a bespoke report. It is a Cyclone D X "
             "cryptographic bill of materials — the published standard — "
             "carrying the asset type, the primitive, the resolved purpose "
             "and the evidence occurrence for every finding. And it is "
             "validated offline against the official JSON schema, vendored at "
             "a pinned commit. Continuous integration fails the build on a "
             "violation.",
         cap="The output is not a bespoke report. It is a CycloneDX "
             "cryptographic bill of materials — the published standard — "
             "carrying the asset type, the primitive, the resolved purpose "
             "and the evidence occurrence for every finding. Validated "
             "offline against the official JSON Schema, vendored at a pinned "
             "commit. CI fails the build on a violation."),

    dict(id="close", build=sc_close, beats=16000,
         say="Scattered evidence becomes one explainable inventory, a risk "
             "assessment you can argue with, and a migration decision you can "
             "defend. Crypto Drishti. Team Zero Day. Problem statement S I H "
             "twenty six one six four.",
         cap="Scattered evidence becomes one explainable inventory, a risk "
             "assessment you can argue with, and a migration decision you can "
             "defend.  CryptoDrishti · Team Zero-Day · SIH26164"),
]

# The short cut is re-edited, not trimmed: it keeps the argument and drops
# the supporting detail.
SHORT_IDS = ["name", "dashboard", "rsa", "honest", "cbom", "close"]

SHORT_SAY = {
    "name": dict(
        say="Cryptography hides in source, dependencies, configuration, "
            "certificates and container images. Crypto Drishti finds all of "
            "it.",
        cap="Cryptography hides in source, dependencies, configuration, "
            "certificates and container images. CryptoDrishti finds all of it "
            "— and turns it into one inventory you can defend."),
    "dashboard": dict(
        say="One scan of the demonstration estate: twenty three distinct "
            "assets, sixteen of them quantum vulnerable, and the scan's own "
            "completeness stated up front.",
        cap="One scan: 23 distinct assets, 16 quantum-vulnerable — and the "
            "scan's own completeness stated up front."),
    "rsa": dict(
        say="One scan, five R S A findings. A signing call goes to M L D S "
            "A sixty five. R S A wrapping a key goes to a hybrid key "
            "exchange — a completely different migration. And a cipher list "
            "that never says what R S A is for gets no target at all. "
            "Purpose decides the migration.",
        cap="Five RSA findings in one scan. A signing call goes to ML-DSA-65. "
            "RSA wrapping a key is key establishment — a hybrid key exchange, "
            "a completely different migration. And a cipher list that never "
            "says what RSA is for gets no target at all. Purpose decides the "
            "migration."),
    "honest": dict(
        say="A key deleted by a later container layer is still reported — "
            "it is still extractable. A refused endpoint makes the scan "
            "partial, and says why.",
        cap="A key deleted by a later container layer is still reported — it "
            "is still extractable. And a refused endpoint makes the scan "
            "PARTIAL, and it says why."),
    "cbom": dict(
        say="The output is a Cyclone D X bill of materials, validated offline "
            "against the official JSON schema.",
        cap="The output is a CycloneDX bill of materials, validated offline "
            "against the official JSON Schema."),
    "close": dict(
        say="Crypto Drishti. Team Zero Day. Problem statement S I H twenty "
            "six one six four.",
        cap="CryptoDrishti · Team Zero-Day · SIH26164"),
}
