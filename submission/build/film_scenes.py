#!/usr/bin/env python3
"""Scene definitions for the CryptoDrishti demonstration film.

Every value that appears on screen -- a file path, an algorithm name, a score,
a migration target, a count -- is a value `python run.py --demo` actually
produced. Nothing here is written for effect. Where the tool declines to
answer, the film shows it declining.

The film is designed **caption-first**: it has to carry its argument with the
sound off. That design is now the whole of it -- the shipped cuts are
caption-led and have no narration track at all, so the on-screen typography and
the caption band are the only things carrying the argument. `presenter/video.md`
records why.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import design as D  # noqa: E402
from PIL import Image  # noqa: E402

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
# The picture area, and the camera over genuine console frames
# --------------------------------------------------------------------------
#
# The caption-led cut reserves a 150px band at the foot of the frame. Earlier
# cuts shrank every scene to fit above it, which is how a readable dashboard
# ended up as a small panel in a large dark field. Scenes built here opt out
# of that shrink and lay themselves out in the full-width picture area
# instead, so the product fills the frame.

WALK = ROOT / "submission" / "walkthrough"
PIC_W, PIC_H = 1920, 930
FULL = ("#cd-stage { transform:none !important; }\n"
        f".pic {{ position:absolute; left:0; top:0; width:{PIC_W}px;"
        f" height:{PIC_H}px; overflow:hidden; }}")


def _marks() -> dict:
    d = json.loads((WALK / "walkthrough.json").read_text())
    return {s["name"]: s["marks"] for s in d["states"]}


def walk(shots, tag="Live console · demo estate", light=False,
         tag_right=False):
    """A camera over genuine console frames.

    Every frame was recorded by `capture_walkthrough.py` driving the running
    console with real clicks. A shot names its frame, when it starts, the
    camera keys `(ms, centre-x, centre-y, visible-width)` in fractions of the
    frame, and the focus rings to draw. A ring names an element whose position
    the browser reported during the capture, so it sits on the real element.
    Consecutive shots dissolve into each other: that is the moment a click
    changed the screen, not a transition added for effect.
    """
    marks = _marks()
    frames, data = [], []
    for i, sh in enumerate(shots):
        path = WALK / f"{sh['frame']}.png"
        src = embed(path, None, 2880)
        with Image.open(path) as im:
            iw, ih = im.width, im.height
        frames.append(f'<div class="wf" id="wf{i}"><img src="{src}"></div>')
        rings = []
        for what, a, b in sh.get("rings", []):
            r = (marks[sh["frame"]][what] if isinstance(what, str)
                 else dict(zip("xywh", what)))
            rings.append({"r": [r["x"], r["y"], r["w"], r["h"]],
                          "a": a, "b": b})
        data.append({"at": sh["at"], "cam": sh["cam"], "rings": rings,
                     "iw": iw, "ih": ih})
    n = sum(len(d["rings"]) for d in data)
    end = max([k[0] for d in data for k in d["cam"]]
              + [r["b"] for d in data for r in d["rings"]])
    css = FULL + f"""
    .wf {{ position:absolute; inset:0; opacity:0; }}
    .wf img {{ position:absolute; display:block; max-width:none; }}
    .ring {{ position:absolute; opacity:0; border-radius:9px; z-index:4;
             border:2px solid {"rgba(26,26,28,.85)" if light
                               else "rgba(237,235,230,.88)"};
             box-shadow:0 0 0 4000px {"rgba(0,0,0,0)" if light
                                      else "rgba(8,8,10,.48)"}; }}
    .fade {{ position:absolute; left:0; right:0; bottom:0; height:70px;
             z-index:5; background:linear-gradient(to bottom,
             rgba(16,16,18,0), {D.PAPER}); }}
    .tag {{ position:absolute; {"right" if light or tag_right else "left"}:30px; top:26px;
            z-index:6; opacity:0;
            font-family:{D.MONO}; font-size:15px; letter-spacing:.13em;
            text-transform:uppercase; color:{D.INK3};
            background:rgba(16,16,18,.86); border:1px solid {D.RULE2};
            border-radius:3px; padding:8px 13px; }}
    """
    rings_html = "".join(f'<div class="ring" id="rg{k}"></div>'
                         for k in range(n))
    body = f"""<div class="pic">{''.join(frames)}{rings_html}
      <div class="fade"></div>
      <div class="tag" data-in="300" data-dur="600">{tag}</div></div>
    <script>
    (function() {{
      const WS = {json.dumps(data)};
      const CW = {PIC_W}, CH = {PIC_H}, X = 450;
      const ez = p => p <= 0 ? 0 : p >= 1 ? 1
               : p < .5 ? 4*p*p*p : 1 - Math.pow(-2*p + 2, 3) / 2;
      function cam(keys, t) {{
        if (t <= keys[0][0]) return keys[0].slice(1);
        for (let i = 1; i < keys.length; i++) {{
          const a = keys[i-1], b = keys[i];
          if (t <= b[0]) {{
            const p = ez((t - a[0]) / Math.max(1, b[0] - a[0]));
            return [1, 2, 3].map(j => a[j] + (b[j] - a[j]) * p);
          }}
        }}
        return keys[keys.length-1].slice(1);
      }}
      window.seekExtra = function(t) {{
        let k = 0;
        WS.forEach((w, i) => {{
          const next = WS[i+1];
          let o = i === 0 ? 1 : Math.min(1, Math.max(0, (t - w.at) / X));
          if (next && t > next.at + X) o = 0;
          const el = document.getElementById('wf' + i);
          el.style.opacity = o;
          const IW = w.iw, IH = w.ih;
          let [cx, cy, z] = cam(w.cam, t);
          const s = CW / (z * IW), vw = CW / s, vh = CH / s;
          cx = Math.min(Math.max(cx * IW, vw / 2), IW - vw / 2);
          cy = Math.min(Math.max(cy * IH, vh / 2), IH - vh / 2);
          const L = CW / 2 - cx * s, T = CH / 2 - cy * s;
          const img = el.querySelector('img');
          img.style.width = (IW * s) + 'px';
          img.style.left = L + 'px'; img.style.top = T + 'px';
          w.rings.forEach(r => {{
            const g = document.getElementById('rg' + (k++));
            const ro = o * Math.min(1, Math.max(0, (t - r.a) / 350),
                                       Math.max(0, (r.b - t) / 350));
            const pad = 10;
            g.style.left = (L + r.r[0] * IW * s - pad) + 'px';
            g.style.top = (T + r.r[1] * IH * s - pad) + 'px';
            g.style.width = (r.r[2] * IW * s + 2 * pad) + 'px';
            g.style.height = (r.r[3] * IH * s + 2 * pad) + 'px';
            g.style.opacity = ro;
          }});
        }});
      }};
    }})();
    </script>"""
    return body, css, end


# --------------------------------------------------------------------------
# Scene builders -- each returns (body, css, choreography_ms)
# --------------------------------------------------------------------------

def sc_hook(fast=False):
    # The fragments arrive at once, not one by one over half a minute: the
    # opening has to put real evidence on screen immediately, then say what
    # it means in two lines.
    step = 170 if fast else 380
    frags = []
    pos = [(5, 6), (52, 4), (8, 21), (55, 19), (4, 36), (48, 34),
           (10, 51), (54, 49)]
    for i, ((where, code), (x, y)) in enumerate(zip(FRAGMENTS, pos)):
        t = 80 + i * step
        frags.append(f"""
        <div class="frag" style="left:{x}%; top:{y}%" data-in="{t}"
             data-dur="520" data-y="10">
          <div class="fc mono">{code}</div>
          <div class="fw mono">{where}</div></div>""")
    kick_at = 80 + len(FRAGMENTS) * step + 250
    css = FULL + f"""
    .frag {{ position:absolute; opacity:0; max-width:40%; }}
    .fc {{ font-size:35px; color:{D.INK2}; }}
    .fw {{ font-size:21px; color:{D.INK4}; margin-top:8px; }}
    .kick {{ position:absolute; left:6%; bottom:9%; opacity:0;
             font-size:58px; font-weight:700; letter-spacing:-.022em;
             line-height:1.18; color:{D.INK}; }}
    .kick span {{ color:{D.ACCENT}; }}
    """
    body = f"""<div class="pic">{''.join(frags)}
      <div class="kick" data-in="{kick_at}" data-dur="800" data-y="16">
        Your cryptography is everywhere.<br>
        <span>Your inventory usually isn't.</span></div></div>"""
    return body, css, kick_at + 1800


def sc_hook_fast():
    return sc_hook(fast=True)


def sc_dashboard():
    return walk([dict(
        frame="w01-assessment", at=0,
        cam=[(0, .50, .50, 1.00), (1600, .50, .50, 1.00),
             (3400, .68, .28, .44), (6600, .68, .28, .44),
             (8400, .50, .68, .80), (12400, .50, .68, .80)],
        rings=[("partial", 3700, 6700), ("figs", 8700, 12200)])])


def sc_inventory():
    return walk([dict(
        frame="w02-inventory", at=0,
        cam=[(0, .50, .56, 1.00), (1500, .50, .56, 1.00),
             (4500, .378, .40, .66), (10500, .378, .40, .66)],
        rings=[("row0", 4700, 7400), ("row1", 7700, 10300)])])


def sc_rsa(short=False):
    rows = []
    gap = 2300 if short else 2700
    for i, c in enumerate(RSA):
        base = 700 + i * gap
        tone = D.UNKNOWN if c["open"] else D.BROKEN
        tcls = "t-open" if c["open"] else "t-set"
        rows.append(f"""
        <div class="row" style="--c:{tone}">
          <div class="algo mono" data-in="{base}" data-dur="420" data-y="8">rsa</div>
          <div class="ev" data-in="{base+160}" data-dur="480" data-y="10">
            <div class="w mono">{c['where']}</div>
            <div class="s"><span>{c['surface']}</span>
              <span class="asr mono">{c['asr']}</span></div></div>
          <div class="pu" data-in="{base+850}" data-dur="520" data-y="10">
            <div class="pl">{c['purpose']}</div>
            <div class="wy">{c['why']}</div></div>
          <div class="ar" data-in="{base+1400}" data-dur="380">{'?' if c['open'] else '→'}</div>
          <div class="tg {tcls} mono" data-in="{base+1550}" data-dur="560" data-y="10">{c['target']}</div>
        </div>""")
    kick = 700 + 3 * gap + 900
    css = FULL + f"""
    .hd {{ position:absolute; left:5%; top:6%; opacity:0; }}
    .hd h2 {{ font-size:56px; margin:0; font-weight:700; letter-spacing:-.024em; }}
    .hd p {{ font-size:26px; color:{D.INK3}; margin:12px 0 0; }}
    .tbl {{ position:absolute; left:5%; right:5%; top:25%; }}
    .row {{ display:grid; grid-template-columns:118px 1.05fr 1.1fr 56px 1.08fr;
            gap:0 28px; align-items:center; padding:38px 0 38px 26px;
            border-top:1px solid {D.RULE}; position:relative; }}
    .row::before {{ content:""; position:absolute; left:0; top:-1px; bottom:0;
                    width:5px; background:var(--c); }}
    .row > * {{ opacity:0; }}
    .algo {{ font-size:42px; font-weight:600; }}
    .w {{ font-size:26px; }}
    .s {{ margin-top:10px; display:flex; gap:12px; align-items:center;
          font-size:19px; color:{D.INK3}; }}
    .asr {{ font-size:14px; letter-spacing:.1em; color:{D.INK2};
            border:1px solid {D.RULE2}; border-radius:2px; padding:3px 9px; }}
    .pl {{ font-size:34px; font-weight:600; color:var(--c); }}
    .wy {{ font-size:20px; color:{D.INK3}; margin-top:8px; }}
    .ar {{ font-size:34px; color:{D.INK4}; text-align:center; }}
    .tg {{ font-size:30px; padding:16px 20px; border-radius:4px;
           background:{D.SURF}; border:1px solid {D.RULE}; }}
    .t-set {{ color:{D.SAFE}; border-color:rgba(63,174,134,.45); }}
    .t-open {{ color:{D.INK3}; font-style:italic; font-size:23px; }}
    .kick {{ position:absolute; left:5%; bottom:6%; opacity:0;
             font-size:44px; font-weight:700; letter-spacing:-.018em;
             color:{D.INK}; }}
    .kick b {{ color:{D.ACCENT}; font-weight:700; }}
    """
    body = f"""<div class="pic">
    <div class="hd" data-in="60" data-dur="640" data-y="12">
      <h2>Same algorithm. Three answers.</h2>
      <p>One scan of the demo estate · RSA, found three ways</p></div>
    <div class="tbl">{''.join(rows)}</div>
    <div class="kick" data-in="{kick}" data-dur="800" data-y="12">
      Finding the algorithm is not enough.
      <b>Purpose changes the migration.</b></div></div>"""
    return body, css, kick + 2600


def sc_rsa_short():
    return sc_rsa(short=True)


def _evidence_shots(scale=1.0):
    k = lambda ms: int(ms * scale)                            # noqa: E731
    return [
        # the inventory, pointer resting on the RSA signing finding
        dict(frame="w03-hover", at=0,
             cam=[(0, .45, .30, .80), (k(2800), .40, .22, .62)],
             rings=[("row0", k(700), k(2900))]),
        # the click: the evidence drawer opens over the same list
        dict(frame="w04-drawer", at=k(3000),
             cam=[(k(3000), .40, .22, .62), (k(4900), .80, .215, .44),
                  (k(7600), .80, .215, .44), (k(9100), .80, .56, .44),
                  (k(11700), .80, .56, .44), (k(13200), .80, .79, .44),
                  (k(15600), .80, .79, .44)],
             rings=[("head", k(5000), k(6100)),
                    ("sec0", k(6100), k(8700)),
                    ("sec1", k(9300), k(12200)),
                    ((.645, .745, .335, .105), k(13400), k(15500))]),
    ]


def sc_evidence():
    return walk(_evidence_shots(1.0))


def sc_evidence_short():
    return walk(_evidence_shots(0.80))


def sc_plan():
    return walk([dict(
        frame="w06-plan", at=0,
        cam=[(0, .50, .52, .98), (1300, .50, .52, .98),
             (3000, .395, .50, .70), (10200, .395, .50, .70)],
        rings=[("p0", 3300, 5400), ("p1", 5700, 7800), ("p3", 8100, 10200)])])


def sc_report():
    return walk([dict(
        frame="w09-report-close", at=0,
        cam=[(0, .50, .43, 1.00), (10400, .50, .41, .95)],
        rings=[("grid", 4900, 7400), ("verdict", 7700, 10200)])],
        tag="Generated report · opened from the console", light=True)


def sc_cbom():
    return walk([dict(
        frame="w07-validated", at=0,
        cam=[(0, .50, .52, .95), (1400, .50, .52, .95),
             (3200, .30, .56, .52), (9600, .30, .56, .52)],
        rings=[("buttons", 3300, 5200), ("result", 5600, 9500)])])


def sc_output_short():
    # plan -> report -> CBOM in one continuous pass, the order a person
    # would take through the console's output: what to do, the document,
    # the machine-readable record.
    return walk([
        dict(frame="w06-plan", at=0,
             cam=[(0, .40, .50, .70), (3600, .365, .50, .64)],
             rings=[("p0", 500, 1500), ("p1", 1600, 2600), ("p3", 2700, 3700)]),
        dict(frame="w09-report-close", at=3900,
             cam=[(3900, .50, .43, 1.00), (7700, .50, .42, .96)]),
        dict(frame="w07-validated", at=7800,
             cam=[(7800, .34, .56, .60), (10800, .30, .56, .52)],
             rings=[("result", 8600, 10800)]),
    ], tag="Live console · outputs", tag_right=True)


def sc_close():
    css = FULL + f"""
    .wrap {{ position:absolute; left:7%; top:50%; transform:translateY(-50%); }}
    .l {{ font-size:40px; color:{D.INK2}; opacity:0; line-height:1.45;
          font-weight:500; }}
    .l b {{ color:{D.INK}; font-weight:600; }}
    .nm {{ font-size:92px; font-weight:700; letter-spacing:-.026em;
           color:{D.INK}; opacity:0; margin-top:52px; }}
    .bar {{ width:0; height:5px; background:{D.ACCENT}; margin:20px 0 0; }}
    .meta {{ display:grid; grid-template-columns:auto auto; gap:12px 34px;
             margin-top:30px; opacity:0; font-size:30px; color:{D.INK3}; }}
    .meta .mono {{ color:{D.INK}; }}
    """
    body = f"""<div class="pic"><div class="wrap">
      <div class="l" data-in="200" data-dur="900" data-y="14">
        Scattered evidence.<br>One explainable inventory.<br>
        <b>A migration decision you can defend.</b></div>
      <div class="nm" data-in="1600" data-dur="800" data-y="14">CryptoDrishti</div>
      <div class="bar" data-in="2200" data-dur="700" data-grow="210"></div>
      <div class="meta" data-in="2600" data-dur="800" data-y="10">
        <span>Team</span><span class="mono">Zero-Day · 146876</span>
        <span>Problem statement</span><span class="mono">SIH26164</span>
        <span>Repository</span>
        <span class="mono">github.com/sgtsujith141-wq/cryptodrishti</span>
      </div></div></div>"""
    return body, css, 4200


def sc_honest():
    css = FULL + f"""
    .hd {{ position:absolute; left:5%; top:7%; opacity:0; }}
    .hd h2 {{ font-size:56px; margin:0; font-weight:700; letter-spacing:-.024em; }}
    .two {{ position:absolute; left:5%; right:5%; top:27%;
            display:grid; grid-template-columns:1fr 1fr; gap:40px; }}
    .b {{ opacity:0; background:{D.SURF}; border:1px solid {D.RULE};
          border-left:5px solid var(--c); border-radius:4px; padding:44px 46px; }}
    .bt {{ font-size:44px; font-weight:700; color:var(--c); }}
    .bd {{ font-size:31px; color:{D.INK2}; margin-top:22px; line-height:1.5; }}
    .bm {{ font-family:{D.MONO}; font-size:21px; color:{D.INK3}; margin-top:26px;
           padding-top:20px; border-top:1px solid {D.RULE}; }}
    """
    body = f"""<div class="pic">
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
    </div></div>"""
    return body, css, 5600


def sc_repo():
    css = FULL + f"""
    .hd {{ position:absolute; left:5%; top:8%; opacity:0; width:56%; }}
    .hd h2 {{ font-size:56px; margin:0; font-weight:700; letter-spacing:-.024em; }}
    .hd p {{ font-size:27px; color:{D.INK3}; margin:16px 0 0; line-height:1.5; }}
    .cmds {{ position:absolute; left:5%; top:38%; width:54%; }}
    .c {{ opacity:0; font-family:{D.MONO}; font-size:31px; color:{D.INK};
          padding:20px 26px; margin-bottom:16px; background:{D.SURF};
          border:1px solid {D.RULE}; border-left:4px solid {D.ACCENT};
          border-radius:4px; }}
    .c span {{ color:{D.INK4}; font-size:22px; }}
    .repo {{ position:absolute; right:5%; top:38%; width:34%; opacity:0;
             text-align:right; }}
    .repo .k {{ font-family:{D.MONO}; font-size:17px; letter-spacing:.13em;
                text-transform:uppercase; color:{D.INK4}; }}
    .repo .v {{ font-family:{D.MONO}; font-size:36px; color:{D.SAFE};
                margin-top:12px; word-break:break-all; line-height:1.35; }}
    .repo .n {{ font-size:23px; color:{D.INK3}; margin-top:22px;
                line-height:1.5; }}
    """
    cmds = [("python run.py --demo", "builds the estate and scans it"),
            ("python -m pytest", "664 tests"),
            ("python -m benchmark.run", "reproduces the accuracy figures")]
    rows = "".join(f"""
      <div class="c" data-in="{900 + i*520}" data-dur="480" data-y="10">
        {c}<br><span>{n}</span></div>""" for i, (c, n) in enumerate(cmds))
    body = f"""<div class="pic">
    <div class="hd" data-in="80" data-dur="640" data-y="12">
      <h2>Check it yourself</h2>
      <p>Every figure in this film comes from a command in the repository.</p></div>
    <div class="cmds">{rows}</div>
    <div class="repo" data-in="600" data-dur="760" data-y="12">
      <div class="k">Source</div>
      <div class="v">github.com/<br>sgtsujith141-wq/<br>cryptodrishti</div>
      <div class="n">664 tests · the labelled benchmark corpus and its
        committed results · the vendored CycloneDX schemas</div></div></div>"""
    return body, css, 3200


# `cap` is the caption: spelled for a reader, and the only text that reaches
# the band. `say` is kept equal to it so `make_film.py --voice` still has a
# script if the pinned voice ever becomes available again; the shipped cuts do
# not use it. An empty `cap` means the scene's own typography carries it.
#
# `beats` is a minimum hold. The renderer maps each scene's choreography onto
# its length, so a camera move stretches across the time the captions need
# instead of finishing early and leaving the frame dead.

def _s(id_, build, beats, cap):
    return dict(id=id_, build=build, beats=beats, cap=cap, say=cap)


SCENES = [
    _s("hook", sc_hook, 12000,
       "A signing call. A pinned dependency. A cipher list nobody has opened "
       "in years. A private key left inside a container image."),
    _s("dashboard", sc_dashboard, 17000,
       "One scan of the demonstration estate. Before anything else, it says "
       "the inventory is incomplete: one endpoint was refused. Then the "
       "numbers — 23 distinct assets, 16 of them quantum-vulnerable."),
    _s("inventory", sc_inventory, 13000,
       "Every asset gets a row, highest risk first. The top two are both "
       "RSA — and they need different replacements."),
    _s("rsa", sc_rsa, 38000,
       "Three of the scan's RSA findings, side by side. A signing call — "
       "RSA-PSS padding — so the target is ML-DSA-65. A key wrapped with "
       "RSA-OAEP is key establishment, so a hybrid key exchange. A cipher "
       "list that permits RSA without saying what for gets no target at all."),
    _s("evidence", sc_evidence, 22000,
       "Open the finding and the tool shows its working. Where the call is, "
       "and what it does. How strong the evidence is — a real call site, not "
       "a manifest. The exposure arithmetic under the operator's scenario. "
       "Only then, the target: ML-DSA-65."),
    _s("plan", sc_plan, 14000,
       "The three answers become three workstreams: ML-DSA-65, the hybrid "
       "group, and the findings whose purpose must be resolved first — one "
       "workstream per replacement, which is how the work is staffed."),
    _s("honest", sc_honest, 17000,
       "It is as careful about what it did not see. A key deleted by a later "
       "container layer is reported as historical — gone at runtime, still "
       "extractable. A refused endpoint makes the scan PARTIAL, and says why."),
    _s("report", sc_report, 14000,
       "Open report, and the same scan becomes a document a director can "
       "read: the headline counts, then the assessment behind them."),
    _s("cbom", sc_cbom, 13000,
       "Validate, and the CycloneDX bill of materials is checked against the "
       "official JSON Schema — offline, at a pinned commit. It passes."),
    _s("repo", sc_repo, 10000,
       "Run it yourself: the demo, the 664 tests and the benchmark are all "
       "in the repository."),
    _s("close", sc_close, 12000, ""),
]

# The short cut is its own edit, not the long one trimmed: each beat is
# re-timed, and the output scenes run as one continuous pass.
SHORT = [
    _s("hook", sc_hook_fast, 6400, ""),
    _s("dashboard", sc_dashboard, 14400,
       "One scan. One explainable cryptographic inventory."),
    _s("rsa", sc_rsa_short, 25400,
       "A signing call goes to ML-DSA-65. A wrapped key goes to a hybrid key "
       "exchange. A cipher list that never says what for gets no target."),
    _s("evidence", sc_evidence_short, 14400,
       "Open the finding: where it is, what it does, how sure the evidence "
       "is — and what it costs."),
    _s("output", sc_output_short, 12400,
       "A remediation programme. A report a director can read. A CBOM that "
       "passes the official schema."),
    _s("close", sc_close, 9400, ""),
]
