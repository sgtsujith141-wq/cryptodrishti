#!/usr/bin/env python3
"""Lay out the six-slide SIH deck from `deck_content.py`.

    python submission/build/build_deck.py

This builder is deliberately dumb about words: every sentence lives in
`deck_content.py`, which was written and fact-checked before any layout
existed. The earlier version of this deck was designed first and then had
explanations squeezed into whatever space survived, which is how it ended up
looking considered and saying very little.

Three rules the layout may not break:

* **The template stays light.** The official template has a light background
  and keeps it. Product screenshots are dark, cropped tight and used only
  where they carry information a sentence cannot.
* **Text is text.** Every explanation is a real PowerPoint text run, editable
  and selectable in the exported PDF. Nothing that a reader must read is
  baked into an image.
* **Nothing important below 13pt.** The type scale is fixed below; if a block
  does not fit, the content gets rewritten or the layout changes. Shrinking
  the type is not an available move.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from PIL import Image                                    # noqa: E402
from pptx import Presentation                            # noqa: E402
from pptx.dml.color import RGBColor                      # noqa: E402
from pptx.enum.shapes import MSO_SHAPE                    # noqa: E402
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN           # noqa: E402
from pptx.util import Emu, Inches, Pt                     # noqa: E402

import deck_content as C                                  # noqa: E402
import deck_shapes as S                                   # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "submission" / "template" / "SIH2026-IDEA-Presentation-Format.pptx"
SHOTS = ROOT / "submission" / "screenshots"
CROPS = Path(__file__).resolve().parent / ".crops"
OUT = ROOT / "submission" / "CryptoDrishti-SIH26164-Idea-Presentation.pptx"

FILL_IN = "[FILL FROM SIH PORTAL]"

# --- type scale, in points -------------------------------------------------
# Set against the brief's readability targets. Nothing a judge must read is
# allowed below CAPTION.
T_PRODUCT = 30      # the product name on the title slide
T_HEAD = 21         # section heading inside a slide
T_BODY = 18         # main explanation
T_ITEM = 16         # a labelled list row
T_LABEL = 15        # secondary label
T_CAPTION = 13      # caption, reference entry, figure label

# --- geometry --------------------------------------------------------------
LEFT = 0.46
RIGHT = 12.87
TOP = 1.20
BOTTOM = 6.84
WIDE = RIGHT - LEFT

# --- colour: the template's own blue leads, one accent supports ------------
INK = RGBColor(0x1A, 0x1A, 0x1C)
INK2 = RGBColor(0x3E, 0x3E, 0x44)
MUTED = RGBColor(0x63, 0x63, 0x6B)
ACCENT = RGBColor(0x9E, 0x3A, 0x24)     # the product's "Shor-broken" rust
NAVY = RGBColor(0x1B, 0x3A, 0x6B)       # picked up from the template title
RULE = RGBColor(0xD2, 0xD0, 0xCB)
PANEL = RGBColor(0xF4, 0xF2, 0xEE)


def portal(key: str) -> str:
    return C.PORTAL.get(key, "").strip() or FILL_IN


# ==========================================================================
# Primitives
# ==========================================================================

def shape_by_name(slide, name):
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    return None


def _bullet(para, kind: str) -> None:
    from pptx.oxml.ns import qn
    pPr = para._p.get_or_add_pPr()
    for tag in ("a:buNone", "a:buChar", "a:buAutoNum", "a:buFont"):
        for el in pPr.findall(qn(tag)):
            pPr.remove(el)
    if kind == "bullet":
        pPr.set("marL", "146050"); pPr.set("indent", "-146050")
        font = pPr.makeelement(qn("a:buFont"), {"typeface": "Arial"})
        char = pPr.makeelement(qn("a:buChar"), {"char": "–"})
        for el in (font, char):
            pPr.insert_element_before(el, "a:tabLst", "a:defRPr", "a:extLst")
    else:
        pPr.set("marL", "0"); pPr.set("indent", "0")
        none = pPr.makeelement(qn("a:buNone"), {})
        pPr.insert_element_before(none, "a:tabLst", "a:defRPr", "a:extLst")


def box(slide, left, top, width, height, name="cd-text"):
    tb = slide.shapes.add_textbox(Inches(left), Inches(top),
                                  Inches(width), Inches(height))
    tb.name = name
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    return tb


def para(tf, first: bool, space_before=0, space_after=4):
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.space_before = Pt(space_before)
    p.space_after = Pt(space_after)
    return p


def run(p, text, size, *, bold=False, italic=False, colour=INK):
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = colour
    return r


def heading(tf, text, first=False, *, size=T_HEAD, colour=ACCENT, gap=9):
    p = para(tf, first, space_before=0 if first else gap, space_after=5)
    run(p, text, size, bold=True, colour=colour)
    _bullet(p, "none")
    return p


def body(tf, text, first=False, *, size=T_BODY, colour=INK2, after=6,
         before=0):
    p = para(tf, first, space_before=before, space_after=after)
    run(p, text, size, colour=colour)
    _bullet(p, "none")
    return p


def item(tf, label, text, first=False, *, size=T_ITEM, after=6, bullet=True):
    """A labelled row: bold lead, then the explanation."""
    p = para(tf, first, space_after=after)
    run(p, f"{label} — ", size, bold=True, colour=INK)
    run(p, text, size, colour=INK2)
    _bullet(p, "bullet" if bullet else "none")
    return p


def bullet(tf, text, first=False, *, size=T_ITEM, after=6):
    p = para(tf, first, space_after=after)
    run(p, text, size, colour=INK2)
    _bullet(p, "bullet")
    return p


def rule(slide, left, top, width, colour=RULE):
    ln = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(left),
                                Inches(top), Inches(width), Pt(1))
    ln.name = "cd-rule"
    ln.fill.solid(); ln.fill.fore_color.rgb = colour
    ln.line.fill.background()
    ln.shadow.inherit = False
    return ln


def panel(slide, left, top, width, height, *, accent=True, name="cd-panel"):
    """A light content panel with an accent edge. Never a dark rectangle."""
    sh = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(left), Inches(top),
                                Inches(width), Inches(height))
    sh.name = name
    sh.fill.solid(); sh.fill.fore_color.rgb = PANEL
    sh.line.color.rgb = RULE
    sh.line.width = Pt(0.75)
    sh.shadow.inherit = False
    if accent:
        bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(left),
                                     Inches(top), Pt(3), Inches(height))
        bar.name = "cd-panel-edge"
        bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
        bar.line.fill.background()
        bar.shadow.inherit = False
    return sh


def crop(name: str, box_frac: tuple[float, float, float, float]) -> Path:
    """Crop a capture to the region that carries the point, by fraction."""
    CROPS.mkdir(parents=True, exist_ok=True)
    tag = "-".join(f"{v:.3f}" for v in box_frac)
    dst = CROPS / f"{Path(name).stem}-{tag}.png"
    src = SHOTS / name
    if dst.is_file() and dst.stat().st_mtime >= src.stat().st_mtime:
        return dst
    im = Image.open(src).convert("RGB")
    l, t, r, b = box_frac
    im.crop((int(im.width * l), int(im.height * t),
             int(im.width * r), int(im.height * b))).save(dst)
    return dst


def picture(slide, path: Path, left, top, width):
    pic = slide.shapes.add_picture(str(path), Inches(left), Inches(top),
                                   width=Inches(width))
    pic.name = f"cd-shot-{path.stem[:18]}"
    return top + Emu(pic.height).inches


def caption(slide, left, top, width, text):
    tb = box(slide, left, top, width, 0.30, name="cd-caption")
    p = para(tb.text_frame, True, space_after=0)
    run(p, text, T_CAPTION, italic=True, colour=MUTED)
    _bullet(p, "none")
    return tb


def set_title(slide, text, *, size=30):
    from pptx.oxml.ns import qn
    title = shape_by_name(slide, "Title 1")
    if title is None:
        return
    p = title.text_frame.paragraphs[0]
    for br in p._p.findall(qn("a:br")):
        p._p.remove(br)
    runs = p.runs
    runs[0].text = text
    runs[0].font.size = Pt(size)
    for r in runs[1:]:
        r.text = ""


def shrink_title(slide, size):
    title = shape_by_name(slide, "Title 1")
    for p in title.text_frame.paragraphs:
        for r in p.runs:
            r.font.size = Pt(size)


def set_oval(slide, text):
    for sh in slide.shapes:
        if sh.name.startswith("Oval") and sh.has_text_frame:
            tf = sh.text_frame
            for p in tf.paragraphs:
                for r in p.runs:
                    r.text = ""
            p = tf.paragraphs[0]
            r = p.runs[0] if p.runs else p.add_run()
            r.text = text
            r.font.size = Pt(11)
            r.font.bold = True


def delete_slide(prs, index):
    lst = prs.slides._sldIdLst
    sid = list(lst)[index]
    prs.part.drop_rel(sid.get(
        "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"))
    lst.remove(sid)


# ==========================================================================
# Slide 1 -- title
# ==========================================================================

def build_title(slide):
    tb = shape_by_name(slide, "TextBox 9")
    tb.left, tb.top = Inches(LEFT), Inches(1.98)
    tb.width, tb.height = Inches(6.45), Inches(4.30)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()

    p = para(tf, True, space_after=4)
    run(p, C.PRODUCT, T_PRODUCT, bold=True, colour=ACCENT)
    _bullet(p, "none")

    body(tf, C.STRAPLINE, size=T_BODY, colour=INK, after=13)

    fields = [("Problem Statement ID", portal("ps_id")),
              ("Problem Statement Title", portal("ps_title")),
              ("Theme", portal("theme")),
              ("PS Category", portal("category")),
              ("Team ID", portal("team_id")),
              ("Team Name", portal("team_name"))]
    for label, value in fields:
        p = para(tf, False, space_after=5)
        run(p, f"{label} – ", T_ITEM, bold=True, colour=INK)
        run(p, value, T_ITEM, colour=INK2)
        _bullet(p, "none")


# ==========================================================================
# Slide 2 -- proposed solution
#
# Left: what the problem is and what the tool does about it.
# Right: an editable diagram of where the evidence comes from and what it
# becomes. Neither half repeats the other -- the text explains assurance,
# the diagram explains topology.
# ==========================================================================

def build_solution(slide):
    set_title(slide, "CryptoDrishti  |  PROPOSED SOLUTION", size=28)

    lw = 5.46
    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(5.30)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "The problem", first=True, size=19)
    body(tf, C.PROBLEM, size=15, after=9)
    heading(tf, "What CryptoDrishti does", size=19, gap=7)
    body(tf, C.SOLUTION, size=15, after=9)
    heading(tf, "Why it is different", size=19, gap=7)
    body(tf, C.DIFFERENTIATOR, size=15, after=0)

    # ---- the discovery diagram -------------------------------------------
    dx, dw = 6.22, RIGHT - 6.22
    S.label(slide, dx, TOP - 0.02, dw, "WHERE THE EVIDENCE COMES FROM", 11,
            bold=True, colour=S.MUTED, name="cd-diag-eyebrow")

    surfaces = [("Source code", "Python AST + rule packs"),
                ("Dependencies", "13 manifest formats"),
                ("Binaries", "ELF symbols, constants"),
                ("Configuration", "nginx · sshd · OpenSSL"),
                ("Certificates", "X.509 · PEM/DER"),
                ("Containers", "OCI · docker save")]
    cw, ch, gx, gy = (dw - 0.22) / 2, 0.58, 0.22, 0.13
    top = TOP + 0.28
    for i, (n, sub) in enumerate(surfaces):
        S.chip(slide, dx + (i % 2) * (cw + gx), top + (i // 2) * (ch + gy),
               cw, ch, n, sub, title_size=13, sub_size=10.5,
               name="cd-surface")
    after = top + 3 * ch + 2 * gy

    S.caret(slide, dx + dw / 2 - 0.09, after + 0.06)
    S.band(slide, dx, after + 0.32, dw, 0.62, "CRYPTODRISHTI",
           "normalise → correlate → classify → score", title_size=16,
           sub_size=11)
    S.caret(slide, dx + dw / 2 - 0.09, after + 1.02)

    outs = [("INVENTORY", "distinct assets"), ("RISK", "Mosca exposure"),
            ("MIGRATION", "named target"), ("CBOM", "CycloneDX 1.6/1.7")]
    ow = (dw - 0.18 * 3) / 4
    oy = after + 1.28
    for i, (n, sub) in enumerate(outs):
        S.chip(slide, dx + i * (ow + 0.18), oy, ow, 0.62, n, sub,
               title_size=11.5, sub_size=11, title_colour=S.NAVY,
               accent_edge=S.ACCENT, name="cd-out")

    S.label(slide, dx, oy + 0.72, dw,
            "A seventh sensor completes a live TLS handshake — only against "
            "an endpoint the operator names, and only after the destination "
            "policy vets every resolved address.", 10.5, colour=S.MUTED,
            italic=True, h=0.46, name="cd-tls-note")


# ==========================================================================
# Slide 3 -- technical approach
#
# Left: how a finding is processed. Right: what that processing buys you,
# on the one example that makes the difference visible.
# ==========================================================================

def build_technical(slide):
    lw = 4.12
    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(0.34)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "How a finding is processed", first=True, size=17)

    steps = [("Scanner evidence", "file, line, symbol, technique, confidence"),
             ("Normalisation", "hits become one distinct asset"),
             ("Purpose + assurance", "what it is for; how strong the proof is"),
             ("Risk assessment", "Mosca X + Y > Z, per purpose"),
             ("Migration decision", "a named target — or none"),
             ("CBOM", "CycloneDX, schema-validated")]
    sy, sh_, gap = TOP + 0.42, 0.52, 0.15
    for i, (n, sub) in enumerate(steps):
        y = sy + i * (sh_ + gap)
        S.chip(slide, LEFT, y, lw, sh_, n, sub, title_size=12.5,
               sub_size=10.5, align=PP_ALIGN.LEFT,
               accent_edge=S.NAVY if i < 5 else S.ACCENT, name="cd-step")
        if i < len(steps) - 1:
            S.caret(slide, LEFT + lw / 2 - 0.055, y + sh_ + 0.012, 0.11)

    # ---- the comparison --------------------------------------------------
    rx = 4.92
    rw = RIGHT - rx
    S.label(slide, rx, TOP - 0.02, rw,
            "ONE ALGORITHM · THREE PURPOSE STATES · THREE DECISIONS", 11,
            bold=True, colour=S.MUTED, name="cd-rsa-eyebrow")
    S.label(slide, rx, TOP + 0.24, rw,
            "Every scanner can tell you RSA is present. What decides the "
            "migration is what it is being used for.", 13, colour=INK2,
            h=0.40, name="cd-rsa-lede")

    tones = [S.ACCENT, S.ACCENT, S.MUTED]
    cy, chh, cgap = TOP + 0.78, 1.06, 0.15
    for i, (case, where, surface, why, target, meaning) in enumerate(
            C.RSA_CASES):
        S.rsa_row(slide, rx, cy + i * (chh + cgap), rw, chh,
                  case=case, where=where, surface=surface,
                  purpose=why, target=target, tone=tones[i],
                  resolved=(i < 2))

    # ---- the stack, compact ---------------------------------------------
    sy2 = 6.06
    S.label(slide, LEFT, sy2 - 0.26, WIDE, "BUILT WITH", 10.5, bold=True,
            colour=S.MUTED, name="cd-stack-eyebrow")
    stack = ["Python 3.11+ · FastAPI", "SQLite (WAL)",
             "Vanilla JS console", "60 rules · 8 languages",
             "ELF symbol parsing", "CycloneDX 1.6 / 1.7"]
    sw = (WIDE - 0.14 * 5) / 6
    for i, item_text in enumerate(stack):
        S.chip(slide, LEFT + i * (sw + 0.14), sy2, sw, 0.40, item_text,
               title_size=11, title_colour=INK2, fill=S.FILL_2,
               name="cd-stack")


# ==========================================================================
# Slide 4 -- feasibility and viability
#
# Half evidence in words, half evidence on screen. Two different product
# views, each cropped to the thing it proves.
# ==========================================================================

def build_feasibility(slide):
    lw = 5.92
    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(4.96)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "Implemented", first=True, size=18)
    for text in C.PROTOTYPE[:3]:
        bullet(tf, text, size=14, after=4)
    heading(tf, "Validated", size=18, gap=8)
    for label_, text in C.VALIDATION[:3]:
        item(tf, label_, text, size=14, after=4)
    heading(tf, "Feasible to deploy", size=18, gap=8)
    body(tf, C.FEASIBILITY, size=14, after=0)

    S.label(slide, LEFT, 6.26, lw,
            "Limits — " + C.LIMITATIONS, 10.5, colour=S.MUTED, italic=True,
            h=0.56, name="cd-limits")

    # ---- two real product views -----------------------------------------
    rx = 6.70
    rw = RIGHT - rx
    a = crop("01-assessment.png", (0.316, 0.112, 0.990, 0.468))
    y = picture(slide, a, rx, TOP, rw)
    caption(slide, rx, y + 0.08, rw,
            "Assessment — the scan states its own completeness first: one "
            "endpoint refused, so the inventory is marked PARTIAL.")

    b = crop("07-evidence-drawer.png", (0.02, 0.118, 0.99, 0.302))
    y2 = picture(slide, b, rx, y + 0.66, rw)
    caption(slide, rx, y2 + 0.08, rw,
            "Evidence drawer — purpose, assurance and the exposure "
            "arithmetic behind one finding's score.")


# ==========================================================================
# Slide 5 -- impact and benefits
#
# Top: the workflow the output actually drives. Bottom: who it helps, and
# the measured evidence, kept in proportion.
# ==========================================================================

def build_impact(slide):
    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(WIDE), Inches(0.32)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "What a migration team does with the output", first=True,
            size=19)

    stages = [("DISCOVER", "Inventory the cryptographic assets that are "
                           "actually present."),
              ("UNDERSTAND", "Algorithm, purpose, evidence strength and "
                             "exact location."),
              ("PRIORITISE", "Quantum exposure with documented, "
                             "operator-set assumptions."),
              ("PLAN", "A purpose-matched target — or a request for more "
                       "evidence."),
              ("EXPORT", "A schema-validated CBOM and a traceable report.")]
    n = len(stages)
    gapx = 0.30
    cw = (WIDE - gapx * (n - 1)) / n
    sy = TOP + 0.46
    for i, (name_, text) in enumerate(stages):
        x = LEFT + i * (cw + gapx)
        S.chip(slide, x, sy, cw, 1.44, name_, text, title_size=13.5,
               sub_size=11, title_colour=S.NAVY, accent_edge=S.ACCENT,
               name="cd-stage")
        if i < n - 1:
            S.arrow(slide, x + cw + 0.05, sy + 0.60, gapx - 0.10, 0.24,
                    down=False, colour=S.RULE)

    # ---- who benefits, and what the measurement actually says ------------
    by = sy + 1.72
    lw2 = 6.30
    S.label(slide, LEFT, by, lw2, "Who this is for", 17, bold=True,
            colour=ACCENT, name="cd-users-head", h=0.30)
    S.label(slide, LEFT, by + 0.32, lw2, C.USERS, 13.5, colour=INK2,
            h=0.70, name="cd-users")

    S.label(slide, LEFT, by + 1.06, lw2, "What changes for them", 17,
            bold=True, colour=ACCENT, name="cd-changes-head", h=0.30)
    cb = box(slide, LEFT, by + 1.40, lw2, 1.50, name="cd-changes")
    cf = cb.text_frame
    for i, text in enumerate(C.CHANGES):
        bullet(cf, text, first=(i == 0), size=13.5, after=6)

    rx = 7.10
    rw = RIGHT - rx
    S.label(slide, rx, by, rw, "Measured on a labelled corpus", 17, bold=True,
            colour=ACCENT, name="cd-bench-head", h=0.30)

    S.chip(slide, rx, by + 0.36, rw, 0.86, "", None, fill=S.FILL,
           name="cd-bench-box")
    S.label(slide, rx + 0.18, by + 0.44, rw - 0.36,
            "Like-for-like, same corpus, before → after", 11.5, bold=True,
            colour=INK, name="cd-bench-label")
    S.label(slide, rx + 0.18, by + 0.70, rw - 0.36,
            "F1  0.941  →  0.983", 19, bold=True, colour=S.TEAL,
            name="cd-bench-f1", h=0.34)
    S.label(slide, rx + 2.90, by + 0.74, rw - 3.10,
            "79/5/5  →  84 TP · 3 FP · 0 FN", 11, colour=S.MUTED,
            name="cd-bench-counts")
    S.label(slide, rx, by + 1.32, rw,
            "An expanded synthetic corpus of 116 findings across six "
            "scanners scores 1.000 — a separate, non-comparable experiment. "
            "Both corpora were written by this project's developers and "
            "measure those corpora only; real-world enterprise accuracy has "
            "not been measured.", 10.5, colour=S.MUTED, italic=True, h=0.72,
            name="cd-bench-caveat")

    # Caption above, so the figure can sit hard against the footer margin.
    S.label(slide, rx, by + 2.06, rw,
            "Remediation programme — grouped by the replacement each asset "
            "needs, which is how the work is staffed.", 10.5, colour=S.MUTED,
            italic=True, h=0.26, name="cd-plan-caption")
    shot = crop("03-migration-plan.png", (0.055, 0.300, 1.0, 0.560))
    picture(slide, shot, rx, by + 2.36, rw)


# ==========================================================================
# Slide 6 -- research and references
#
# Mostly text, deliberately: this section's job is to be checkable. The one
# visual earns its place by answering a question the list cannot -- which
# standard governs which part of the product.
# ==========================================================================

def build_references(slide):
    shrink_title(slide, 28)
    lw, rx = 6.06, 7.00
    rw = RIGHT - rx

    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(4.10)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    for i, (group, entries) in enumerate([C.REFERENCES[0], C.REFERENCES[3]]):
        heading(tf, group, first=(i == 0), size=T_LABEL + 1)
        for e in entries:
            bullet(tf, e, size=T_CAPTION, after=4)

    rb = box(slide, rx, TOP, rw, 4.10, name="cd-refs-right")
    rf = rb.text_frame
    for i, (group, entries) in enumerate([C.REFERENCES[1], C.REFERENCES[2]]):
        heading(rf, group, first=(i == 0), size=T_LABEL + 1)
        for e in entries:
            bullet(rf, e, size=T_CAPTION, after=4)

    # Which standard governs which part of the product.
    my = 5.76
    S.label(slide, LEFT, my - 0.26, WIDE,
            "WHICH STANDARD GOVERNS WHICH PART OF THE PRODUCT", 10.5,
            bold=True, colour=S.MUTED, name="cd-map-eyebrow")
    mapping = [("FIPS 203 / 204 / 205", "the migration targets it names"),
               ("NIST IR 8547", "how it classifies what is at risk"),
               ("CycloneDX 1.6 / 1.7", "the CBOM it exports and validates"),
               ("OCI image spec", "how it reads container layers"),
               ("Mosca X + Y > Z", "how it scores exposure")]
    mw = (WIDE - 0.14 * 4) / 5
    for i, (std, does) in enumerate(mapping):
        S.chip(slide, LEFT + i * (mw + 0.14), my, mw, 0.62, std, does,
               title_size=11, sub_size=10.5, title_colour=S.NAVY,
               accent_edge=S.ACCENT, name="cd-map")

    S.label(slide, LEFT, my + 0.72, WIDE,
            "Scope — " + C.REFERENCE_NOTE, 10.5, colour=S.MUTED, italic=True,
            h=0.44, name="cd-ref-note")


# ==========================================================================

def main() -> int:
    if not TEMPLATE.is_file():
        print(f"template not found: {TEMPLATE}", file=sys.stderr)
        return 1
    shot = SHOTS / "01-assessment.png"
    if not shot.is_file():
        print(f"missing capture: {shot}", file=sys.stderr)
        return 1

    prs = Presentation(str(TEMPLATE))
    delete_slide(prs, 6)          # the template's own instructions page
    if len(prs.slides) != 6:
        print(f"expected 6 slides, got {len(prs.slides)}", file=sys.stderr)
        return 1

    s1, s2, s3, s4, s5, s6 = list(prs.slides)
    build_title(s1)
    build_solution(s2)
    build_technical(s3)
    build_feasibility(s4)
    build_impact(s5)
    build_references(s6)
    for s in (s2, s3, s4, s5, s6):
        set_oval(s, portal("team_name"))

    prs.save(str(OUT))
    print(f"written: {OUT.relative_to(ROOT)}  ({len(prs.slides)} slides)")

    labels = {"ps_id": "Problem Statement ID",
              "ps_title": "Problem Statement Title",
              "theme": "Theme", "category": "PS Category",
              "team_id": "Team ID", "team_name": "Team Name"}
    missing = [v for k, v in labels.items() if portal(k) == FILL_IN]
    if missing:
        print("\nSTILL TO FILL FROM THE SIH PORTAL:")
        for m in missing:
            print(f"  - {m}")
    else:
        print("\nRegistration details written to the title slide:")
        for k, v in labels.items():
            print(f"  {v:26s} {C.PORTAL[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
