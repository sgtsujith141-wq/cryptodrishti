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
from pptx.enum.text import MSO_ANCHOR                     # noqa: E402
from pptx.util import Emu, Inches, Pt                     # noqa: E402

import deck_content as C                                  # noqa: E402

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
# ==========================================================================

def build_solution(slide):
    set_title(slide, "CryptoDrishti  |  PROPOSED SOLUTION", size=28)

    lw, rx = 6.06, 7.00
    rw = RIGHT - rx

    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(4.26)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "The problem", first=True)
    body(tf, C.PROBLEM)
    heading(tf, "What CryptoDrishti is")
    body(tf, C.SOLUTION, after=0)

    rb = box(slide, rx, TOP, rw, 4.26, name="cd-right")
    rf = rb.text_frame
    heading(rf, "What it does", first=True)
    for label, text in C.CAPABILITIES:
        item(rf, label, text, size=T_LABEL, after=5)
    heading(rf, "What makes it different")
    body(rf, C.DIFFERENTIATOR, size=T_LABEL, after=0)

    # The implemented pipeline, as four editable panels rather than a picture.
    top = 6.10
    caption(slide, LEFT, top - 0.32, WIDE,
            "The implemented pipeline — every stage below exists in the tool.")
    gap, n = 0.16, len(C.PIPELINE)
    w = (WIDE - gap * (n - 1)) / n
    for i, (name, sub) in enumerate(C.PIPELINE):
        x = LEFT + i * (w + gap)
        panel(slide, x, top, w, 0.64, name="cd-stage")
        tbx = box(slide, x + 0.16, top + 0.09, w - 0.28, 0.50,
                  name="cd-stage-text")
        stf = tbx.text_frame
        p = para(stf, True, space_after=3)
        run(p, name, T_LABEL, bold=True, colour=NAVY)
        _bullet(p, "none")
        p = para(stf, False, space_after=0)
        run(p, sub, T_CAPTION, colour=MUTED)
        _bullet(p, "none")


# ==========================================================================
# Slide 3 -- technical approach
# ==========================================================================

def build_technical(slide):
    lw, rx = 6.06, 7.00
    rw = RIGHT - rx

    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(2.58)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "System architecture", first=True)
    for step in C.ARCHITECTURE:
        bullet(tf, step, size=T_LABEL, after=4)
    rb = box(slide, rx, TOP, rw, 2.58, name="cd-impl")
    rf = rb.text_frame
    heading(rf, "Technical implementation", first=True)
    for label, text in C.IMPLEMENTATION:
        item(rf, label, text, size=T_LABEL, after=4)

    # The differentiator, given the room it needs to be read without zooming.
    y = 4.26
    hb = box(slide, LEFT, y - 0.40, WIDE, 0.36, name="cd-rsa-head")
    p = para(hb.text_frame, True, space_after=0)
    run(p, "One algorithm, three decisions. ", T_HEAD, bold=True, colour=ACCENT)
    run(p, "The same RSA, resolved three ways by a single scan.",
        T_HEAD - 3, colour=INK2)
    _bullet(p, "none")

    rowh, gapy = 0.52, 0.06
    cols = [0.0, 3.42, 6.36, 9.16]
    widths = [3.28, 2.82, 2.66, 3.25]
    heads = ["Evidence", "Why the purpose resolves that way",
             "Recommendation", "Meaning"]
    hdr = box(slide, LEFT, y, WIDE, 0.28, name="cd-rsa-cols")
    hp = hdr.text_frame
    for i, h in enumerate(heads):
        tbx = box(slide, LEFT + cols[i], y, widths[i], 0.26,
                  name="cd-rsa-col")
        p = para(tbx.text_frame, True, space_after=0)
        run(p, h.upper(), T_CAPTION - 1, bold=True, colour=MUTED)
        _bullet(p, "none")
    hdr._element.getparent().remove(hdr._element)

    for i, (title, where, surface, why, target, meaning) in enumerate(
            C.RSA_CASES):
        top = y + 0.30 + i * (rowh + gapy)
        rule(slide, LEFT, top - 0.05, WIDE)
        tbx = box(slide, LEFT + cols[0], top + 0.04, widths[0], rowh - 0.12,
                  name="cd-rsa-ev")
        tf2 = tbx.text_frame
        p = para(tf2, True, space_after=2)
        run(p, title, T_ITEM, bold=True, colour=INK)
        _bullet(p, "none")
        p = para(tf2, False, space_after=0)
        run(p, f"{where}   ({surface})", T_CAPTION, colour=MUTED)
        _bullet(p, "none")

        for idx, text, size, colour, bold in (
                (1, why, T_LABEL, INK2, False),
                (2, target, T_ITEM, ACCENT if "resolved first" not in target
                 else MUTED, True),
                (3, meaning, T_LABEL, INK2, False)):
            tbx = box(slide, LEFT + cols[idx], top + 0.10, widths[idx], rowh - 0.18,
                      name="cd-rsa-cell")
            p = para(tbx.text_frame, True, space_after=0)
            run(p, text, size, bold=bold, italic=(idx == 2 and bold and
                                                  "resolved first" in target),
                colour=colour)
            _bullet(p, "none")

    sb = box(slide, LEFT, 6.30, WIDE, 0.52, name="cd-security")
    p = para(sb.text_frame, True, space_after=0)
    run(p, "Security design — ", T_CAPTION, bold=True, colour=INK)
    run(p, C.SECURITY, T_CAPTION, colour=MUTED)
    _bullet(p, "none")


# ==========================================================================
# Slide 4 -- feasibility and viability
# ==========================================================================

def build_feasibility(slide):
    lw, rx = 7.12, 7.96
    rw = RIGHT - rx

    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(5.40)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "Implemented prototype", first=True)
    for text in C.PROTOTYPE:
        bullet(tf, text, size=T_LABEL, after=4)
    heading(tf, "Validation")
    for label, text in C.VALIDATION:
        item(tf, label, text, size=T_LABEL, after=4)

    # One screenshot, cropped to the numbers it is there to prove.
    path = crop("01-assessment.png", (0.300, 0.115, 0.990, 0.725))
    y = picture(slide, path, rx, TOP + 0.04, rw)
    caption(slide, rx, y + 0.11, rw,
            "Live console, demo estate — the partial-scan warning names "
            "the refused endpoint, above the real counts.")

    fb = box(slide, rx, 4.62, rw, 2.20, name="cd-feas")
    ff = fb.text_frame
    p = para(ff, True, space_after=4)
    run(p, "Why deployment is feasible — ", T_LABEL, bold=True, colour=INK)
    run(p, C.FEASIBILITY, T_LABEL, colour=INK2)
    _bullet(p, "none")
    p = para(ff, False, space_after=0)
    run(p, "Current limits — ", T_CAPTION, bold=True, colour=INK)
    run(p, C.LIMITATIONS, T_CAPTION, colour=MUTED)
    _bullet(p, "none")


# ==========================================================================
# Slide 5 -- impact and benefits
# ==========================================================================

def build_impact(slide):
    lw, rx = 6.60, 7.52
    rw = RIGHT - rx

    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(5.10)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    heading(tf, "How a migration team actually uses the output", first=True)
    for stage, text in C.WORKFLOW:
        p = para(tf, False, space_after=7)
        run(p, f"{stage}  ", T_ITEM, bold=True, colour=NAVY)
        run(p, text, T_ITEM, colour=INK2)
        _bullet(p, "none")
    heading(tf, "Intended users")
    body(tf, C.USERS, size=T_LABEL, after=0)

    rb = box(slide, rx, TOP, rw, 0.40, name="cd-bench-head")
    heading(rb.text_frame, "Benchmark evidence", first=True)

    top = TOP + 0.46
    panel(slide, rx, top, rw, 1.26, name="cd-bench-a")
    tbx = box(slide, rx + 0.18, top + 0.13, rw - 0.34, 1.04, name="cd-bench-at")
    tf2 = tbx.text_frame
    p = para(tf2, True, space_after=5)
    run(p, "Like-for-like: the same corpus, before and after", T_LABEL,
        bold=True, colour=INK)
    _bullet(p, "none")
    for label, counts, f1 in C.BENCHMARK["like_for_like"]:
        p = para(tf2, False, space_after=3)
        run(p, f"{label}: ", T_LABEL, bold=True, colour=INK2)
        run(p, f"{counts}   ", T_LABEL, colour=INK2)
        run(p, f1, T_LABEL, bold=True, colour=ACCENT)
        _bullet(p, "none")

    top2 = top + 1.44
    panel(slide, rx, top2, rw, 0.92, name="cd-bench-b")
    tbx = box(slide, rx + 0.18, top2 + 0.13, rw - 0.34, 0.66,
              name="cd-bench-bt")
    tf3 = tbx.text_frame
    label, counts, f1 = C.BENCHMARK["expanded"]
    p = para(tf3, True, space_after=5)
    run(p, label, T_LABEL, bold=True, colour=INK)
    _bullet(p, "none")
    p = para(tf3, False, space_after=0)
    run(p, f"{counts}   ", T_LABEL, colour=INK2)
    run(p, f1, T_LABEL, bold=True, colour=ACCENT)
    _bullet(p, "none")

    cb = box(slide, rx, top2 + 1.08, rw, 1.60, name="cd-bench-caveat")
    p = para(cb.text_frame, True, space_after=0)
    run(p, C.BENCHMARK["caveat"], T_CAPTION, italic=True, colour=MUTED)
    _bullet(p, "none")


# ==========================================================================
# Slide 6 -- research and references
# ==========================================================================

def build_references(slide):
    shrink_title(slide, 28)
    lw, rx = 6.06, 7.00
    rw = RIGHT - rx

    tb = shape_by_name(slide, "TextBox 8")
    tb.left, tb.top = Inches(LEFT), Inches(TOP)
    tb.width, tb.height = Inches(lw), Inches(5.10)
    tb.name = "cd-body"
    tf = tb.text_frame
    tf.word_wrap = True
    tf.clear()
    for i, (group, entries) in enumerate([C.REFERENCES[0], C.REFERENCES[2]]):
        heading(tf, group, first=(i == 0), size=T_LABEL + 1)
        for e in entries:
            bullet(tf, e, size=T_CAPTION, after=4)

    rb = box(slide, rx, TOP, rw, 5.10, name="cd-refs-right")
    rf = rb.text_frame
    for i, (group, entries) in enumerate([C.REFERENCES[1], C.REFERENCES[3]]):
        heading(rf, group, first=(i == 0), size=T_LABEL + 1)
        for e in entries:
            bullet(rf, e, size=T_CAPTION, after=4)

    nb = box(slide, LEFT, 6.28, WIDE, 0.56, name="cd-ref-note")
    p = para(nb.text_frame, True, space_after=0)
    run(p, "Scope of these references — ", T_CAPTION, bold=True, colour=INK)
    run(p, C.REFERENCE_NOTE, T_CAPTION, colour=MUTED)
    _bullet(p, "none")


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
