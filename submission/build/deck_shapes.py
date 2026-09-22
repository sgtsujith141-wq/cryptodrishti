#!/usr/bin/env python3
"""Editable diagram primitives for the SIH deck.

Diagrams here are built from real PowerPoint shapes and text runs, not from
rendered images. That matters for three reasons: the labels stay selectable in
the exported PDF, the type sits at the same sizes as the body copy instead of
being scaled down by an image box, and whoever inherits this deck can edit a
box without regenerating a PNG.

The palette is the light one the official template uses. Product screenshots
are the only dark surface in the deck, which is what makes them read as
product rather than decoration.
"""

from __future__ import annotations

from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

# --- palette --------------------------------------------------------------
INK = RGBColor(0x1A, 0x1A, 0x1C)
INK2 = RGBColor(0x3E, 0x3E, 0x44)
MUTED = RGBColor(0x63, 0x63, 0x6B)
ACCENT = RGBColor(0x9E, 0x3A, 0x24)
NAVY = RGBColor(0x1B, 0x3A, 0x6B)
TEAL = RGBColor(0x14, 0x4C, 0x39)
RULE = RGBColor(0xD2, 0xD0, 0xCB)
FILL = RGBColor(0xF5, 0xF3, 0xEF)
FILL_2 = RGBColor(0xEC, 0xE9, 0xE3)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)


def _plain(shape):
    shape.shadow.inherit = False
    return shape


def _tf(shape):
    tf = shape.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.06)
    tf.margin_top = tf.margin_bottom = Inches(0.03)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    return tf


def _line(tf, first, text, size, *, bold=False, colour=INK, align=None,
          space_after=0, italic=False):
    from pptx.oxml.ns import qn
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.space_before = Pt(0)
    p.space_after = Pt(space_after)
    if align is not None:
        p.alignment = align
    pPr = p._p.get_or_add_pPr()
    pPr.set("marL", "0"); pPr.set("indent", "0")
    none = pPr.makeelement(qn("a:buNone"), {})
    pPr.insert_element_before(none, "a:tabLst", "a:defRPr", "a:extLst")
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = colour
    return p


def chip(slide, x, y, w, h, title, sub=None, *, fill=FILL, border=RULE,
         title_size=13, sub_size=11.5, title_colour=INK, sub_colour=MUTED,
         accent_edge=None, align=PP_ALIGN.CENTER, name="cd-chip"):
    """A labelled box. The workhorse of every diagram in the deck."""
    sh = _plain(slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                       Inches(x), Inches(y),
                                       Inches(w), Inches(h)))
    sh.name = name
    sh.adjustments[0] = 0.09
    sh.fill.solid(); sh.fill.fore_color.rgb = fill
    sh.line.color.rgb = border; sh.line.width = Pt(0.75)
    tf = _tf(sh)
    _line(tf, True, title, title_size, bold=True, colour=title_colour,
          align=align, space_after=2 if sub else 0)
    if sub:
        _line(tf, False, sub, sub_size, colour=sub_colour, align=align)
    if accent_edge:
        bar = _plain(slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Pt(3.2), Inches(h)))
        bar.name = "cd-chip-edge"
        bar.fill.solid(); bar.fill.fore_color.rgb = accent_edge
        bar.line.fill.background()
    return sh


def band(slide, x, y, w, h, title, sub=None, *, fill=NAVY, title_size=16,
         sub_size=11, name="cd-band"):
    """A solid emphasis bar — used for the one node everything converges on."""
    sh = _plain(slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                       Inches(x), Inches(y),
                                       Inches(w), Inches(h)))
    sh.name = name
    sh.adjustments[0] = 0.12
    sh.fill.solid(); sh.fill.fore_color.rgb = fill
    sh.line.fill.background()
    tf = _tf(sh)
    _line(tf, True, title, title_size, bold=True, colour=WHITE,
          align=PP_ALIGN.CENTER, space_after=1 if sub else 0)
    if sub:
        _line(tf, False, sub, sub_size, colour=RGBColor(0xD8, 0xDE, 0xEA),
              align=PP_ALIGN.CENTER)
    return sh


def arrow(slide, x, y, w, h, *, down=True, colour=RULE, name="cd-arrow"):
    sh = _plain(slide.shapes.add_shape(
        MSO_SHAPE.DOWN_ARROW if down else MSO_SHAPE.RIGHT_ARROW,
        Inches(x), Inches(y), Inches(w), Inches(h)))
    sh.name = name
    sh.fill.solid(); sh.fill.fore_color.rgb = colour
    sh.line.fill.background()
    return sh


def caret(slide, x, y, size=0.13, *, colour=MUTED, name="cd-caret"):
    """A small downward chevron — lighter than a full arrow between rows."""
    return arrow(slide, x, y, size, size * 1.15, down=True, colour=colour,
                 name=name)


def label(slide, x, y, w, text, size=11, *, bold=False, colour=MUTED,
          align=PP_ALIGN.LEFT, italic=False, name="cd-label", h=0.26):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tb.name = name
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    _line(tf, True, text, size, bold=bold, colour=colour, align=align,
          italic=italic)
    return tb


def rsa_row(slide, x, y, w, h, *, case, where, surface, purpose, target,
            tone, resolved, name="cd-rsa"):
    """One RSA finding as a card: the evidence on the left, the decision on
    the right, on the same line.

    Three of these stacked are the deck's central argument. Putting purpose
    and decision on one line is what makes the comparison readable in a
    glance -- the eye runs down the purpose column, then down the decision
    column, and the difference is the point.
    """
    card = _plain(slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                         Inches(x), Inches(y),
                                         Inches(w), Inches(h)))
    card.name = name
    card.adjustments[0] = 0.06
    card.fill.solid(); card.fill.fore_color.rgb = FILL
    card.line.color.rgb = RULE; card.line.width = Pt(0.75)
    edge = _plain(slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x),
                                         Inches(y), Pt(3.4), Inches(h)))
    edge.name = "cd-rsa-edge"
    edge.fill.solid(); edge.fill.fore_color.rgb = tone
    edge.line.fill.background()

    pad = 0.17
    inner_w = w - pad * 2
    label(slide, x + pad, y + 0.08, inner_w * 0.52, case, 13, bold=True,
          colour=INK, h=0.22, name="cd-rsa-case")
    label(slide, x + pad, y + 0.30, inner_w * 0.54,
          f"{where}   ·   {surface}", 10.5, colour=MUTED, h=0.20,
          name="cd-rsa-where")

    # purpose (left) and decision (right) share the bottom line
    py = y + h - 0.50
    label(slide, x + pad, py + 0.06, inner_w * 0.50, purpose, 15, bold=True,
          colour=tone, h=0.30, name="cd-rsa-purpose")

    bw = inner_w * 0.44
    bx = x + w - pad - bw
    inner = _plain(slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                          Inches(bx), Inches(py),
                                          Inches(bw), Inches(0.42)))
    inner.name = "cd-rsa-target"
    inner.adjustments[0] = 0.14
    inner.fill.solid()
    inner.fill.fore_color.rgb = WHITE if resolved else FILL_2
    inner.line.color.rgb = TEAL if resolved else RULE
    inner.line.width = Pt(1.0 if resolved else 0.75)
    tf = _tf(inner)
    _line(tf, True, target, 12.5 if resolved else 11, bold=resolved,
          italic=not resolved, colour=TEAL if resolved else MUTED,
          align=PP_ALIGN.CENTER)
    return card
