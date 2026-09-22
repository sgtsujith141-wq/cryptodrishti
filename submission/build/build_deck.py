#!/usr/bin/env python3
"""Fill the official SIH template with CryptoDrishti's actual content.

    python submission/build/build_deck.py

Rules this script follows, because the template and the brief both require them:

* **Exactly six slides.** The template ships seven; the seventh is the
  instructions slide, which says in its own text to keep the deck to six. It
  is removed.
* **The template is not restyled.** Its backgrounds, branding, section titles,
  footer and slide numbering are left exactly as supplied. Only the content
  areas are written to.
* **Nothing is invented.** Registration details come from `PORTAL` below; a
  field left empty there becomes a visible marker rather than a guess, and
  `check_deck.py` refuses to call the deck submittable while any remain.
* **One image per slide, large enough to read.** Every image is a capture of
  the running application in its dark theme, or the architecture diagram
  rendered from `docs/architecture/architecture.mmd`. Each is cropped to the
  region that carries the argument -- nothing is mocked, composed or retouched.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageChops
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "submission" / "template" / "SIH2026-IDEA-Presentation-Format.pptx"
SHOTS = ROOT / "submission" / "screenshots"
DIAGRAM = ROOT / "docs" / "architecture" / "architecture-dark.png"
TRIMMED = Path(__file__).resolve().parent / ".trimmed"
OUT = ROOT / "submission" / "CryptoDrishti-SIH26164-Idea-Presentation.pptx"

# Registration details, exactly as the SIH portal issues them. A field left
# empty here is written into the deck as a visible marker instead, so
# `check_deck.py` still refuses to call the deck submittable -- filling these
# in is the only thing that clears that check, and nothing else bypasses it.
FILL_IN = "[FILL FROM SIH PORTAL]"

PORTAL = {
    "ps_id": "SIH26164",
    "ps_title": "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
    "theme": "26164",
    "category": "Software",
    "team_id": "146876",
    "team_name": "Zero-Day",
}


def portal(key: str) -> str:
    """One registration field, or the fill-in marker when it is not known."""
    return PORTAL.get(key, "").strip() or FILL_IN


# How each capture is cropped. `left` drops the console's scroll rail, which is
# navigation chrome rather than content; `top`/`bottom` are fractions of what
# is left, choosing the region that carries the point the slide is making.
CROPS = {
    # Enough rows to show three RSA findings resolving three different ways.
    "04-inventory.png": {"left": 190, "bottom": 0.58},
    # Cut above RECOMMENDED MIGRATION, which is a section break rather than a
    # line of text -- the earlier cut ran through the middle of one.
    "07-evidence-drawer.png": {"left": 0, "bottom": 0.53},
    "01-assessment.png": {"left": 190},
    "06-scan-history.png": {"left": 190},
    # The export card ends around halfway; the rest is empty panel.
    "05-cbom-export.png": {"left": 190, "bottom": 0.50},
    # The remediation table ends well above the panel it sits in.
    "03-migration-plan.png": {"left": 190, "bottom": 0.72},
}

# The template's own furniture. Content must stay inside these bounds: the
# title and the team oval occupy the top, the blue footer bar the bottom.
TOP = 1.22
BOTTOM = 6.82
LEFT = 0.45
RIGHT_EDGE = 12.88

INK = RGBColor(0x1A, 0x1A, 0x1A)
MUTED = RGBColor(0x5A, 0x5A, 0x5A)
ACCENT = RGBColor(0x8C, 0x1D, 0x1D)
DEEP = RGBColor(0x0F, 0x17, 0x2A)


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------

def prepare(name: str) -> Path:
    """Return the capture cropped to the region the slide actually uses.

    The captures are dark-theme screenshots of whole scenes. Two things are
    removed: the uniform background around the content, and -- where a slide
    only makes a point about the top of a long panel -- everything below that
    point. No content is scaled, recoloured, retouched or recomposed.
    """
    src = SHOTS / name
    spec = CROPS.get(name, {})
    TRIMMED.mkdir(parents=True, exist_ok=True)
    tag = f"{spec.get('left', 0)}-{spec.get('top', 0)}-{spec.get('bottom', 1)}"
    dst = TRIMMED / f"{src.stem}-{tag}{src.suffix}"
    if dst.is_file() and dst.stat().st_mtime >= src.stat().st_mtime:
        return dst

    im = Image.open(src).convert("RGB")
    left = spec.get("left", 0)
    work = im.crop((left, 0, im.width, im.height))
    background = work.getpixel((4, work.height // 2))
    diff = ImageChops.difference(work, Image.new("RGB", work.size, background))
    box = diff.convert("L").point(lambda v: 255 if v > 10 else 0).getbbox()
    out = work.crop(box) if box else work

    top = int(out.height * spec.get("top", 0.0))
    bottom = int(out.height * spec.get("bottom", 1.0))
    if (top, bottom) != (0, out.height):
        out = out.crop((0, top, out.width, bottom))
    out.save(dst)
    return dst


def shot(slide, name, left, top, *, width=None, height=None, caption=None):
    """Place a prepared capture, sized by width or by height, and caption it."""
    path = prepare(name)
    w, h = Image.open(path).size
    if height is not None:
        width = height * w / h
    pic = slide.shapes.add_picture(str(path), Inches(left), Inches(top),
                                   width=Inches(width))
    pic.name = f"cd-shot-{Path(name).stem}"
    below = top + Emu(pic.height).inches
    if caption:
        add_caption(slide, left, below + 0.07, width, caption)
        below += 0.07 + 0.32
    return below


def figure(slide, path, left, top, width, max_height, *, caption=None):
    """Place an image scaled down if it would otherwise exceed `max_height`."""
    w, h = Image.open(path).size
    height = width * h / w
    if height > max_height:
        height, width = max_height, max_height * w / h
    left = left + 0  # explicit: callers position from the left edge
    pic = slide.shapes.add_picture(str(path), Inches(left), Inches(top),
                                   width=Inches(width), height=Inches(height))
    pic.name = f"cd-figure-{Path(path).stem}"
    below = top + height
    if caption:
        add_caption(slide, left, below + 0.07, width, caption)
        below += 0.07 + 0.32
    return below


# --------------------------------------------------------------------------
# Text
# --------------------------------------------------------------------------

def shape_by_name(slide, name):
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    return None


def _bullet(para, kind: str) -> None:
    """Set this paragraph's bullet explicitly.

    The template's layouts carry a bullet, so a heading written into a content
    placeholder inherits one. Every paragraph therefore states its own
    intention rather than relying on what it happens to inherit.
    """
    from pptx.oxml.ns import qn

    pPr = para._p.get_or_add_pPr()
    for tag in ("a:buNone", "a:buChar", "a:buAutoNum", "a:buFont"):
        for el in pPr.findall(qn(tag)):
            pPr.remove(el)
    if kind == "bullet":
        pPr.set("marL", "160020")
        pPr.set("indent", "-160020")
        font = pPr.makeelement(qn("a:buFont"), {"typeface": "Arial"})
        char = pPr.makeelement(qn("a:buChar"), {"char": "–"})
        for el in (font, char):
            pPr.insert_element_before(el, "a:tabLst", "a:defRPr", "a:extLst")
    else:
        pPr.set("marL", "0")
        pPr.set("indent", "0")
        none = pPr.makeelement(qn("a:buNone"), {})
        pPr.insert_element_before(none, "a:tabLst", "a:defRPr", "a:extLst")


def style_run(run, style: str, size: float) -> None:
    font = run.font
    if style == "head":
        font.size, font.bold, font.color.rgb = Pt(size + 0.5), True, ACCENT
    elif style == "lead":
        font.size, font.bold, font.color.rgb = Pt(size), True, DEEP
    elif style == "note":
        font.size, font.italic, font.color.rgb = Pt(size - 1), True, MUTED
    else:
        font.size, font.color.rgb = Pt(size), INK


def write(frame, blocks, *, size=12, gap=4) -> None:
    """Replace a text frame's contents with (text, style) blocks.

    `style` is one of: head, body, bullet, lead, note. A block may also carry a
    (lead, rest) tuple to bold an inline label. Runs are assigned rather than
    paragraph text, so the template's typeface and colour inheritance survives
    wherever we do not deliberately override it.
    """
    frame.clear()
    frame.word_wrap = True
    for index, (text, style) in enumerate(blocks):
        para = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        para.space_before = Pt(gap + 4 if (style == "head" and index) else 0)
        para.space_after = Pt(gap)
        if isinstance(text, tuple):
            head, rest = text
            style_run(para.add_run(), "lead", size)
            para.runs[-1].text = head
            style_run(para.add_run(), style, size)
            para.runs[-1].text = rest
        else:
            run = para.add_run()
            run.text = text
            style_run(run, style, size)
        _bullet(para, style)


def place(shape, left, top, width, height) -> None:
    shape.left, shape.top = Inches(left), Inches(top)
    shape.width, shape.height = Inches(width), Inches(height)


def body(slide, left, top, width, height, blocks, *, size=12, gap=4):
    """Write into the template's own content placeholder, repositioned."""
    box = shape_by_name(slide, "TextBox 8")
    place(box, left, top, width, height)
    write(box.text_frame, blocks, size=size, gap=gap)
    box.name = "cd-body"
    return box


def note(slide, left, top, width, height, blocks, *, size=10.5, gap=2):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width),
                                   Inches(height))
    box.name = "cd-note"
    box.text_frame.word_wrap = True
    write(box.text_frame, blocks, size=size, gap=gap)
    return box


def add_caption(slide, left, top, width, text, *, size=9.5):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width),
                                   Inches(0.3))
    box.text_frame.word_wrap = True
    para = box.text_frame.paragraphs[0]
    run = para.add_run()
    run.text = text
    run.font.size, run.font.color.rgb = Pt(size), MUTED
    _bullet(para, "body")
    box.name = "cd-caption"
    return box


def set_title(slide, text: str, *, size: int = 32) -> None:
    """Rewrite a slide's title on one line.

    The template's slide-2 title is a single paragraph holding an empty run, a
    line break and the label. Assigning run text (rather than the frame's
    `.text`) keeps the template's typeface, weight and colour; the break is
    dropped so a longer title cannot push down into the content area.
    """
    from pptx.oxml.ns import qn

    title = shape_by_name(slide, "Title 1")
    if title is None:
        return
    para = title.text_frame.paragraphs[0]
    for br in para._p.findall(qn("a:br")):
        para._p.remove(br)
    runs = para.runs
    runs[0].text = text
    runs[0].font.size = Pt(size)
    for run in runs[1:]:
        run.text = ""


def shrink_title(slide, size: int) -> None:
    """Reduce a title's point size without touching its text.

    `RESEARCH AND REFERENCES` at the template's 36pt runs under the Smart India
    Hackathon logo in the top-right corner.
    """
    title = shape_by_name(slide, "Title 1")
    for para in title.text_frame.paragraphs:
        for run in para.runs:
            run.font.size = Pt(size)


def set_team_oval(slide, text: str) -> None:
    for shape in slide.shapes:
        if shape.name.startswith("Oval") and shape.has_text_frame:
            frame = shape.text_frame
            for para in frame.paragraphs:
                for run in para.runs:
                    run.text = ""
            para = frame.paragraphs[0]
            run = para.runs[0] if para.runs else para.add_run()
            run.text = text
            run.font.size = Pt(10)
            run.font.bold = True


def delete_slide(prs, index: int) -> None:
    """Remove a slide and its entry in the slide id list."""
    slides = prs.slides._sldIdLst
    slide_id = list(slides)[index]
    rid = slide_id.get(
        "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
    prs.part.drop_rel(rid)
    slides.remove(slide_id)


# ==========================================================================
# Slide 1 -- who we are, and what this is
# ==========================================================================

def build_title(slide) -> None:
    box = shape_by_name(slide, "TextBox 9")
    place(box, LEFT, 2.16, 6.25, 3.55)
    write(box.text_frame, [
        ("Problem Statement ID – " + portal("ps_id"), "lead"),
        ("Problem Statement Title – " + portal("ps_title"), "body"),
        ("Theme – " + portal("theme"), "body"),
        ("PS Category – " + portal("category"), "body"),
        ("Team ID – " + portal("team_id"), "body"),
        ("Team Name – " + portal("team_name"), "body"),
    ], size=15, gap=9)

    tag = note(slide, LEFT, 5.88, 6.25, 1.0, [
        ("CryptoDrishti", "lead"),
        ("Find every cryptographic asset an organisation owns, prove what the "
         "evidence actually supports, and say what each one must become.",
         "body"),
        ("Working tool · 664 tests · CycloneDX CBOM validated against the "
         "official schema · runs offline.", "note"),
    ], size=12, gap=2)
    for para in tag.text_frame.paragraphs[:1]:
        for run in para.runs:
            run.font.size, run.font.color.rgb = Pt(15), ACCENT


# ==========================================================================
# Slide 2 -- the problem, and why our solution is different
# ==========================================================================

def build_solution(slide) -> None:
    set_title(slide, "CryptoDrishti  |  PROPOSED SOLUTION", size=29)

    body(slide, LEFT, TOP, 5.95, 4.30, [
        ("The problem", "head"),
        ("Post-quantum migration is an inventory problem before it is a "
         "mathematics problem. NIST published the replacement algorithms in "
         "2024; almost nothing has moved, because no one can list what they "
         "have. Cryptography hides in source, transitive dependencies, "
         "binaries with no source, certificate stores, deployment config and "
         "shipped container images.", "body"),

        ("Our solution", "head"),
        ("Seven sensors read what is actually there. Every finding becomes a "
         "distinct asset, classified by what a quantum computer does to it, "
         "scored, matched to a named replacement, and exported as a CycloneDX "
         "CBOM. One operator, one machine, no network.", "body"),

        ("Three things no other inventory does", "head"),
        (("Purpose, not keyword. ",
          "RSA signing and RSA key transport are one algorithm and two "
          "migrations — ML-DSA against ML-KEM. Purpose is resolved from the "
          "call site, and when the evidence is silent the tool names no "
          "target rather than the wrong one."), "bullet"),
        (("Assurance is a field, not a footnote. ",
          "Capability, declared, used, observed. A library that can do RSA is "
          "not proof that RSA runs."), "bullet"),
        (("Containers read layer by layer. ",
          "A key deleted by a later layer is reported as historical: gone at "
          "runtime, still extractable from the archive."), "bullet"),
    ], size=11.5, gap=4)

    shot(slide, "04-inventory.png", 6.62, 1.30, width=6.26,
         caption="One scan. Three RSA findings, three different "
                 "recommendations — and the third refuses to guess.")

    note(slide, LEFT, 5.72, RIGHT_EDGE - LEFT, 1.05, [
        (("Where it looks — ",
          "source (Python AST, plus rule packs for seven more languages) · "
          "dependency manifests · ELF binaries · X.509 certificates · server "
          "and application configuration · container images (OCI layout, OCI "
          "tar, docker save) · one live TLS endpoint the operator names."),
         "body"),
        ("Every sensor but the TLS probe runs with the network unplugged.",
         "note"),
    ], size=10.5, gap=3)


# ==========================================================================
# Slide 3 -- how it works, and why the architecture is credible
# ==========================================================================

def build_technical(slide) -> None:
    body(slide, LEFT, TOP, 6.05, 1.62, [
        ("Stack", "head"),
        ("Python 3.11+ · FastAPI · SQLite · a vanilla JavaScript console with "
         "no build step, no framework and no CDN.", "body"),

        ("Seven discovery sensors", "head"),
        ("source · dependency · binary (ELF symbols, constants, banners) · "
         "certificate (X.509, KeyUsage) · configuration · container (layer "
         "replay with whiteouts) · network (live TLS).", "body"),
    ], size=10.5, gap=3)

    note(slide, 6.85, TOP, 6.03, 1.62, [
        ("Risk engine", "head"),
        ("Mosca's inequality, X + Y > Z, read differently per purpose: "
         "harvest-now-decrypt-later for key establishment, forgery-after-"
         "Q-Day for signatures, a Grover margin for symmetric keys. Q-Day is "
         "a scenario the operator chooses, never a forecast.", "body"),

        ("Output and posture", "head"),
        ("CycloneDX 1.6 (ECMA-424) and 1.7, each validated offline against "
         "its own official schema. Loopback by default; refuses a "
         "non-loopback bind without a token.", "body"),
    ], size=10.5, gap=3)

    figure(slide, DIAGRAM, 2.22, 2.88, 8.90, 3.58,
           caption="Left to right: inputs, the security gate each one passes "
                   "through, the seven sensors, the analysis chain, and the "
                   "outputs. The TLS probe (dashed) is the only outbound "
                   "path — there is no cloud, KMS, HSM or registry box, "
                   "because no such integration exists.")


# ==========================================================================
# Slide 4 -- why this is feasible, validated and real
# ==========================================================================

def build_feasibility(slide) -> None:
    body(slide, LEFT, TOP, 8.00, 4.45, [
        ("It is built, not proposed", "head"),
        (("~9,000 lines of first-party Python and JavaScript · 664 automated "
          "tests · CI on Python 3.11, 3.12 and 3.13 · ", "every figure on "
          "this slide is reproducible by a command in this repository."),
         "body"),

        ("How we know it works", "head"),
        (("Measured, not asserted. ",
          "A hand-labelled corpus of 116 findings across six scanners, "
          "written by reading the fixtures rather than by running the tool. "
          "It found seven real detector defects that code review had missed. "
          "CI fails if precision or recall regresses."), "bullet"),
        (("Conformance is checked by the standard, not by us. ",
          "Every CBOM is validated against the official CycloneDX JSON "
          "Schemas, offline, at a pinned commit. CI fails on any violation."),
         "bullet"),

        ("The three risks that actually matter, and the answers", "head"),
        (("Hostile input. ",
          "It reads untrusted paths and archives, so: filesystem boundary "
          "with symlink-escape refusal, per-member archive vetting, bounded "
          "streaming with nothing extracted to disk, and a destination policy "
          "that resolves, vets every resolved address, then connects to the "
          "vetted literal."), "bullet"),
        (("A partial scan mistaken for a complete one. ",
          "The most damaging thing this tool could produce. Every scan "
          "carries an explicit complete-or-partial flag and its reasons into "
          "the console, the report and the CBOM."), "bullet"),
        (("Leaking what it finds. ",
          "A crypto inventory is the most sensitive file an estate owns. "
          "Evidence is redacted before export; the location is kept, because "
          "that is what makes a finding actionable."), "bullet"),

        ("What that adds up to", "head"),
        (("664 automated tests · 116 labelled benchmark findings across six "
          "scanners · 7 detector defects the benchmark found that code review "
          "did not · 0 schema violations, ", "each checked by CI on every "
          "push to this branch."), "body"),
    ], size=10.5, gap=3)

    shot(slide, "07-evidence-drawer.png", 8.72, 1.26, width=4.16,
         caption="Every finding opens onto the evidence behind it and the "
                 "arithmetic behind its score.")

    # Confined to the text column's width: the evidence panel's caption sits
    # to the right of it, and a full-width strip would run underneath.
    note(slide, LEFT, 5.80, 8.00, 1.0, [
        (("Stated limits — ",
          "full AST analysis is Python only; seven more languages use curated "
          "rule packs, and Rust and Swift are recognised but effectively "
          "uncovered. Binary parsing is ELF only, so Mach-O and PE are out of "
          "scope. No KMS, HSM, cloud or Kubernetes integration exists, and "
          "none is claimed."), "body"),
        (("Reproduce it — ", "python -m pytest  ·  python -m benchmark.run  ·  "
          "python run.py --demo  ·  python run.py --preflight-offline"),
         "note"),
    ], size=10, gap=3)


# ==========================================================================
# Slide 5 -- the impact, and the evidence for it
# ==========================================================================

def build_impact(slide) -> None:
    body(slide, LEFT, TOP, 6.05, 4.50, [
        ("Who it is for", "head"),
        ("Security engineers and migration programme owners who have been "
         "told to move to post-quantum cryptography and have no inventory to "
         "move.", "body"),

        ("What changes for them", "head"),
        ("“We think we use RSA somewhere” becomes a per-asset list with file, "
         "line, purpose, evidence strength and a named replacement.",
         "bullet"),
        ("What an estate runs is separated from what it merely has installed, "
         "so the migration plan is not padded with libraries nobody calls.",
         "bullet"),
        ("The output is a published standard a regulator or a downstream tool "
         "can consume, not a bespoke report format.", "bullet"),
        ("A partial scan is labelled partial, so nobody signs off an estate "
         "on an inventory that silently missed half of it.", "bullet"),

        ("Measured evidence — on a synthetic corpus, and only that", "head"),
        (("Precision 1.000  ·  recall 1.000  ·  F1 1.000 ",
          "over 116 hand-labelled findings across six scanners."), "body"),
        (("Cryptographic purpose correct on 114 of 114 ",
          "scored cases; assurance on 116 of 116."), "body"),
        ("Read that precisely. These figures measure a developer-written "
         "corpus this project wrote. They are NOT an estimate of real-world "
         "enterprise accuracy, which has not been measured and is not "
         "claimed. Network-sensor accuracy is excluded entirely, because what "
         "a TLS handshake negotiates depends on the local library build.",
         "note"),
    ], size=11, gap=3)

    note(slide, LEFT, 5.74, 6.05, 1.08, [
        ("Why it matters", "head"),
        ("The inventory is the gate every other migration step waits behind. "
         "Standardised algorithms do not help an estate that cannot say where "
         "its cryptography is. This produces that list, with the evidence "
         "attached, on a machine that never has to leave the building.",
         "body"),
    ], size=10.5, gap=2)

    shot(slide, "01-assessment.png", 6.72, 1.26, width=6.16,
         caption="The whole estate in one screen — with the partial-scan "
                 "warning stated at the top rather than buried in a payload.")

    note(slide, 6.72, 5.86, 6.16, 0.95, [
        (("Adoption cost — ",
          "one command. No daemon, no agent, no cloud account, no network. It "
          "reads a repository, a binary tree or a container image on the "
          "machine it is already running on."), "note"),
    ], size=10.5, gap=2)


# ==========================================================================
# Slide 6 -- the standards this is built against
# ==========================================================================

def build_references(slide) -> None:
    shrink_title(slide, 29)

    body(slide, LEFT, TOP, 6.30, 4.60, [
        ("Standards implemented", "head"),
        ("FIPS 203 — ML-KEM · FIPS 204 — ML-DSA · FIPS 205 — SLH-DSA",
         "bullet"),
        ("FIPS 202 — SHA-3 and SHAKE · SP 800-208 — LMS", "bullet"),
        ("NIST IR 8547 — transition to post-quantum cryptography standards",
         "bullet"),

        ("Formats and specifications", "head"),
        ("CycloneDX 1.6 (ECMA-424) and CycloneDX 1.7 — cryptographic bill of "
         "materials; schemas vendored from the CycloneDX specification "
         "repository at pinned commit 0bd48c8", "bullet"),
        ("RFC 8996 — deprecation of TLS 1.0 and 1.1 · RFC 7693 — BLAKE2 · "
         "RFC 8032 — EdDSA · RFC 7748 — X25519 and X448", "bullet"),
        ("OCI Image Format Specification — image layout and layer whiteouts",
         "bullet"),

        ("Method", "head"),
        ("Mosca's inequality (X + Y > Z) for exposure timing; Shor's and "
         "Grover's algorithms for the classification split.", "bullet"),

        ("Project", "head"),
        ("github.com/sgtsujith141-wq/cryptodrishti — source, 664 tests, the "
         "labelled corpus and its committed results, the vendored schemas, "
         "and the architecture diagram's editable source.", "bullet"),
        ("Problem statement SIH26164, National Technical Research "
         "Organisation (NTRO).", "bullet"),

        ("Where this has not been checked", "head"),
        ("The classifications follow NIST IR 8547 and the CycloneDX "
         "specification as we read them; they have not been reviewed by an "
         "external cryptographer. The vendored schemas are checksummed and "
         "pinned, and CI fails if they drift — but they are a snapshot of an "
         "upstream that moves.", "body"),
    ], size=10.5, gap=2)

    below = shot(slide, "05-cbom-export.png", 6.95, 1.26, width=5.93,
                 caption="Export and validation are the same screen: checked "
                         "against the official schema on the spot.")
    below = shot(slide, "03-migration-plan.png", 6.95, below + 0.16,
                 width=5.93,
                 caption="The standards on the left, applied — every asset "
                         "given the target that matches its resolved purpose.")

    note(slide, 6.95, below + 0.18, 5.93, 0.90, [
        ("Every externally sourced claim in this deck is one of the standards "
         "listed here. Nothing is claimed about quantum-computer arrival "
         "dates, regulatory deadlines or competing products — Q-Day is "
         "treated throughout as an operator-chosen scenario.", "note"),
    ], size=10, gap=2)


# --------------------------------------------------------------------------

def main() -> int:
    if not TEMPLATE.is_file():
        print(f"template not found: {TEMPLATE}", file=sys.stderr)
        return 1
    needed = [DIAGRAM] + [SHOTS / n for n in (
        "01-assessment.png", "03-migration-plan.png", "04-inventory.png",
        "05-cbom-export.png", "06-scan-history.png", "07-evidence-drawer.png")]
    missing = [p.name for p in needed if not p.is_file()]
    if missing:
        print(f"missing assets: {', '.join(missing)}", file=sys.stderr)
        print("run `python run.py --demo`, serve it, then "
              "`python submission/build/capture_screens.py`", file=sys.stderr)
        return 1

    prs = Presentation(str(TEMPLATE))

    # Slide 7 is the template's own instructions page, whose text says to keep
    # the deck to six slides. Removing it is following the template.
    delete_slide(prs, 6)
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

    for slide in (s2, s3, s4, s5, s6):
        set_team_oval(slide, portal("team_name"))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(OUT))
    print(f"written: {OUT.relative_to(ROOT)}  ({len(prs.slides)} slides)")

    labels = {
        "ps_id": "Problem Statement ID",
        "ps_title": "Problem Statement Title (verbatim)",
        "theme": "Theme",
        "category": "PS Category",
        "team_id": "Team ID",
        "team_name": "Team Name (also shown in each slide's oval)",
    }
    unfilled = [labels[k] for k in labels if portal(k) == FILL_IN]
    if unfilled:
        print("\nSTILL TO FILL FROM THE SIH PORTAL (this script will not guess):")
        for item in unfilled:
            print(f"  - {item}")
    else:
        print("\nRegistration details, as written into the title slide:")
        for key, label in labels.items():
            print(f"  {label.split(' (')[0]:26s} {PORTAL[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
