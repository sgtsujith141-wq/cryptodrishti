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
* **Nothing is invented.** Values this repository cannot establish -- Team ID,
  Team Name, the portal's Theme string, the verbatim problem-statement title --
  are written as explicit fill-in markers rather than plausible guesses, and
  the build prints them at the end.
* **Only genuine screenshots.** Every image is a capture of the running
  application from `submission/screenshots/`, or the architecture diagram
  rendered from `docs/architecture/architecture.mmd`. Images are trimmed of
  their empty margins so they are legible at slide size; nothing else is
  altered, and no interface is mocked up.
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
DIAGRAM = ROOT / "docs" / "architecture" / "architecture.png"
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

# The template's own furniture. Content must stay inside these bounds: the
# title and the team oval occupy the top, the blue footer bar the bottom.
TOP = 1.22
BOTTOM = 6.84
LEFT = 0.45
RIGHT_EDGE = 12.88
COL_L_W = 6.60
COL_R_X = 7.32
COL_R_W = 5.56

INK = RGBColor(0x1A, 0x1A, 0x1A)
MUTED = RGBColor(0x5A, 0x5A, 0x5A)
ACCENT = RGBColor(0x8C, 0x1D, 0x1D)


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------

def trim(name: str, *, source: Path | None = None,
         keep_top: float = 1.0) -> Path:
    """Return the screenshot with its uniform outer margin removed.

    The captures are whole-viewport PNGs, so a third of each one is empty page
    background; at slide scale that shrinks the interface to illegibility.
    Cropping to the content's bounding box is the only change made -- no
    scaling of content, no retouching, no composition of separate captures.
    """
    src = source or (SHOTS / name)
    TRIMMED.mkdir(parents=True, exist_ok=True)
    suffix = "" if keep_top >= 1.0 else f"-top{int(keep_top * 100)}"
    dst = TRIMMED / f"{src.stem}{suffix}{src.suffix}"
    if dst.is_file() and dst.stat().st_mtime >= src.stat().st_mtime:
        return dst
    im = Image.open(src).convert("RGB")
    background = im.getpixel((4, im.height // 2))
    diff = ImageChops.difference(im, Image.new("RGB", im.size, background))
    box = diff.convert("L").point(lambda v: 255 if v > 12 else 0).getbbox()
    out = im.crop(box) if box else im
    if keep_top < 1.0:
        out = out.crop((0, 0, out.width, int(out.height * keep_top)))
    out.save(dst)
    return dst


def picture(slide, name, left, top, width, *, caption=None, source=None,
            keep_top=1.0):
    """Place a trimmed capture and return the y coordinate just below it."""
    path = trim(name, source=source, keep_top=keep_top)
    pic = slide.shapes.add_picture(str(path), Inches(left), Inches(top),
                                   width=Inches(width))
    pic.name = f"cd-shot-{Path(name).stem}"
    bottom = top + Emu(pic.height).inches
    if caption:
        add_caption(slide, left, bottom + 0.06, width, caption)
        bottom += 0.06 + 0.30
    return bottom


def fit_picture(slide, path, left, top, width, max_height):
    """Place an image scaled down if it would otherwise run past `max_height`."""
    w, h = Image.open(path).size
    height = width * h / w
    if height > max_height:
        height, width = max_height, max_height * w / h
    pic = slide.shapes.add_picture(str(path), Inches(left), Inches(top),
                                   width=Inches(width), height=Inches(height))
    pic.name = f"cd-figure-{Path(path).stem}"
    return top + Emu(pic.height).inches


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
        pPr.set("marL", "182880")
        pPr.set("indent", "-182880")
        font = pPr.makeelement(qn("a:buFont"), {"typeface": "Arial"})
        char = pPr.makeelement(qn("a:buChar"), {"char": "•"})
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
        font.size, font.bold, font.color.rgb = Pt(size + 1), True, ACCENT
    elif style == "lead":
        font.size, font.bold, font.color.rgb = Pt(size), True, INK
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


def band(slide, top, blocks, *, size=11, gap=3):
    """A full-width strip under both columns, so the lower third carries content."""
    box = slide.shapes.add_textbox(Inches(LEFT), Inches(top),
                                   Inches(RIGHT_EDGE - LEFT), Inches(BOTTOM - top))
    write(box.text_frame, blocks, size=size, gap=gap)
    box.name = "cd-band"
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
            run.font.size = Pt(9)


def delete_slide(prs, index: int) -> None:
    """Remove a slide and its entry in the slide id list."""
    slides = prs.slides._sldIdLst
    slide_id = list(slides)[index]
    rid = slide_id.get(
        "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
    prs.part.drop_rel(rid)
    slides.remove(slide_id)


# --------------------------------------------------------------------------
# Slide 1 -- Title
# --------------------------------------------------------------------------

def build_title(slide) -> None:
    box = shape_by_name(slide, "TextBox 9")
    place(box, LEFT, 2.25, 6.2, 3.65)
    write(box.text_frame, [
        ("Problem Statement ID – " + portal("ps_id"), "lead"),
        ("Problem Statement Title – " + portal("ps_title"), "body"),
        ("Theme – " + portal("theme"), "body"),
        ("PS Category – " + portal("category"), "body"),
        ("Team ID – " + portal("team_id"), "body"),
        ("Team Name – " + portal("team_name"), "body"),
    ], size=15, gap=9)

    note = slide.shapes.add_textbox(Inches(LEFT), Inches(6.05), Inches(6.2),
                                    Inches(0.9))
    note.name = "cd-note"
    note.text_frame.word_wrap = True
    write(note.text_frame, [
        ("CryptoDrishti — cryptographic discovery, quantum-risk "
         "assessment and post-quantum migration planning.", "lead"),
        ("Problem statement raised by the National Technical Research "
         "Organisation (NTRO).", "note"),
    ], size=12, gap=2)
    for para in note.text_frame.paragraphs:
        for run in para.runs:
            if not run.font.italic:
                run.font.color.rgb = ACCENT


# --------------------------------------------------------------------------
# Slide 2 -- Proposed Solution
# --------------------------------------------------------------------------

def build_solution(slide) -> None:
    set_title(slide, "CryptoDrishti  |  PROPOSED SOLUTION", size=30)

    body(slide, LEFT, TOP, COL_L_W, 4.4, [
        ("The problem", "head"),
        ("An organisation cannot migrate cryptography it cannot enumerate. "
         "Keys, algorithms and protocols are scattered across source code, "
         "transitive dependencies, compiled binaries with no source, "
         "certificate stores, deployment configuration and shipped container "
         "images.", "body"),

        ("Our solution", "head"),
        ("A single-operator tool that reads what is actually present, "
         "classifies every asset by what a quantum computer does to it, and "
         "emits a standards-conformant CycloneDX CBOM.", "body"),

        ("What is genuinely new here", "head"),
        (("Purpose, not keyword. ",
          "Cryptographic purpose is resolved from the call site. RSA signing "
          "and RSA key transport are one algorithm and two different "
          "migrations — ML-DSA against ML-KEM — and the tool refuses "
          "to name a target when the evidence does not settle which."),
         "bullet"),
        (("Assurance is a field. ",
          "Capability, declared, used, observed. A library that can do RSA is "
          "not evidence that RSA is used, and the inventory says so."),
         "bullet"),
        (("Layer-aware containers. ",
          "A key deleted by a later layer is reported as historical — "
          "still extractable from the archive, not present at runtime."),
         "bullet"),
    ], size=12, gap=4)

    picture(slide, "04-inventory.png", COL_R_X, 1.26, COL_R_W,
            caption="One scan, three RSA findings, three different answers — "
                    "and the third refuses to guess.")

    band(slide, 5.62, [
        (("Where it looks — ",
          "source code (Python AST plus curated rules for seven more languages) "
          "· dependency manifests · ELF binaries · X.509 "
          "certificates · server and application configuration · "
          "container images (OCI layout, OCI tar, docker save) · a live "
          "TLS endpoint the operator names."), "body"),
        ("Everything except the TLS probe runs entirely offline.", "note"),
    ], size=11, gap=3)


# --------------------------------------------------------------------------
# Slide 3 -- Technical Approach
# --------------------------------------------------------------------------

def build_technical(slide) -> None:
    body(slide, LEFT, TOP, 5.30, 4.10, [
        ("Stack", "head"),
        ("Python 3.11+ · FastAPI · SQLite · a vanilla "
         "JavaScript console with no build step, no framework and no CDN.",
         "body"),

        ("Seven discovery sensors", "head"),
        ("source · dependency · binary (ELF symbols) · "
         "certificate (X.509 and KeyUsage) · configuration · "
         "container · network (live TLS).", "body"),

        ("Risk engine", "head"),
        ("Mosca's inequality, X + Y > Z, with a purpose-specific reading of X: "
         "harvest-now-decrypt-later for key establishment, forgery-after-Q-Day "
         "for signatures, a Grover margin for symmetric keys. Q-Day is an "
         "operator-chosen scenario, never a forecast.", "body"),

        ("Output", "head"),
        ("CycloneDX 1.6 and 1.7 CBOM, validated offline against the official "
         "JSON Schemas vendored at a pinned upstream commit, plus a "
         "self-contained HTML report.", "body"),

        ("Deployment", "head"),
        ("One operator, loopback by default. The server refuses to start on a "
         "non-loopback bind without an access token.", "body"),
    ], size=11, gap=3)

    note = slide.shapes.add_textbox(Inches(LEFT), Inches(5.42),
                                    Inches(5.30), Inches(1.35))
    note.name = "cd-note"
    note.text_frame.word_wrap = True
    write(note.text_frame, [
        (("What it does not do — ",
          "no agent, no daemon, no telemetry and no outbound call the operator "
          "did not ask for. A scan of a directory or an image archive touches "
          "the network zero times."), "note"),
    ], size=10.5, gap=2)

    bottom = fit_picture(slide, DIAGRAM, 6.05, 1.20, 6.83, 5.28)
    add_caption(slide, 6.05, bottom + 0.05, 6.83,
                "Security gates sit between every input and every sensor. The "
                "TLS probe (dashed) is the only outbound path; no cloud, KMS, "
                "HSM or registry integration exists, so none is drawn.")


# --------------------------------------------------------------------------
# Slide 4 -- Feasibility and Viability
# --------------------------------------------------------------------------

def build_feasibility(slide) -> None:
    body(slide, LEFT, TOP, COL_L_W, 4.28, [
        ("It is built, not proposed", "head"),
        ("A working prototype of roughly 9,000 lines of first-party Python and "
         "JavaScript, with 664 automated tests and continuous integration on "
         "Python 3.11, 3.12 and 3.13.", "body"),

        ("How it is validated", "head"),
        (("Hand-labelled corpus. ",
          "116 findings across six scanners, with deliberately difficult "
          "negatives — comments, prose, crypto-shaped identifiers, a "
          "disable-list. CI fails if precision or recall regresses."),
         "bullet"),
        (("Schema conformance. ",
          "Every CBOM is checked against the official CycloneDX JSON Schemas, "
          "offline, at a pinned commit. CI fails on any violation."), "bullet"),

        ("Risks, and what we did about them", "head"),
        (("Hostile input. ",
          "The tool reads untrusted paths and archives, so it enforces a "
          "filesystem boundary that refuses symlink escapes, vets every "
          "archive member, streams under a size budget with nothing extracted "
          "to disk, and resolves-then-vets every network address before "
          "connecting to the vetted literal."), "bullet"),
        (("A partial scan read as complete. ",
          "The most damaging output this tool could produce. Every scan "
          "carries an explicit complete-or-partial flag and its reasons into "
          "the console, the report and the CBOM."), "bullet"),
        (("Leaking what it finds. ",
          "Evidence is redacted before export; the location is kept, because "
          "that is what makes a finding actionable."), "bullet"),
    ], size=10.5, gap=3)

    picture(slide, "07-evidence-drawer.png", COL_R_X, 1.26, COL_R_W,
            caption="Every finding opens onto its evidence: file, line, "
                    "technique, confidence, assurance and the exposure "
                    "arithmetic behind its score.")

    band(slide, 5.58, [
        (("Honest constraints — ",
          "full AST analysis is Python only; seven more languages have curated "
          "rule packs, and Rust and Swift are recognised but effectively "
          "uncovered. Binary symbol parsing is ELF only, so Mach-O and PE "
          "are out of scope. No KMS, HSM, cloud or Kubernetes integration "
          "is implemented, and none is claimed."), "body"),
        (("Reproduce every number above — ",
          "python -m pytest  ·  python -m benchmark.run  ·  "
          "python run.py --preflight-offline"), "note"),
    ], size=10.5, gap=3)


# --------------------------------------------------------------------------
# Slide 5 -- Impact and Benefits
# --------------------------------------------------------------------------

def build_impact(slide) -> None:
    body(slide, LEFT, TOP, COL_L_W, 4.44, [
        ("Who it is for", "head"),
        ("Security engineers and migration programme owners who have been told "
         "to move to post-quantum cryptography and do not yet have an "
         "inventory to move.", "body"),

        ("What it changes", "head"),
        ("Turns “we think we use RSA somewhere” into a per-asset list "
         "with file, line, purpose, evidence strength and a named replacement.",
         "bullet"),
        ("Separates what an estate runs from what it merely has available, so "
         "a migration plan is not padded with libraries nobody calls.",
         "bullet"),
        ("Produces a CBOM a regulator or a downstream tool can actually "
         "consume, in a published standard rather than a bespoke format.",
         "bullet"),

        ("Measured evidence", "head"),
        ("Across the project's own labelled corpus of 116 findings: precision "
         "1.000, recall 1.000, F1 1.000, with cryptographic purpose correct on "
         "114 of 114 scored cases.", "body"),
        ("These figures measure a developer-written synthetic corpus. They are "
         "NOT an estimate of real-world enterprise accuracy, which this project "
         "has not measured and does not claim. Network-sensor accuracy is "
         "excluded, because what a TLS handshake negotiates depends on the "
         "local library build.", "note"),

        ("Adoption cost", "head"),
        ("One command, no daemon, no network, no cloud account. It reads a "
         "repository, a binary tree or a container image on the machine it is "
         "already running on.", "body"),
    ], size=11, gap=3)

    note = slide.shapes.add_textbox(Inches(LEFT), Inches(5.72),
                                    Inches(COL_L_W), Inches(1.1))
    note.name = "cd-note"
    note.text_frame.word_wrap = True
    write(note.text_frame, [
        (("Both screens beside this text come from one command — ",
          "python run.py --demo builds a synthetic estate and a container "
          "image, scans them, records an operator override and leaves the "
          "console showing exactly what is shown here."), "note"),
    ], size=10.5, gap=2)

    bottom = picture(slide, "06-scan-history.png", COL_R_X, 1.26, COL_R_W,
                     caption="A partial scan is labelled PARTIAL, with the "
                             "reason, rather than passed off as a complete "
                             "inventory.")
    picture(slide, "02-exposure.png", COL_R_X, bottom + 0.30, COL_R_W,
            caption="Exposure is shown as arithmetic the operator can argue "
                    "with — secrecy, migration effort and the chosen "
                    "Q-Day scenario, each labelled by where its value came "
                    "from.")


# --------------------------------------------------------------------------
# Slide 6 -- Research and References
# --------------------------------------------------------------------------

def build_references(slide) -> None:
    shrink_title(slide, 30)

    body(slide, LEFT, TOP, 6.55, 4.3, [
        ("Standards implemented", "head"),
        ("FIPS 203 — ML-KEM, module-lattice key encapsulation", "bullet"),
        ("FIPS 204 — ML-DSA, module-lattice digital signatures", "bullet"),
        ("FIPS 205 — SLH-DSA, stateless hash-based signatures", "bullet"),
        ("FIPS 202 — SHA-3 and SHAKE; SP 800-208 — LMS", "bullet"),
        ("NIST IR 8547 — transition to post-quantum cryptography "
         "standards", "bullet"),

        ("Formats and specifications", "head"),
        ("CycloneDX 1.6 (ECMA-424) and CycloneDX 1.7 — cryptographic bill "
         "of materials; schemas vendored from the CycloneDX specification "
         "repository at pinned commit 0bd48c8", "bullet"),
        ("RFC 8996 — deprecation of TLS 1.0 and 1.1", "bullet"),
        ("RFC 7693 — BLAKE2 · RFC 8032 — EdDSA · RFC 7748 "
         "— X25519 and X448", "bullet"),
        ("OCI Image Format Specification — image layout and layer "
         "whiteouts", "bullet"),

        ("Method", "head"),
        ("Mosca's inequality (X + Y > Z) for exposure timing; Shor's and "
         "Grover's algorithms for the classification split.", "bullet"),

        ("Project", "head"),
        ("github.com/sgtsujith141-wq/cryptodrishti — source, 664 tests, "
         "the labelled benchmark corpus and its committed results, the "
         "vendored schemas, and the architecture diagram's editable source.",
         "bullet"),
        ("Problem statement SIH26164, raised by the National Technical "
         "Research Organisation (NTRO).", "bullet"),
    ], size=10.5, gap=2)

    note = slide.shapes.add_textbox(Inches(COL_R_X), Inches(TOP),
                                    Inches(COL_R_W), Inches(0.90))
    note.name = "cd-note"
    note.text_frame.word_wrap = True
    write(note.text_frame, [
        ("Every externally sourced claim in this deck is one of the standards "
         "or specifications listed here. Nothing is claimed about "
         "quantum-computer arrival dates, regulatory deadlines or competing "
         "products: Q-Day is treated throughout as an operator-chosen "
         "scenario.", "note"),
    ], size=11, gap=2)

    bottom = picture(slide, "05-cbom-export.png", COL_R_X, 2.18, COL_R_W,
                     keep_top=0.46,
                     caption="Export and validation are the same screen: the "
                             "CBOM is checked against the official schema on "
                             "the spot.")

    picture(slide, "03-migration-plan.png", COL_R_X, bottom + 0.30, COL_R_W,
            keep_top=0.72,
            caption="The standards on the left, applied: every asset is given "
                    "the target that matches its purpose, and anything "
                    "unresolved is handed to a human instead of guessed.")


# --------------------------------------------------------------------------

def main() -> int:
    if not TEMPLATE.is_file():
        print(f"template not found: {TEMPLATE}", file=sys.stderr)
        return 1
    needed = [DIAGRAM] + [SHOTS / n for n in (
        "02-exposure.png", "04-inventory.png", "05-cbom-export.png",
        "06-scan-history.png", "07-evidence-drawer.png")]
    missing = [p.name for p in needed if not p.is_file()]
    if missing:
        print(f"missing assets: {', '.join(missing)}", file=sys.stderr)
        print("run `python run.py --demo`, then capture the screenshots",
              file=sys.stderr)
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
