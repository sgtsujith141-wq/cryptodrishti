#!/usr/bin/env python3
"""Contact sheets: all six slides at once, and frames across the film.

    python submission/build/contact_sheet.py

A slide can pass every geometric check and still be a wall of text or an empty
infographic. Seeing the six side by side is the fastest way to judge whether
the deck reads as one designed document, and whether text and visuals are
actually in balance.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
PDF = ROOT / "submission" / "CryptoDrishti-SIH26164-Idea-Presentation.pdf"
VIDEO = ROOT / "submission" / "video" / "CryptoDrishti-Final-Demo.mp4"
OUT = ROOT / "submission" / "contact"

FONT = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
BG = (24, 24, 27)
INK = (236, 236, 232)


def sheet(images, cols, cell_w, labels, path, pad=26, title=""):
    rows = (len(images) + cols - 1) // cols
    cell_h = max(int(cell_w * im.height / im.width) for im in images)
    head = 58 if title else 0
    W = cols * cell_w + pad * (cols + 1)
    H = head + rows * (cell_h + 34) + pad * (rows + 1)
    sheet_im = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(sheet_im)
    if title:
        draw.text((pad, 18), title, font=ImageFont.truetype(FONT, 26),
                  fill=INK)
    small = ImageFont.truetype(FONT, 17)
    for i, im in enumerate(images):
        r, c = divmod(i, cols)
        x = pad + c * (cell_w + pad)
        y = head + pad + r * (cell_h + 34 + pad)
        thumb = im.resize((cell_w, int(cell_w * im.height / im.width)),
                          Image.LANCZOS)
        draw.rectangle((x - 1, y - 1, x + cell_w, y + thumb.height),
                       outline=(70, 70, 76))
        sheet_im.paste(thumb, (x, y))
        draw.text((x, y + thumb.height + 8), labels[i], font=small,
                  fill=(168, 168, 174))
    sheet_im.save(path)
    return path


def slides() -> Path:
    import pymupdf
    doc = pymupdf.open(str(PDF))
    imgs, labs = [], []
    for i, page in enumerate(doc, 1):
        pix = page.get_pixmap(dpi=100)
        imgs.append(Image.frombytes("RGB", (pix.width, pix.height),
                                    pix.samples))
        labs.append(f"Slide {i}")
    OUT.mkdir(parents=True, exist_ok=True)
    return sheet(imgs, 3, 640, labs, OUT / "deck-contact-sheet.png",
                 title="CryptoDrishti — SIH26164 — six-slide contact sheet")


def scene_midpoints() -> list[tuple[str, float]] | None:
    """The middle of every scene, computed the way the film was timed.

    Sampling at fixed intervals instead means some scenes get two frames and
    others none, which makes the sheet useless for the thing it exists for --
    checking that every scene actually drew something worth looking at.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import make_film as M                               # noqa: PLC0415
        import film_scenes as F                             # noqa: PLC0415
    except ImportError:
        return None
    out, clock = [], 0.0
    for sc in F.SCENES:
        chunks = M.caption_plan(sc["cap"])
        seconds = max(sc["beats"] / 1000.0 + 0.6,
                      sum(d for _t, d in chunks) + M.CAPTION_PAD)
        out.append((sc["id"], clock + seconds * 0.62))
        clock += seconds
    return out


def frames(count: int = 12) -> Path | None:
    if not VIDEO.is_file():
        return None
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                          "format=duration", "-of", "csv=p=0", str(VIDEO)],
                         capture_output=True, text=True, check=True)
    dur = float(out.stdout.strip())
    marks = scene_midpoints()
    if marks:
        # 0.62 through each scene: past the reveal, before the dip to black.
        marks = [(n, t) for n, t in marks if t < dur]
    else:
        marks = [(f"{int(dur*(i+.5)/count//60)}:"
                  f"{int(dur*(i+.5)/count%60):02d}", dur * (i + 0.5) / count)
                 for i in range(count)]
    OUT.mkdir(parents=True, exist_ok=True)
    imgs, labs = [], []
    for i, (name, t) in enumerate(marks):
        tmp = OUT / f".f{i}.png"
        subprocess.run(["ffmpeg", "-v", "error", "-ss", f"{t:.2f}",
                        "-i", str(VIDEO), "-frames:v", "1", "-y", str(tmp)],
                       check=True)
        imgs.append(Image.open(tmp).convert("RGB"))
        labs.append(f"{name}  {int(t // 60)}:{int(t % 60):02d}")
    cols = 4 if len(imgs) > 9 else 3
    path = sheet(imgs, cols, 460, labs, OUT / "film-contact-sheet.png",
                 title="CryptoDrishti — full film — one frame per scene")
    for i in range(len(imgs)):
        (OUT / f".f{i}.png").unlink(missing_ok=True)
    return path


def main() -> int:
    if PDF.is_file():
        print(f"  {slides().relative_to(ROOT)}")
    f = frames()
    if f:
        print(f"  {f.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
