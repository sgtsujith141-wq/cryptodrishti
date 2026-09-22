#!/usr/bin/env python3
"""Assemble the submission demonstration video.

    python submission/build/make_video.py

What this produces is an **assembled product overview**, not a screen
recording: every visual is a still capture of the running application (or the
architecture diagram rendered from its source), given slow motion and cut
together with narration. Nothing is simulated -- no cursor is animated, no
interaction is faked, and no output appears on screen that the tool did not
actually produce.

Pipeline, all local:

* narration from macOS `say`, one clip per scene, measured with `ffprobe` so
  the picture is cut to the voice rather than the other way round;
* frames composited with Pillow at 1920x1080 and piped straight into `ffmpeg`,
  so no intermediate PNGs are ever written to disk;
* H.264 video, AAC audio, `yuv420p` for players that insist on it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
SHOTS = ROOT / "submission" / "screenshots"
DIAGRAM = ROOT / "docs" / "architecture" / "architecture-dark.png"
OUT = ROOT / "submission" / "CryptoDrishti-SIH26164-Demo.mp4"

W, H = 1920, 1080
FPS = 30
VOICE = "Daniel"
RATE = 168

# The console's own dark palette, so the frame and the screenshots inside it
# read as one product.
BG = (14, 15, 17)
INK = (236, 236, 232)
MUTED = (138, 147, 159)
RED = (217, 80, 60)
GREEN = (63, 174, 134)
RULE = (43, 46, 51)

FONTS = "/System/Library/Fonts/Supplemental"
F_BOLD = f"{FONTS}/Arial Bold.ttf"
F_REG = f"{FONTS}/Arial.ttf"
F_IT = f"{FONTS}/Arial Italic.ttf"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


@dataclass
class Scene:
    kind: str                     # title | statement | visual
    say: str                      # narration
    heading: str = ""
    lines: list[str] = field(default_factory=list)
    image: Path | None = None
    crop: tuple[float, float, float, float] | None = None   # l,t,r,b fractions
    footer: str = ""
    hold: float = 1.0             # seconds added after the narration ends


def scenes() -> list[Scene]:
    return [
        Scene(
            kind="title",
            heading="CryptoDrishti",
            lines=["Enterprise Cryptographic Discovery & Analysis Tool",
                   "Problem Statement SIH26164  ·  Team 146876 — Zero-Day"],
            footer="Assembled from real screen captures of the running tool. "
                   "No interaction is simulated.",
            say="Crypto Drishti. An enterprise cryptographic discovery and "
                "analysis tool, built for Smart India Hackathon problem "
                "statement S I H twenty six one six four.",
            hold=1.4),

        Scene(
            kind="statement",
            heading="Migration is an inventory problem first",
            lines=[
                "NIST published the replacement algorithms in 2024.",
                "Almost nothing has moved — because almost nobody can list "
                "what they actually have.",
                "",
                "Cryptography hides in source code, transitive dependencies, "
                "binaries with no source,",
                "certificate stores, deployment configuration, and inside "
                "shipped container images.",
            ],
            say="Post-quantum migration is an inventory problem before it is "
                "a mathematics problem. NIST published the replacement "
                "algorithms in twenty twenty four. Almost nothing has moved, "
                "because almost nobody can list what they actually have. "
                "Cryptography hides in source code, in transitive "
                "dependencies, in binaries with no source, in certificate "
                "stores, in deployment configuration, and inside shipped "
                "container images."),

        Scene(
            kind="visual",
            heading="Seven sensors, one inventory",
            lines=["Every finding becomes a distinct asset — classified, "
                   "scored, and matched to a named replacement."],
            image=SHOTS / "04-inventory.png",
            crop=(0.055, 0.03, 1.0, 0.60),
            say="Crypto Drishti reads what is actually there. Seven sensors, "
                "one inventory. Every finding becomes a distinct "
                "cryptographic asset, classified by what a quantum computer "
                "does to it, scored for exposure, and matched to a named "
                "replacement."),

        Scene(
            kind="visual",
            heading="The architecture",
            lines=["Inputs, the gate each one passes, seven sensors, the "
                   "analysis chain, the outputs."],
            image=DIAGRAM,
            say="Left to right: the inputs, the security gate each one passes "
                "through, the seven discovery sensors, the analysis chain, "
                "and the outputs. Every input is vetted before a sensor sees "
                "it. The live T L S probe is the only outbound path in the "
                "system. There is no cloud, no key management service and no "
                "registry integration, so none is drawn."),

        Scene(
            kind="visual",
            heading="One algorithm. Three different answers.",
            lines=["RSA signing, RSA key establishment, and RSA the tool "
                   "refuses to guess about."],
            image=SHOTS / "04-inventory.png",
            crop=(0.055, 0.03, 1.0, 0.30),
            say="Here is the idea the tool is built around. Three R S A "
                "findings, in one scan. The first is a signing call, and the "
                "recommendation is M L D S A sixty five. The second is R S A "
                "O A E P doing key establishment, and the recommendation is a "
                "hybrid key exchange — a completely different migration. The "
                "third: the tool can see that R S A is permitted, but not "
                "what it is used for. So it says, purpose must be resolved "
                "first, rather than guessing.",
            hold=1.3),

        Scene(
            kind="visual",
            heading="Evidence, and the arithmetic behind the score",
            lines=["Capability, declared, used, observed — a library that "
                   "can do RSA is not proof that RSA runs."],
            image=SHOTS / "07-evidence-drawer.png",
            crop=(0.0, 0.0, 1.0, 0.53),
            say="Every finding opens onto the evidence behind it. The file, "
                "the line, the technique, the confidence, and how strong the "
                "evidence is that this asset is actually used. Capability, "
                "declared, used, or observed. A library that can do R S A is "
                "not proof that R S A runs. Below that, the exposure "
                "arithmetic: how long the data must stay secret, how long "
                "migration takes, and the operator's chosen Q Day scenario."),

        Scene(
            kind="visual",
            heading="Two things it refuses to do",
            lines=["It will not pass off a partial scan as a complete "
                   "inventory, and it will not hide a deleted key."],
            image=SHOTS / "01-assessment.png",
            crop=(0.055, 0.0, 1.0, 1.0),
            say="Two things this tool refuses to do. It will not present a "
                "partial scan as a complete inventory. When a sensor is "
                "refused, the scan says so, and that warning travels into the "
                "report and into the C BOM. And when it reads a container "
                "image, a key deleted by a later layer is reported as "
                "historical. Gone at runtime, still extractable from the "
                "archive."),

        Scene(
            kind="visual",
            heading="Conformance checked by the standard, not by us",
            lines=["CycloneDX 1.6 and 1.7, validated offline against the "
                   "official JSON Schema at a pinned commit."],
            image=SHOTS / "05-cbom-export.png",
            crop=(0.055, 0.0, 1.0, 0.50),
            say="Output is a Cyclone D X cryptographic bill of materials, "
                "version one point six or one point seven, each validated "
                "offline against its own official JSON schema, vendored at a "
                "pinned commit. Export and validation are the same screen."),

        Scene(
            kind="statement",
            heading="Built, not proposed",
            lines=[
                "664 automated tests  ·  CI on Python 3.11, 3.12 and 3.13",
                "116 hand-labelled benchmark findings across six scanners",
                "7 real detector defects the benchmark found that code review "
                "had missed",
                "",
                "Precision 1.000, recall 1.000 — on a synthetic corpus this "
                "project wrote.",
                "That is not a measurement of real-world enterprise accuracy, "
                "and none is claimed.",
            ],
            say="This is built, not proposed. Six hundred and sixty four "
                "automated tests. A hand labelled benchmark corpus of one "
                "hundred and sixteen findings across six scanners, which "
                "found seven real detector defects that code review had "
                "missed. Precision and recall are both one point zero zero "
                "zero on that corpus. And that is a synthetic corpus this "
                "project wrote. It is not a measurement of real world "
                "enterprise accuracy, and we do not claim one.",
            hold=1.4),

        Scene(
            kind="title",
            heading="CryptoDrishti",
            lines=["One command. No daemon, no agent, no cloud account, "
                   "no network.",
                   "github.com/sgtsujith141-wq/cryptodrishti"],
            footer="Source, 664 tests, the labelled benchmark corpus and its "
                   "committed results, and the vendored schemas.",
            say="Crypto Drishti. One command, no network, no cloud account. "
                "The source, the tests and the benchmark corpus are all in "
                "the repository.",
            hold=1.8),
    ]


# --------------------------------------------------------------------------
# Composition
# --------------------------------------------------------------------------

def wrap(draw, text, fnt, width):
    words, lines, cur = text.split(), [], ""
    for word in words:
        trial = f"{cur} {word}".strip()
        if draw.textlength(trial, font=fnt) <= width:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def prepared(scene: Scene) -> Image.Image | None:
    if scene.image is None:
        return None
    im = Image.open(scene.image).convert("RGB")
    if scene.crop:
        l, t, r, b = scene.crop
        im = im.crop((int(im.width * l), int(im.height * t),
                      int(im.width * r), int(im.height * b)))
    return im


def frame(scene: Scene, source: Image.Image | None, progress: float,
          fade: float) -> Image.Image:
    """One composited frame. `progress` 0..1 through the scene."""
    canvas = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(canvas)

    if scene.kind == "title":
        f_h = font(F_BOLD, 104)
        f_s = font(F_REG, 40)
        f_f = font(F_IT, 25)
        y = 352
        draw.text((160, y), scene.heading, font=f_h, fill=INK)
        y += 150
        draw.line((160, y, 160 + 190, y), fill=RED, width=5)
        y += 46
        for line in scene.lines:
            draw.text((160, y), line, font=f_s, fill=MUTED)
            y += 62
        if scene.footer:
            draw.text((160, H - 132), scene.footer, font=f_f, fill=(96, 102, 112))

    elif scene.kind == "statement":
        f_h = font(F_BOLD, 62)
        f_b = font(F_REG, 37)
        y = 210
        for line in wrap(draw, scene.heading, f_h, W - 320):
            draw.text((160, y), line, font=f_h, fill=INK)
            y += 80
        y += 18
        draw.line((160, y, 160 + 150, y), fill=RED, width=4)
        y += 54
        for line in scene.lines:
            if not line:
                y += 30
                continue
            for part in wrap(draw, line, f_b, W - 320):
                draw.text((160, y), part, font=f_b, fill=MUTED)
                y += 56

    else:  # visual
        f_h = font(F_BOLD, 48)
        f_c = font(F_REG, 28)
        draw.text((110, 74), scene.heading, font=f_h, fill=INK)
        y = 140
        for line in scene.lines:
            for part in wrap(draw, line, f_c, W - 240):
                draw.text((110, y), part, font=f_c, fill=MUTED)
                y += 40
        box_top = y + 34
        box = (110, box_top, W - 110, H - 70)
        bw, bh = box[2] - box[0], box[3] - box[1]

        if source is not None:
            # A slow push in, so the frame is never static but never busy.
            zoom = 1.0 + 0.055 * progress
            sw, sh = source.size
            cw, ch = sw / zoom, sh / zoom
            ox = (sw - cw) * (0.5 + 0.06 * progress)
            oy = (sh - ch) * (0.5 - 0.04 * progress)
            scale = min(bw / cw, bh / ch)
            dw, dh = int(cw * scale), int(ch * scale)
            view = source.resize((dw, dh), Image.LANCZOS,
                                 box=(ox, oy, ox + cw, oy + ch))
            px = box[0] + (bw - dw) // 2
            py = box_top + (bh - dh) // 2
            draw.rectangle((px - 1, py - 1, px + dw, py + dh), outline=RULE)
            canvas.paste(view, (px, py))

    if fade < 1.0:
        canvas = Image.blend(Image.new("RGB", (W, H), (0, 0, 0)), canvas, fade)
    return canvas


# --------------------------------------------------------------------------
# Audio
# --------------------------------------------------------------------------

def narrate(scene: Scene, path: Path) -> float:
    subprocess.run(["say", "-v", VOICE, "-r", str(RATE), "-o", str(path),
                    scene.say], check=True, capture_output=True)
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", str(path)],
        capture_output=True, text=True, check=True)
    return float(probe.stdout.strip())


def main() -> int:
    for tool in ("ffmpeg", "ffprobe", "say"):
        if not shutil.which(tool):
            print(f"{tool} is required and was not found", file=sys.stderr)
            return 1
    plan = scenes()
    missing = [str(s.image) for s in plan
               if s.image is not None and not s.image.is_file()]
    if missing:
        print("missing assets:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="cd-video-") as tmp:
        work = Path(tmp)

        # ---- narration first: the picture is cut to the voice -------------
        durations, clips = [], []
        for i, scene in enumerate(plan):
            aiff = work / f"say-{i}.aiff"
            spoken = narrate(scene, aiff)
            total = spoken + 0.9 + scene.hold          # lead-in + tail
            durations.append(total)
            wav = work / f"aud-{i}.wav"
            subprocess.run(
                ["ffmpeg", "-y", "-v", "error", "-i", str(aiff),
                 "-af", "adelay=700|700,apad", "-t", f"{total:.3f}",
                 "-ar", "48000", "-ac", "2", str(wav)], check=True)
            clips.append(wav)
            print(f"  scene {i + 1}: narration {spoken:5.1f}s  "
                  f"scene {total:5.1f}s")

        listing = work / "audio.txt"
        listing.write_text("".join(f"file '{c}'\n" for c in clips))
        track = work / "audio.wav"
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat",
                        "-safe", "0", "-i", str(listing), "-c", "copy",
                        str(track)], check=True)

        runtime = sum(durations)
        print(f"\n  total runtime {int(runtime // 60)}:{int(runtime % 60):02d}")

        # ---- frames, piped straight into the encoder ----------------------
        OUT.parent.mkdir(parents=True, exist_ok=True)
        encoder = subprocess.Popen(
            ["ffmpeg", "-y", "-v", "error",
             "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
             "-r", str(FPS), "-i", "-",
             "-i", str(track),
             "-c:v", "libx264", "-preset", "medium", "-crf", "20",
             "-pix_fmt", "yuv420p", "-movflags", "+faststart",
             "-c:a", "aac", "-b:a", "160k", "-shortest", str(OUT)],
            stdin=subprocess.PIPE)

        fade_frames = int(FPS * 0.32)
        for scene, seconds in zip(plan, durations):
            source = prepared(scene)
            count = int(seconds * FPS)
            for n in range(count):
                progress = n / max(count - 1, 1)
                fade = min(1.0,
                           (n + 1) / fade_frames,
                           (count - n) / fade_frames)
                encoder.stdin.write(
                    frame(scene, source, progress, fade).tobytes())
        encoder.stdin.close()
        if encoder.wait() != 0:
            print("ffmpeg failed", file=sys.stderr)
            return 1

    size = OUT.stat().st_size
    print(f"\nwritten: {OUT.relative_to(ROOT)}  ({size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
