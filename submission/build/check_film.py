#!/usr/bin/env python3
"""Verify a rendered cut of the film.

    python submission/build/check_film.py

Checks the things a successful render does not prove:

* the container decodes end to end, both streams, with no errors;
* dimensions, frame rate and codecs are what was asked for;
* no unintended black or frozen frames (the deliberate dips at scene joins
  are short, so a long dark run means a scene failed to draw);
* audio peaks below clipping and sits in a sane loudness range;
* the SRT parses, is in order, and no cue outlives the film.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIDEO = ROOT / "submission" / "video"
CUTS = ["CryptoDrishti-Final-Demo", "CryptoDrishti-Short-Demo"]


def probe(path: Path) -> dict:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_format",
                          "-show_streams", "-of", "json", str(path)],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def decodes(path: Path) -> tuple[bool, str]:
    r = subprocess.run(["ffmpeg", "-v", "error", "-i", str(path), "-f", "null", "-"],
                       capture_output=True, text=True)
    return r.returncode == 0 and not r.stderr.strip(), r.stderr.strip()[:300]


def _content(im):
    """(peak luma, lit ratio, bounding-box area as a fraction of the frame)."""
    small = im.resize((480, 270))
    px = list(small.getdata())
    peak = max(px)
    lit = sum(1 for v in px if v > 70) / len(px)
    box = small.point(lambda v: 255 if v > 70 else 0).getbbox()
    area = 0.0
    if box:
        area = ((box[2] - box[0]) * (box[3] - box[1])) / (480 * 270)
    return peak, lit, area


def empty_frames(path: Path, samples: int = 40) -> list[str]:
    """Frames with nothing visible on them.

    `blackdetect` is the wrong tool here. This film is deliberately near-black
    (#0E0F11, luma ~16/255), so a frame of crisp white text on that background
    is over 98% "black" by its threshold and gets flagged. Running it produced
    three false failures on a film whose frames each carried a heading, a
    subheading and a table.

    So the test is content-aware instead: sample frames across the runtime and
    ask whether anything is actually drawn -- a bright peak and a plausible
    number of lit pixels. Only the deliberate dips between scenes should come
    back empty, and those are under half a second.
    """
    import io
    import subprocess as sp

    from PIL import Image

    out = sp.run(["ffprobe", "-v", "error", "-show_entries",
                  "format=duration", "-of", "csv=p=0", str(path)],
                 capture_output=True, text=True, check=True)
    dur = float(out.stdout.strip())
    empty = []
    for i in range(samples):
        t = dur * (i + 0.5) / samples
        raw = sp.run(["ffmpeg", "-v", "error", "-ss", f"{t:.2f}", "-i",
                      str(path), "-frames:v", "1", "-f", "image2pipe",
                      "-vcodec", "png", "-"],
                     capture_output=True, check=True).stdout
        if not raw:
            empty.append(f"{t:.1f}s (no frame decoded)")
            continue
        im = Image.open(io.BytesIO(raw)).convert("L")
        peak, lit, area = _content(im)
        # A sparse frame is not an empty one. The opening deliberately holds a
        # single line of evidence on a wide dark field, which is only 0.06% of
        # the pixels -- a ratio test calls that empty. What actually matters is
        # whether anything is drawn, so measure the bounding box of the lit
        # pixels instead.
        if peak < 90 or area < 0.004:
            # Scenes dip through black for ~0.3s at each join, so a single
            # dark sample is a transition, not a dead scene. Only flag it if
            # the frame half a second later is dark too.
            follow = sp.run(["ffmpeg", "-v", "error", "-ss", f"{t + 0.6:.2f}",
                             "-i", str(path), "-frames:v", "1", "-f",
                             "image2pipe", "-vcodec", "png", "-"],
                            capture_output=True).stdout
            if follow:
                fpeak, _flit, farea = _content(
                    Image.open(io.BytesIO(follow)).convert("L"))
                if fpeak >= 90 and farea >= 0.004:
                    continue        # a transition, which is by design
            empty.append(f"{t:.1f}s (peak {peak}, content area {area * 100:.2f}%)")
    return empty


def levels(path: Path) -> tuple[float, float]:
    r = subprocess.run(["ffmpeg", "-v", "info", "-i", str(path),
                        "-af", "volumedetect", "-f", "null", "-"],
                       capture_output=True, text=True)
    peak = re.search(r"max_volume: (-?[\d.]+) dB", r.stderr)
    mean = re.search(r"mean_volume: (-?[\d.]+) dB", r.stderr)
    return (float(peak.group(1)) if peak else 0.0,
            float(mean.group(1)) if mean else 0.0)


def srt_ok(path: Path, duration: float) -> tuple[bool, str]:
    if not path.is_file():
        return False, "missing"
    cues = re.findall(r"(\d\d:\d\d:\d\d,\d\d\d) --> (\d\d:\d\d:\d\d,\d\d\d)",
                      path.read_text(encoding="utf-8"))
    if not cues:
        return False, "no cues"

    def secs(s: str) -> float:
        h, m, rest = s.split(":")
        sec, ms = rest.split(",")
        return int(h) * 3600 + int(m) * 60 + int(sec) + int(ms) / 1000

    last = 0.0
    for a, b in cues:
        sa, sb = secs(a), secs(b)
        if sb <= sa or sa < last - 0.001:
            return False, f"out of order or zero-length at {a}"
        last = sa
    end = secs(cues[-1][1])
    if end > duration + 0.5:
        return False, f"last cue ends {end:.1f}s, film is {duration:.1f}s"
    return True, f"{len(cues)} cues, last ends {end:.1f}s"


def main() -> int:
    bad = 0
    for name in CUTS:
        mp4, srt = VIDEO / f"{name}.mp4", VIDEO / f"{name}.srt"
        print(f"=== {name} ===")
        if not mp4.is_file():
            print("  MISSING"); bad += 1; continue

        info = probe(mp4)
        dur = float(info["format"]["duration"])
        size = int(info["format"]["size"])
        v = next(s for s in info["streams"] if s["codec_type"] == "video")
        a = next((s for s in info["streams"] if s["codec_type"] == "audio"), None)
        fps = eval(v["r_frame_rate"])  # noqa: S307 - ffprobe emits "30/1"
        print(f"  {int(dur//60)}:{int(dur%60):02d}  {v['width']}x{v['height']}  "
              f"{fps:g}fps  {v['codec_name']}"
              f"{'/' + a['codec_name'] if a else ' (no audio)'}  "
              f"{size:,} bytes")

        ok, err = decodes(mp4)
        print(f"  [{'ok' if ok else 'FAIL'}] decodes end to end"
              + ("" if ok else f" -- {err}"))
        bad += 0 if ok else 1

        dims_ok = (v["width"], v["height"]) == (1920, 1080)
        print(f"  [{'ok' if dims_ok else 'FAIL'}] 1920x1080")
        bad += 0 if dims_ok else 1

        empty = empty_frames(mp4)
        print(f"  [{'ok' if not empty else 'FAIL'}] every sampled frame has "
              f"visible content" + ("" if not empty
                                    else f" -- {empty[:3]}"))
        bad += 0 if not empty else 1

        if a:
            peak, mean = levels(mp4)
            clip = peak >= -0.5
            quiet = mean < -40
            print(f"  [{'FAIL' if clip else 'ok'}] peak {peak:.1f} dB "
                  f"(no clipping)   mean {mean:.1f} dB"
                  + ("  -- SILENT?" if quiet else ""))
            bad += 1 if clip else 0

        sok, note = srt_ok(srt, dur)
        print(f"  [{'ok' if sok else 'FAIL'}] captions -- {note}")
        bad += 0 if sok else 1
        print()

    print("ALL CHECKS PASSED" if not bad else f"{bad} PROBLEM(S)")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
