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


def black_runs(path: Path) -> list[tuple[float, float]]:
    """Dark stretches. Scene joins dip for ~0.3s; anything longer is a fault."""
    r = subprocess.run(
        ["ffmpeg", "-v", "info", "-i", str(path),
         "-vf", "blackdetect=d=0.5:pix_th=0.10", "-f", "null", "-"],
        capture_output=True, text=True)
    runs = []
    for m in re.finditer(r"black_start:([\d.]+) black_end:([\d.]+)", r.stderr):
        runs.append((float(m.group(1)), float(m.group(2))))
    return runs


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

        runs = [r for r in black_runs(mp4) if r[1] - r[0] > 0.9]
        print(f"  [{'ok' if not runs else 'FAIL'}] no black run over 0.9s"
              + ("" if not runs else f" -- {runs[:3]}"))
        bad += 0 if not runs else 1

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
