#!/usr/bin/env python3
"""Render the CryptoDrishti demonstration film.

    python submission/build/make_film.py            # both cuts
    python submission/build/make_film.py --short    # short cut only

Scenes are authored as HTML (`film_scenes.py`) and driven by a deterministic
`seek(t)` in the page: every animated element declares when it enters and how
long it takes, and the engine positions it for an exact millisecond. Nothing
depends on wall-clock timing, so a render is reproducible frame for frame.

Frames are screenshotted from headless Chromium and piped straight into
ffmpeg. No intermediate image files are written.

Narration is generated locally with macOS `say`, and each scene is held for at
least as long as its own line takes to speak -- the picture is cut to the
voice, not the other way round. The film is designed to work with the sound
off; captions carry the argument and an SRT is written alongside.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import design as D          # noqa: E402
import film_scenes as F     # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "submission" / "video"

W, H = 1920, 1080
FPS = 30
VOICE = "Rishi"       # en_IN: the submission's own accent, and not the
RATE = 166            # rejected en_GB voice from the previous cut
LEAD = 0.55           # silence before a line starts
TAIL = 1.30           # silence after it ends, to let a frame settle

ENGINE = """
function ease(p){ return p<=0?0:p>=1?1:1-Math.pow(1-p,3); }
function seek(t){
  document.querySelectorAll('[data-in]').forEach(el=>{
    const tin=+el.dataset.in, dur=+(el.dataset.dur||600);
    const p=ease((t-tin)/dur);
    el.style.opacity=p;
    const y=+(el.dataset.y||0), s=el.dataset.scale?+el.dataset.scale:null;
    let tr='';
    if(y) tr+=`translateY(${(1-p)*y}px) `;
    if(s) tr+=`scale(${1+(s-1)*p}) `;
    if(tr) el.style.transform=tr.trim();
  });
  document.querySelectorAll('[data-grow]').forEach(el=>{
    const tin=+el.dataset.in, dur=+(el.dataset.dur||600);
    el.style.width=(ease((t-tin)/dur)*(+el.dataset.grow))+'px';
    el.style.opacity=1;
  });
}
window.seek=seek; seek(0);
"""


def scene_page(body: str, css: str) -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
{D.BASE_CSS}
html,body{{width:{W}px;height:{H}px;overflow:hidden;background:{D.PAPER};}}
body{{position:relative;}}
{css}
</style></head><body>{body}<script>{ENGINE}</script></body></html>"""


def narrate(text: str, path: Path) -> float:
    subprocess.run(["say", "-v", VOICE, "-r", str(RATE), "-o", str(path), text],
                   check=True, capture_output=True)
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                          "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True)
    return float(out.stdout.strip())


def srt_time(sec: float) -> str:
    ms = int(round(sec * 1000))
    h, ms = divmod(ms, 3600000)
    m, ms = divmod(ms, 60000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def caption_lines(say: str) -> list[str]:
    """Split narration into caption-sized chunks on sentence boundaries."""
    parts = re.split(r"(?<=[.?])\s+", say.strip())
    out, cur = [], ""
    for part in parts:
        if len(cur) + len(part) < 96:
            cur = f"{cur} {part}".strip()
        else:
            if cur:
                out.append(cur)
            cur = part
    if cur:
        out.append(cur)
    return out


def build(cut: str) -> int:
    scenes = list(F.SCENES)
    if cut == "short":
        by_id = {s["id"]: s for s in F.SCENES}
        scenes = []
        for sid in F.SHORT_IDS:
            s = dict(by_id[sid])
            s.update(F.SHORT_SAY[sid])          # its own say + cap
            # The short cut moves faster: hold only as long as the line needs.
            s["beats"] = min(s["beats"], 11500)
            scenes.append(s)

    name = ("CryptoDrishti-Short-Demo" if cut == "short"
            else "CryptoDrishti-Final-Demo")
    mp4 = OUTDIR / f"{name}.mp4"
    srt = OUTDIR / f"{name}.srt"
    OUTDIR.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright

    with tempfile.TemporaryDirectory(prefix="cd-film-") as tmp:
        work = Path(tmp)

        # ---- narration, and the durations it dictates --------------------
        plan, clips = [], []
        for i, sc in enumerate(scenes):
            aiff = work / f"say-{i}.aiff"
            spoken = narrate(sc["say"], aiff)
            body, css, choreo = sc["build"]()
            # The scene is held for whichever is longer: the choreography it
            # needs, or the line it has to say.
            seconds = max(sc["beats"] / 1000.0 + 0.6, LEAD + spoken + TAIL)
            plan.append((sc, body, css, seconds, spoken, choreo))
            wav = work / f"aud-{i}.wav"
            subprocess.run(
                ["ffmpeg", "-y", "-v", "error", "-i", str(aiff),
                 "-af", f"adelay={int(LEAD*1000)}|{int(LEAD*1000)},apad,"
                        "loudnorm=I=-18:TP=-2.0:LRA=9",
                 "-t", f"{seconds:.3f}", "-ar", "48000", "-ac", "2", str(wav)],
                check=True)
            clips.append(wav)
            print(f"  {sc['id']:10s} speech {spoken:5.1f}s  scene {seconds:5.1f}s")

        listing = work / "a.txt"
        listing.write_text("".join(f"file '{c}'\n" for c in clips))
        track = work / "audio.wav"
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat",
                        "-safe", "0", "-i", str(listing), "-c", "copy",
                        str(track)], check=True)

        # ---- captions ----------------------------------------------------
        blocks, n, clock = [], 1, 0.0
        for sc, _b, _c, seconds, spoken, _ch in plan:
            lines = caption_lines(sc["cap"])
            if lines:
                span = spoken / len(lines)
                for j, line in enumerate(lines):
                    a = clock + LEAD + j * span
                    blocks.append(f"{n}\n{srt_time(a)} --> "
                                  f"{srt_time(a + span)}\n{line}\n")
                    n += 1
            clock += seconds
        srt.write_text("\n".join(blocks), encoding="utf-8")

        total = sum(p[3] for p in plan)
        print(f"\n  runtime {int(total//60)}:{int(total%60):02d}"
              f"  ({len(plan)} scenes)")

        # ---- frames ------------------------------------------------------
        enc = subprocess.Popen(
            ["ffmpeg", "-y", "-v", "error",
             "-f", "image2pipe", "-vcodec", "png", "-r", str(FPS), "-i", "-",
             "-i", str(track),
             "-c:v", "libx264", "-preset", "medium", "-crf", "19",
             "-pix_fmt", "yuv420p", "-movflags", "+faststart",
             "-c:a", "aac", "-b:a", "160k", "-shortest", str(mp4)],
            stdin=subprocess.PIPE)

        fade = int(FPS * 0.30)
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": W, "height": H})
            for sc, body, css, seconds, _sp, choreo in plan:
                page.set_content(scene_page(body, css), wait_until="load")
                page.wait_for_timeout(120)
                count = int(seconds * FPS)
                # Map frame time onto choreography time so the reveals always
                # finish with the last 15% of the scene left to hold -- whether
                # that means stretching them across a long narration line or
                # compressing them for the short cut. Truncating instead would
                # cut a reveal off mid-way.
                usable = max(1.0, seconds * 1000.0 * 0.85)
                for k in range(count):
                    t_ms = k / FPS * 1000.0
                    page.evaluate("t => window.seek(t)",
                                  int(min(choreo, t_ms * choreo / usable)))
                    # Dip through black at the joins: on a near-black film this
                    # reads as a soft dissolve rather than a cut to nowhere.
                    o = min(1.0, (k + 1) / fade, (count - k) / fade)
                    page.evaluate("o => document.body.style.filter = "
                                  "`brightness(${o})`", round(o, 4))
                    enc.stdin.write(page.screenshot(type="png"))
            browser.close()
        enc.stdin.close()
        if enc.wait() != 0:
            print("ffmpeg failed", file=sys.stderr)
            return 1

    print(f"  written: {mp4.relative_to(ROOT)} "
          f"({mp4.stat().st_size:,} bytes)")
    print(f"  captions: {srt.relative_to(ROOT)}")
    return 0


def main() -> int:
    for tool in ("ffmpeg", "ffprobe", "say"):
        if not shutil.which(tool):
            print(f"{tool} not found", file=sys.stderr)
            return 1
    ap = argparse.ArgumentParser()
    ap.add_argument("--short", action="store_true")
    ap.add_argument("--full", action="store_true")
    args = ap.parse_args()
    cuts = []
    if args.short:
        cuts = ["short"]
    elif args.full:
        cuts = ["full"]
    else:
        cuts = ["full", "short"]
    for cut in cuts:
        print(f"=== {cut} cut ===")
        rc = build(cut)
        if rc:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
