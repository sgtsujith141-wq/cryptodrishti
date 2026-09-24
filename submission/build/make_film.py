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

The film has two possible soundtracks, and it picks the honest one rather
than the convenient one.

*Voiced* uses the neural voice pinned by the team's other submission, via the
authenticated ElevenLabs CLI. Each scene is then held for at least as long as
its own line takes to speak -- the picture is cut to the voice.

*Caption-led* is what you get when that voice is genuinely unavailable: no
narration at all, captions burned into the picture, and each scene held for as
long as its captions take to read. It is not a downgrade dressed up as a
choice -- the alternative is the operating system's `say`, which sounds like a
robot reading a script, and a robot reading a script is worse than silence.

The mode is chosen by a quota preflight, not by hope: the script asks how many
characters the account has left before it spends any, and prints which cut it
is building and why.
"""

from __future__ import annotations

import argparse
import re
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import design as D          # noqa: E402
import film_scenes as F     # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "submission" / "video"

W, H = 1920, 1080
FPS = 30
# The narration voice, used only when `--voice` is passed and the quota
# preflight clears: the same neural voice and settings the team's other
# submission pinned, via the authenticated ElevenLabs CLI. The voice id and
# parameters are read from that project rather than guessed, so the two films
# would sound like they came from the same team. That project is never
# written to.
SMS_NARRATION = Path("/Volumes/Volume/Projects/SecureMailScope/"
                     "submission/demo/narration-script.json")
LEAD = 0.55           # silence before a line starts
TAIL = 1.30           # silence after it ends, to let a frame settle

# Caption-led timing. 14 characters a second is a comfortable subtitle reading
# rate -- slower than the 17 a streaming service will push, because these
# captions carry an argument rather than dialogue the picture already explains.
CAPTION_CPS = 14.0
CAPTION_MIN = 2.4     # no caption is allowed to flash past faster than this
CAPTION_PAD = 0.45    # a held beat after the last caption of a scene
CAPTION_FADE = 0.26
CAPTION_WIDTH = 68    # characters: two lines on screen, no more

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
  if (window.seekExtra) window.seekExtra(t);   // scene-owned motion: the camera
}
window.seek=seek; seek(0);
window.caption=function(text,opacity){
  const el=document.getElementById('cd-cap-txt');
  if(!el) return;
  if(el.textContent!==text) el.textContent=text;
  el.style.opacity=opacity;
};
"""

# The burned-in caption gets a reserved band at the foot of the frame rather
# than an overlay. Several scenes anchor content to the bottom -- a product
# capture runs to 6% from the edge, and two scenes place a line lower still --
# so a caption floated over the picture would sit on top of them. Instead the
# whole scene is scaled to the picture area above the band. Because the scene
# background and the page background are the same near-black, the reclaimed
# margin is invisible: the composition simply reads as having more air.
CAPTION_ZONE = 150                                   # px reserved at the foot
STAGE_SCALE = (H - CAPTION_ZONE) / H

CAPTION_CSS = f"""
#cd-stage{{position:absolute;left:0;top:0;width:{W}px;height:{H}px;
  transform:scale({STAGE_SCALE:.5f});transform-origin:50% 0;}}
#cd-cap{{position:absolute;left:0;right:0;bottom:0;height:{CAPTION_ZONE}px;
  z-index:99;display:flex;align-items:center;justify-content:center;
  padding:0 180px;box-sizing:border-box;pointer-events:none;}}
#cd-cap-txt{{font-family:{D.SANS};font-size:31px;line-height:1.44;
  font-weight:450;color:{D.INK};text-align:center;max-width:1400px;
  letter-spacing:0.004em;opacity:0;}}
"""


def scene_page(body: str, css: str, captions: bool = False) -> str:
    if captions:
        body = (f'<div id="cd-stage">{body}</div>'
                '<div id="cd-cap"><div id="cd-cap-txt"></div></div>')
    # `set_content` rewrites the document but keeps the window, so a camera
    # hook left by the previous scene would otherwise run against this one.
    return f"""<!doctype html><html><head><meta charset="utf-8">
<script>window.seekExtra = null;</script><style>
{D.BASE_CSS}
html,body{{width:{W}px;height:{H}px;overflow:hidden;background:{D.PAPER};}}
body{{position:relative;}}
{css}
{CAPTION_CSS if captions else ""}
</style></head><body>{body}<script>{ENGINE}</script></body></html>"""


def _elevenlabs_binary() -> str | None:
    binary = shutil.which("elevenlabs")
    if binary is None:
        # A background shell may not inherit the npm global bin directory.
        for candidate in (Path.home() / ".npm-global/bin/elevenlabs",
                          Path("/usr/local/bin/elevenlabs"),
                          Path("/opt/homebrew/bin/elevenlabs")):
            if candidate.is_file():
                return str(candidate)
    return binary


def _quota_remaining(binary: str) -> int | None:
    """Characters left on the account, or None if it cannot be determined."""
    result = subprocess.run(
        [binary, "user", "subscription", "get",
         "--intent", "check remaining character quota before rendering a "
                     "product demonstration narration"],
        capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        d = json.loads(result.stdout)
        return int(d["character_limit"]) - int(d["character_count"])
    except (KeyError, ValueError, TypeError):
        return None


def voice_config(needed: int) -> dict | None:
    """The pinned neural voice, or None with the reason printed.

    The check is made before a single character is spent. A half-narrated film
    is worse than a caption-led one, because the failure shows up as the voice
    vanishing in the middle of a sentence.
    """
    binary = _elevenlabs_binary()
    if binary is None:
        print("  no elevenlabs CLI on PATH")
        return None
    if not SMS_NARRATION.is_file():
        print(f"  no pinned voice at {SMS_NARRATION}")
        return None
    try:
        d = json.loads(SMS_NARRATION.read_text())
        cfg = {"binary": binary, "voice_id": d["voice_id"],
               "model": d["model"], "settings": d["settings"]}
    except (KeyError, ValueError):
        print(f"  pinned voice file at {SMS_NARRATION} is unreadable")
        return None
    left = _quota_remaining(binary)
    if left is None:
        print("  could not read the account quota")
        return None
    if left < needed:
        print(f"  neural voice needs {needed:,} characters, "
              f"the account has {left:,} left")
        return None
    print(f"  quota: {left:,} characters available, {needed:,} needed")
    return cfg


class NarrationFailed(RuntimeError):
    """The neural voice failed part-way through. Never degrade silently."""


def narrate(text: str, path: Path, cfg: dict) -> float:
    """Render one line with the pinned voice. Returns its duration."""
    params = json.dumps({"voice_id": cfg["voice_id"],
                         "output_format": "mp3_44100_128"})
    body = json.dumps({"text": text, "model_id": cfg["model"],
                       "voice_settings": cfg["settings"]})
    for attempt in range(3):
        result = subprocess.run(
            [cfg["binary"], "text-to-speech", "convert",
             "--params", params, "--json", body, "-o", str(path),
             "--intent", "generate narration for a hackathon product "
                         "demonstration video"],
            capture_output=True, text=True)
        if result.returncode == 0 and path.is_file() and path.stat().st_size:
            break
        # Rate limits are the likely cause of a transient failure, so back off
        # before giving up on the line.
        if attempt < 2:
            time.sleep(3 * (attempt + 1))
    else:
        detail = (result.stderr.strip() or result.stdout.strip()
                  or f"exit {result.returncode}")
        raise NarrationFailed(detail[:400])
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


def _wrap(text: str, limit: int) -> list[str]:
    """Break a run of words into balanced pieces, none longer than `limit`.

    Balanced rather than greedy: filling each line to the brim and letting the
    remainder fall off the end is what produces a caption reading `commit.`
    on its own, which looks like a mistake on screen.
    """
    if len(text) <= limit:
        return [text]
    words = text.split()
    pieces = -(-len(text) // limit)
    target = len(text) / pieces
    out, cur = [], ""
    for word in words:
        too_long = cur and len(cur) + 1 + len(word) > limit
        full_enough = cur and len(cur) >= target and len(out) < pieces - 1
        if too_long or full_enough:
            out.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}".strip()
    if cur:
        out.append(cur)
    return out


def caption_lines(say: str, limit: int = 96) -> list[str]:
    """Split narration into caption-sized chunks.

    Sentence boundaries first, because that is where a reader already pauses;
    then the sentence's own clause punctuation; then balanced word wrapping.
    A final pass folds away any stub too short to be worth a caption of its
    own -- a two-word flash reads as a glitch rather than as emphasis.
    """
    def clauses(text: str) -> list[str]:
        if len(text) <= limit:
            return [text]
        parts, cur = [], ""
        for piece in re.split(r"(?<=[,;:])\s+|\s+(?=--\s)|\s+(?=\u2014\s)",
                              text):
            if cur and len(cur) + 1 + len(piece) > limit:
                parts.append(cur)
                cur = piece
            else:
                cur = f"{cur} {piece}".strip()
        if cur:
            parts.append(cur)
        return [w for part in parts for w in _wrap(part, limit)]

    chunks, cur = [], ""
    for sentence in re.split(r"(?<=[.?!])\s+", say.strip()):
        if cur and len(cur) + 1 + len(sentence) <= limit:
            cur = f"{cur} {sentence}".strip()
            continue
        if cur:
            chunks.extend(clauses(cur))
        cur = sentence
    if cur:
        chunks.extend(clauses(cur))

    merged: list[str] = []
    for chunk in chunks:
        if (merged and (len(chunk) < 26 or len(merged[-1]) < 26)
                and len(merged[-1]) + 1 + len(chunk) <= limit + 14):
            merged[-1] = f"{merged[-1]} {chunk}"
        else:
            merged.append(chunk)
    return [c for c in merged if c]


def _words(text: str) -> list[str]:
    return re.sub(r"[^a-z0-9 ]", " ", text.lower()).split()


def screen_text(scenes: list[dict]) -> list[str]:
    """What each scene already says in its own typography."""
    from playwright.sync_api import sync_playwright        # noqa: PLC0415
    out = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": W, "height": H})
        for sc in scenes:
            body, css, _choreo = sc["build"]()
            page.set_content(scene_page(body, css), wait_until="load")
            out.append(" ".join(
                _words(page.evaluate("document.body.innerText"))))
        browser.close()
    return out


def already_shown(caption: str, screen: str) -> bool:
    """True when the scene already typesets this caption's substance.

    Several scenes land their point in large type -- the RSA sequence ends on
    `Purpose decides the migration.` set across the frame. Burning the same
    sentence into the caption band underneath it says the same thing twice in
    two sizes, which reads as a mistake. Where the scene already carries the
    line, the band stays empty and lets the better typography do the work.
    """
    words = _words(caption)
    if len(words) < 4:
        return False
    for n in range(len(words), 3, -1):
        if any(" ".join(words[i:i + n]) in screen
               for i in range(len(words) - n + 1)):
            return n / len(words) >= 0.8
    return False


def caption_plan(cap: str) -> list[tuple[str, float]]:
    """Caption chunks paired with the time each one needs to be read."""
    return [(line, max(CAPTION_MIN, len(line) / CAPTION_CPS + 0.6))
            for line in caption_lines(cap, CAPTION_WIDTH)]


def build(cut: str, voiced: bool) -> int:
    # The short cut is its own edit (`F.SHORT`), not the long one trimmed.
    scenes = list(F.SHORT if cut == "short" else F.SCENES)

    name = ("CryptoDrishti-Short-Demo" if cut == "short"
            else "CryptoDrishti-Final-Demo")
    mp4 = OUTDIR / f"{name}.mp4"
    srt = OUTDIR / f"{name}.srt"
    OUTDIR.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright

    with tempfile.TemporaryDirectory(prefix="cd-film-") as tmp:
        work = Path(tmp)

        cfg = voice_config(sum(len(sc["say"]) for sc in scenes)) if voiced \
            else None
        if cfg is None:
            print("  building the caption-led cut: no narration track, "
                  "captions burned into the picture")
        else:
            print(f"  building the voiced cut: {cfg['voice_id']}")

        # ---- timing, and the narration that may dictate it ---------------
        # `timed` drives the burned-in band, `cues` the sidecar SRT. They are
        # the same list except where the scene already says the line itself:
        # the band then stays empty, while the SRT keeps every line so the
        # transcript stays complete.
        shown = screen_text(scenes) if cfg is None else [""] * len(scenes)
        plan, clips = [], []
        for i, sc in enumerate(scenes):
            body, css, choreo = sc["build"]()
            chunks = caption_plan(sc["cap"])
            floor = sc["beats"] / 1000.0 + 0.6

            if cfg is not None:
                mp3 = work / f"say-{i}.mp3"
                try:
                    spoken = narrate(sc["say"], mp3, cfg)
                except NarrationFailed as exc:
                    print(f"\n  the neural voice failed on scene "
                          f"'{sc['id']}': {exc}", file=sys.stderr)
                    return 2        # tells main() to fall back, once
                seconds = max(floor, LEAD + spoken + TAIL)
                span = spoken / max(1, len(chunks))
                timed = [(text, LEAD + j * span, span)
                         for j, (text, _d) in enumerate(chunks)]
                wav = work / f"aud-{i}.wav"
                subprocess.run(
                    ["ffmpeg", "-y", "-v", "error", "-i", str(mp3),
                     "-af", f"adelay={int(LEAD*1000)}|{int(LEAD*1000)},apad,"
                            "loudnorm=I=-18:TP=-2.0:LRA=9",
                     "-t", f"{seconds:.3f}", "-ar", "48000", "-ac", "2",
                     str(wav)], check=True)
                clips.append(wav)
                print(f"  {sc['id']:10s} speech {spoken:5.1f}s  "
                      f"scene {seconds:5.1f}s")
            else:
                read = sum(d for _t, d in chunks)
                seconds = max(floor, read + CAPTION_PAD)
                # Where the choreography outlasts the reading, the captions
                # stretch to fill it rather than finishing early and leaving
                # the viewer staring at a held frame with nothing to read.
                head = 0.30
                scale = ((seconds - head - CAPTION_PAD) / read) if read else 1
                timed, clock = [], head
                for text, d in chunks:
                    timed.append((text, clock, d * scale))
                    clock += d * scale
                dupes = sum(1 for t, _a, _d in timed
                            if already_shown(t, shown[i]))
                print(f"  {sc['id']:10s} read   {read:5.1f}s  "
                      f"scene {seconds:5.1f}s  ({len(chunks)} captions"
                      + (f", {dupes} already on screen)" if dupes else ")"))

            cues = list(timed)
            if cfg is None:
                timed = [c for c in timed if not already_shown(c[0], shown[i])]
            plan.append((sc, body, css, seconds, timed, cues, choreo))

        total = sum(pl[3] for pl in plan)

        # ---- soundtrack --------------------------------------------------
        track = work / "audio.wav"
        if cfg is not None:
            listing = work / "a.txt"
            listing.write_text("".join(f"file '{c}'\n" for c in clips))
            subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat",
                            "-safe", "0", "-i", str(listing), "-c", "copy",
                            str(track)], check=True)
        else:
            # A silent stereo track, so the file is a well-formed A/V
            # container everywhere rather than a video-only stream that some
            # players and uploaders handle badly.
            subprocess.run(
                ["ffmpeg", "-y", "-v", "error", "-f", "lavfi",
                 "-i", "anullsrc=r=48000:cl=stereo",
                 "-t", f"{total + 0.5:.3f}", str(track)], check=True)

        # ---- captions ----------------------------------------------------
        blocks, n, clock = [], 1, 0.0
        for _sc, _b, _c, seconds, _timed, cues, _ch in plan:
            for text, at, dur in cues:
                blocks.append(f"{n}\n{srt_time(clock + at)} --> "
                              f"{srt_time(clock + at + dur)}\n{text}\n")
                n += 1
            clock += seconds
        srt.write_text("\n".join(blocks), encoding="utf-8")

        print(f"\n  runtime {int(total//60)}:{int(total%60):02d}"
              f"  ({len(plan)} scenes, {n - 1} captions)")

        # ---- frames ------------------------------------------------------
        enc = subprocess.Popen(
            ["ffmpeg", "-y", "-v", "error",
             "-f", "image2pipe", "-vcodec", "png", "-r", str(FPS), "-i", "-",
             "-i", str(track),
             "-c:v", "libx264", "-preset", "medium", "-crf", "19",
             "-pix_fmt", "yuv420p", "-movflags", "+faststart",
             "-c:a", "aac", "-b:a", "160k", "-shortest", str(mp4)],
            stdin=subprocess.PIPE)

        burn = cfg is None
        fade = int(FPS * 0.30)
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": W, "height": H})
            for sc, body, css, seconds, timed, _cues, choreo in plan:
                page.set_content(scene_page(body, css, captions=burn),
                                 wait_until="load")
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
                    if burn:
                        now, text, op = k / FPS, "", 0.0
                        for line, at, dur in timed:
                            if at <= now <= at + dur:
                                text = line
                                op = min(1.0, (now - at) / CAPTION_FADE,
                                         (at + dur - now) / CAPTION_FADE)
                                break
                        page.evaluate("a => window.caption(a[0], a[1])",
                                      [text, round(max(0.0, op), 3)])
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

    sound = "narrated" if cfg is not None else "caption-led, silent"
    print(f"  written: {mp4.relative_to(ROOT)} "
          f"({mp4.stat().st_size:,} bytes)  {sound}")
    print(f"  captions: {srt.relative_to(ROOT)}")
    return 0


def main() -> int:
    for tool in ("ffmpeg", "ffprobe"):
        if not shutil.which(tool):
            print(f"{tool} not found", file=sys.stderr)
            return 1
    ap = argparse.ArgumentParser()
    ap.add_argument("--short", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--voice", action="store_true",
                    help="attempt the pinned neural voice; without it the "
                         "caption-led cut is built directly")
    args = ap.parse_args()
    if args.short:
        cuts = ["short"]
    elif args.full:
        cuts = ["full"]
    else:
        cuts = ["full", "short"]
    for cut in cuts:
        print(f"=== {cut} cut ===")
        rc = build(cut, voiced=args.voice)
        if rc == 2:
            # The voice died part-way. Build the cut that does not need it
            # rather than shipping half a narration.
            print("  rebuilding this cut caption-led", file=sys.stderr)
            rc = build(cut, voiced=False)
        if rc:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
