# Demonstration video

> **A video file exists:** `submission/CryptoDrishti-SIH26164-Demo.mp4`.
>
> It is an **assembled product overview**, not a screen recording. Every
> visual in it is a still capture of the running application, or the
> architecture diagram rendered from its source, given slow motion and cut
> together with synthesised narration. No cursor is animated, no interaction
> is simulated, and nothing appears on screen that the tool did not actually
> produce. Nobody has been filmed and no microphone was used.
>
> If you want a hand-recorded live walkthrough instead, the shot list and
> narration below are written to be performed; that has **not** been done.

## How the file is produced

```bash
python run.py --demo                                   # real data
python run.py --port 8140 &                            # serve it
python submission/build/capture_screens.py --port 8140 # dark-theme captures
python submission/build/make_video.py                  # assemble
```

Everything runs locally:

* **Narration** — macOS `say`, one clip per scene. The picture is cut to the
  voice: each scene's length is measured from its own audio with `ffprobe`,
  so the timing cannot drift out of sync.
* **Frames** — composited with Pillow at 1920×1080 and piped straight into
  `ffmpeg`. No intermediate PNGs are written to disk.
* **Motion** — a slow push-in on each still. It is there so the frame is never
  static, not to imply the interface is doing something.
* **Encoding** — H.264 / AAC, `yuv420p`, `+faststart`.

The narration script and the on-screen text both live in
`submission/build/make_video.py`, in the `scenes()` function. That is the one
place to edit them; the file is regenerated from it.

## Scene list

| # | Scene | Visual |
|---|---|---|
| 1 | Title — what this is, and that it is assembled from real captures | — |
| 2 | Migration is an inventory problem first | — |
| 3 | Seven sensors, one inventory | inventory |
| 4 | The architecture | architecture diagram |
| 5 | One algorithm, three different answers | inventory, top rows |
| 6 | Evidence, and the arithmetic behind the score | evidence drawer |
| 7 | Two things it refuses to do | assessment, with the partial-scan warning |
| 8 | Conformance checked by the standard, not by us | CBOM export |
| 9 | Built, not proposed — the numbers, with their caveat | — |
| 10 | Close | — |

## What the narration may not say

The same rules as the live script, and they matter more here because a
recording is quotable and cannot be qualified afterwards:

* no national or regulatory deadline;
* no date by which a quantum computer will arrive;
* no claim about what a named competing product can or cannot do;
* no accuracy figure without the sentence saying it measures a synthetic
  corpus this project wrote;
* no price, cost, latency or market-size figure.

Scene 9 states the benchmark result and its caveat in the same breath, on
screen and in the narration, because that is the one number most likely to be
repeated out of context.

## If you would rather perform it live

Use `presenter/script.md`, which is the timed eight-minute version with every
click named and a fallback for each thing that can break on stage. The scene
order above maps onto it directly.
