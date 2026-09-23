# The demonstration film

> **Concept:** *The cryptography you cannot see.*
>
> Two cuts exist, both built by `submission/build/make_film.py`:
>
> | Cut | Path | Length |
> |---|---|---|
> | Full | `submission/video/CryptoDrishti-Final-Demo.mp4` | ~3:55 |
> | Short | `submission/video/CryptoDrishti-Short-Demo.mp4` | ~1:19 |
>
> Both are **assembled product films**, not screen recordings. Real captures
> of the running tool are intercut with motion-designed scenes built from real
> scan output. No cursor is animated, no interaction is simulated, and no
> value appears on screen that the application did not produce.

## What replaced the previous version

The earlier video was a slideshow: screenshots with a slow zoom, cut to
narration. It had no concept, so every scene looked like the one before it.

This one is built around a single idea — **fragmented evidence becomes one
explainable inventory** — and the film's centre of gravity is the moment that
idea becomes concrete: one algorithm, three different migration decisions.

* **Act I** opens on real cryptographic evidence scattered across the frame,
  each fragment labelled with the file it came from. No stock imagery, no
  padlocks, no particles.
* **Act III** is the signature sequence. Three RSA findings assemble one at a
  time — evidence, then resolved purpose, then target — and the third one
  deliberately produces no target at all.
* **Act V** is about what the tool *did not* see: a key deleted by a later
  container layer, and a scan marked PARTIAL because an endpoint was refused.

## How it is built

```bash
python run.py --demo                                    # real data
python run.py --port 8140 &
python submission/build/capture_screens.py --port 8140  # dark-theme captures
python submission/build/make_film.py                    # both cuts + SRT
python submission/build/make_film.py --short            # short cut only
```

Scenes are authored as HTML in `submission/build/film_scenes.py` and driven by
a deterministic `seek(t)` in the page: each element declares when it enters and
how long it takes, so a render is reproducible frame for frame. Frames are
screenshotted from headless Chromium and piped straight into ffmpeg — no
intermediate images are written.

Choreography is mapped onto scene length rather than truncated, which is how
the short cut re-times the same scenes instead of cutting them off mid-reveal.

## Narration and captions — and one thing I could not check

**The film is designed caption-first.** Every scene carries its argument in
typeset on-screen text and is meant to work with the sound off. An SRT sits
beside each cut, and captions are written separately from the narration
(`cap` versus `say` in `film_scenes.py`) so a viewer reads *CryptoDrishti*,
*RSA* and *ML-DSA-65* while the synthesiser is handed *Crypto Drishti*,
*R S A* and *M L D S A sixty five*.

Narration is generated locally with macOS `say` (voice **Rishi**, en-IN),
loudness-normalised to -18 LUFS with a -2 dBTP ceiling, and the picture is cut
to the voice — each scene is held at least as long as its own line takes to
speak.

**What has been verified about the audio:** that both streams decode, that the
peak sits below clipping, that the mean level is in a sane range, that every
caption cue is ordered and none outlives the film, and that the technical
terms are spelled phonetically for the synthesiser.

**What has not been verified:** how it *sounds*. Judging whether a synthetic
voice reads as natural requires listening to it, which was not possible while
building this. No claim is made that the narration sounds human, and the film
is built so that claim does not need to be true — the captions carry it. If
the voice is judged poor on a listen, mute the narration track and the film
still works, or regenerate with a different `VOICE` in `make_film.py`.

## What the narration may not say

* no national or regulatory deadline;
* no date by which a quantum computer will arrive;
* no claim about a named competing product;
* no accuracy figure without the sentence saying it measures a synthetic
  corpus this project wrote;
* no price, cost, latency or market-size figure.

## Presenting live instead

`presenter/script.md` is the timed eight-minute script, with every click named
and a fallback for each thing that can break on stage.
