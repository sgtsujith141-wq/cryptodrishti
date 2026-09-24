# The demonstration film

> **Concept:** *The cryptography you cannot see.*
>
> Two cuts exist, both built by `submission/build/make_film.py`:
>
> | Cut | Path | Length |
> |---|---|---|
> | Full | `submission/video/CryptoDrishti-Final-Demo.mp4` | 3:54 · 12 scenes |
> | Short | `submission/video/CryptoDrishti-Short-Demo.mp4` | 1:26 · 6 scenes |
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
  deliberately produces no target at all. It is paid off immediately by the
  real remediation screen, where those three answers appear as three funded
  workstreams: the argument the film has just made, in the product's own
  words rather than the film's.
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

## Sound: why this film is caption-led

**The film ships silent, with its captions burned into the picture.** That is a
deliberate choice made after the alternative failed, and it is worth stating
plainly rather than leaving a viewer to wonder why there is no voice.

**What was intended.** Narration was to use the same neural voice the team's
other submission pinned: voice `SQ8WYwlpzxrTbbuJgi38` on
`eleven_multilingual_v2`, with that project's exact settings (stability 0.42,
similarity 0.82, style 0.18, speaker boost on, speed 1.06), generated through
the authenticated ElevenLabs CLI. The voice id and parameters are read from
`SecureMailScope/submission/demo/narration-script.json` rather than guessed.
Nothing in that project is modified — it is read only.

**Why it could not be used.** The ElevenLabs account is on the free tier and
its monthly character allowance is spent: 9,994 of 10,000 characters consumed,
next reset 19 October 2026. The full cut needs roughly 2,900 characters of
narration and the account has six. This is a billing state, not a bug, and no
amount of retrying changes it.

**Why not fall back to `say`.** Because the operating system's synthesiser
reads as a robot reading a script, and that is the single thing this film was
rebuilt to stop being. A robot narrator is worse than silence: it makes a
careful product look automatically generated. The `say` path has therefore been
**deleted from the builder** rather than left in as a tempting default — there
is no longer a code path that can quietly produce it.

**What the builder does now.** `make_film.py` runs a quota preflight before it
spends a single character: it asks the account how many characters remain,
compares that against the narration it is about to request, and prints which
cut it is building and why. If the voice dies part-way through a voiced build,
the cut is discarded and rebuilt caption-led rather than shipped half-narrated.

```bash
python submission/build/make_film.py              # caption-led (current)
python submission/build/make_film.py --voice      # attempt the pinned voice
```

**How the caption-led cut is timed.** Scene length is driven by reading speed
rather than speech: fourteen characters a second, with a floor of 2.4 seconds
so nothing flashes past, and no caption longer than 68 characters so it never
exceeds two lines on screen. Captions break at sentence boundaries first, then
at clause punctuation, then on balanced word wrapping — and a final pass folds
away any stub too short to deserve a caption of its own. Where a scene's
choreography outlasts its captions, the captions stretch to fill it, so the
text and the picture stay in step instead of the text finishing early.

Captions were always written separately from the narration (`cap` versus `say`
in `film_scenes.py`), so the on-screen text already reads as prose — it was
never a transcript of something spoken. That is why this cut works: the film
was designed caption-first from the start.

**What has been verified** by `submission/build/check_film.py`: that both cuts
decode end to end, that every SRT cue is ordered and none outlives the film,
that no sampled frame is empty, and that the caption band carries ink in at
least 80% of sampled frames — a caption-led film whose captions silently failed
to draw would pass every other check, so that one is measured directly. The burned-in captions
and the SRT come from one timed list, so their wording and timings cannot
drift apart.

One deliberate difference between them: where a scene already typesets a line
in large type — the RSA sequence ends on *Purpose decides the migration.* set
across the frame — the band stays empty rather than repeating the sentence
underneath it in a smaller size. Six lines are withheld this way. The SRT
keeps all of them, so the transcript stays complete.

**What has not been verified:** nothing about how it sounds, because there is
no sound. That is the point — there is no synthetic voice here to misjudge.

**If you want narration before the deadline.** Top the ElevenLabs account up,
or supply a key with quota, then run `make_film.py --voice`; the preflight will
pass and the pinned voice will be used. Alternatively, record the narration
yourself — `presenter/script.md` is the script, and a human reading it beats
any synthesiser.

## What the captions may not say

* no national or regulatory deadline;
* no date by which a quantum computer will arrive;
* no claim about a named competing product;
* no accuracy figure without the sentence saying it measures a synthetic
  corpus this project wrote;
* no price, cost, latency or market-size figure.

## Presenting live instead

`presenter/script.md` is the timed eight-minute script, with every click named
and a fallback for each thing that can break on stage.
