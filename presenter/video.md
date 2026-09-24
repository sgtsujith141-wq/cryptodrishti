# The demonstration film

> **Concept:** *The cryptography you cannot see.*
>
> Two cuts exist, both built by `submission/build/make_film.py`:
>
> | Cut | Path | Length |
> |---|---|---|
> | Full | `submission/video/CryptoDrishti-Final-Demo.mp4` | 3:09 · 11 scenes |
> | Short | `submission/video/CryptoDrishti-Short-Demo.mp4` | 1:26 · 6 scenes |
>
> The product is the main character. Most of the running time is the real
> console, recorded while it was driven with real clicks; the rest is typeset
> from the same scan's output. No cursor is drawn, no interaction is
> simulated, and no value appears on screen that the application did not
> produce.

## The short cut, beat by beat

| Time | Beat | On screen |
|---|---|---|
| 0–7 s | Hook | real evidence fragments, each labelled with its file — *Your cryptography is everywhere. Your inventory usually isn't.* |
| 7–22 s | The product | the console's assessment: PARTIAL stated first, then 23 assets, 16 quantum-vulnerable |
| 22–48 s | Signature moment | one algorithm, three purposes, three answers — ML-DSA-65, X25519MLKEM768, *purpose must be resolved first* |
| 48–63 s | Follow the evidence | the RSA signing row is hovered and opened; the drawer shows purpose, assurance, proves use, the exposure arithmetic, then the target |
| 63–76 s | Output | the remediation programme, the generated report, and the CBOM passing validation |
| 76–86 s | Close | *Scattered evidence. One explainable inventory. A migration decision you can defend.* — team, problem statement, repository |

The full cut follows the same order at a slower pace, and adds the inventory,
the remediation programme and the CBOM as scenes of their own, plus what the
scan did not see and how to check every figure.

## How the product footage is made

`submission/build/capture_walkthrough.py` drives the running console in
headless Chromium exactly as a presenter would, and records each state:

1. the assessment, scrolled into view;
2. the inventory;
3. the pointer resting on the RSA signing finding — the script checks that the
   hovered row really is that finding, and fails if it is not;
4. the click, and the evidence drawer that opens;
5. the drawer scrolled to the exposure arithmetic;
6. the remediation programme;
7. **Validate** pressed, and the console's own verdict;
8. **Open report** pressed, and the tab it opens.

Each state is a full 2880×1620 frame, saved with the on-screen position of the
elements that matter in it (`submission/walkthrough/walkthrough.json`). The
film's camera moves across those frames — pushing in to the part being
discussed, so interface text is read at a legible size rather than as a small
panel in a dark field — and its focus rings are drawn at the positions the
browser reported. A dissolve between two frames marks the moment a click
changed the screen. It is a sequence of genuine states with restrained camera
movement, not a continuous screen recording, and it says so.

```bash
python run.py --demo                                        # real data
python run.py --port 8140 &
python submission/build/capture_walkthrough.py --port 8140  # the walkthrough
python submission/build/make_film.py                        # both cuts + SRT
python submission/build/make_film.py --short                # short cut only
```

Scenes are authored as HTML in `submission/build/film_scenes.py` and driven by
a deterministic `seek(t)`, so a render is reproducible frame for frame. Frames
are screenshotted from headless Chromium and piped straight into ffmpeg.

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
least two thirds of sampled frames — a caption-led film whose captions silently failed
to draw would pass every other check, so that one is measured directly. The burned-in captions
and the SRT come from one timed list, so their wording and timings cannot
drift apart.

Where a scene's own typography carries a line — the opening's two-line hook,
the RSA sequence's verdict *Purpose changes the migration.*, the closing card —
the band is left empty rather than repeating the sentence underneath itself in
a smaller size. The builder also withholds any caption that the scene already
shows on screen, and the SRT keeps every caption it has, so the transcript
stays complete.

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
