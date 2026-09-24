# SIH submission assets — SIH26164

Everything here is built from the repository by a script. Nothing in this
directory is hand-edited, so a rebuild is reproducible and always matches the
code it describes.

| Asset | Path | State |
|---|---|---|
| Official template (unmodified) | `template/SIH2026-IDEA-Presentation-Format.pptx` | 7 slides, as supplied |
| **Idea presentation** | `CryptoDrishti-SIH26164-Idea-Presentation.pptx` | **6 slides, QA-clean** |
| **Presentation PDF** | `CryptoDrishti-SIH26164-Idea-Presentation.pdf` | **6 pages, vector text** |
| **Demonstration film, full** | `video/CryptoDrishti-Final-Demo.mp4` | 3:54 · 1920×1080 H.264 · captions burned in, plus SRT |
| **Demonstration film, short** | `video/CryptoDrishti-Short-Demo.mp4` | 1:26 · 1920×1080 H.264 · captions burned in, plus SRT |
| Deck contact sheet | `contact/deck-contact-sheet.png` | all six slides side by side |
| Film contact sheet | `contact/film-contact-sheet.png` | one frame from every scene of the full cut |
| Screenshots | `screenshots/*.png` | 8 genuine captures, 7 dark-theme console + the report |

| | |
|---|---|
| Repository | https://github.com/sgtsujith141-wq/cryptodrishti |
| Demo video (YouTube) | **[YOUTUBE LINK TO BE ADDED AFTER UPLOAD]** |

Nothing has been uploaded to the SIH portal or to YouTube. Once the film is
uploaded, put the link in `deck_content.py` (`YOUTUBE_URL`), rebuild the deck
and PDF, and the placeholder on slide 6 becomes the real link.

### Build scripts

| Script | What it does |
|---|---|
| `build/capture_screens.py` | dark-theme captures of every console scene |
| `build/build_deck.py` | fills the official template |
| `build/check_deck.py` | text, geometry and completeness QA |
| `build/export_pdf.py` | PDF — LibreOffice if present, else macOS QuickLook |
| `build/design.py` | the shared design system: palette, type stack, base CSS |
| `build/render_panels.py` | the deck's custom diagram panels, HTML → PNG |
| `build/film_scenes.py` | film scene definitions and captions |
| `build/make_film.py` | renders both cuts of the film, plus SRT |

## Registration details

These are written into the title slide, and the team name into the oval on
slides 2–6. They live in one place — the `PORTAL` dictionary at the top of
`build/build_deck.py`.

| Field | Value |
|---|---|
| Problem Statement ID | SIH26164 |
| Problem Statement Title | Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) |
| Theme | Blockchain & Cybersecurity |
| PS Category | Software |
| Team ID | 146876 |
| Team Name | Zero-Day |

Any field left empty in `PORTAL` is written into the deck as a visible
`[FILL FROM SIH PORTAL]` marker instead, and `check_deck.py` counts those and
refuses to call the deck submittable while the count is above zero. Filling the
dictionary is the only thing that clears that check — nothing bypasses it.

## Rebuilding everything

```bash
python run.py --demo                                    # real data
python run.py --port 8140 &                             # serve it
python submission/build/capture_screens.py --port 8140  # dark-theme captures
python docs/architecture/render.py                      # diagram, light + dark
python submission/build/build_deck.py                   # fill the template
python submission/build/check_deck.py                   # QA gate
python docs/architecture/render.py                      # diagram, light + dark
python submission/build/render_panels.py                # custom deck panels
python submission/build/build_deck.py                   # fill the template
python submission/build/check_deck.py                   # QA gate
python submission/build/export_pdf.py                   # six-page PDF
python submission/build/make_film.py                    # both film cuts + SRT
```

`check_deck.py` exits non-zero if any shape leaves the canvas, collides with
another, or runs into the template's footer bar — so a layout regression fails
loudly rather than shipping.

## What the deck contains

Exactly six slides. Each carries **one central argument supported by three to
five substantive elements** — an explanation, technical detail, evidence, and a
conclusion where one is warranted. The deck is built to be read as a static
PDF, with no presenter, so nothing important is left to be said out loud.

| # | Slide | Central argument | Supporting elements |
|---|---|---|---|
| 1 | Title | What this is and who built it | product name, one-line description, the six portal fields |
| 2 | Proposed Solution | An inventory has to come before a migration | the problem, what the tool is, five capabilities, the differentiator, the implemented pipeline |
| 3 | Technical Approach | Detection is not understanding | system architecture, verified technology stack, the three-RSA comparison, security design |
| 4 | Feasibility | This is a working prototype, not a proposal | implemented capabilities, validation evidence, a real cropped screenshot, feasibility and limits |
| 5 | Impact | The output drives a real migration workflow | five workflow stages, intended users, both benchmark corpora with their caveat |
| 6 | References | The standards the work is built against | four grouped reference sets, plus a scope note |

**Content came first.** Every sentence lives in
[`build/deck_content.py`](build/deck_content.py), which was written and
fact-checked against the repository before any layout existed; the builder only
arranges it. The module's docstring lists the file each technical claim was
verified against.

### Readability

The template's light background is preserved. Product screenshots are dark,
but they are cropped tight and used only where they carry information a
sentence cannot — no slide is turned into a dark rectangle, and no explanation
is buried inside an image. **Every explanation is a real PowerPoint text run**,
editable in the deck and selectable in the PDF.

| Role | Size |
|---|---|
| Slide title | template's own, 28–36pt |
| Section heading inside a slide | 21pt |
| Main explanation | 18pt |
| Labelled list row / secondary label | 15–16pt |
| Caption, reference entry, figure label | 13pt |

Nothing a judge must read falls below 13pt. The only smaller text is the
template's own furniture — the team-name oval at 11pt and the footer at 12pt.

The template ships a seventh slide, headed *IMPORTANT INSTRUCTIONS*, whose own
text says to keep the deck to six slides including the title. The build removes
it; that is following the template, not departing from it.

## Images

Every image is real. The screenshots are captures of the running application in
its dark theme, taken from the database `python run.py --demo` produces. The
architecture diagram is rendered from
`docs/architecture/architecture.mmd`, which is also the source of the light
variant used in the main README — one source, two palettes, so the two cannot
disagree about what the system does.

Each capture is cropped to the region that carries the point its slide is
making, at a section boundary rather than through a line of text. That cropping
is the only change: nothing is scaled, recoloured, retouched, annotated or
composed from separate captures.

## About the PDF

Exported by `build/export_pdf.py` through LibreOffice
(`soffice --headless --convert-to pdf`), so the text is real text — selectable,
searchable and sharp at any zoom. If LibreOffice is not installed the script
falls back to rendering through macOS QuickLook at 240 dpi, which is faithful
but rasterised; it prints which route it took and records it in the PDF's
Producer metadata, so there is never any doubt about which one produced a given
file.

## Contact sheets

Two are generated by `build/contact_sheet.py` and committed under `contact/`:

| Sheet | What it is for |
|---|---|
| `contact/deck-contact-sheet.png` | all six slides side by side — the fastest way to see whether text and visuals are actually in balance, and whether the deck reads as one designed document |
| `contact/film-contact-sheet.png` | one frame from the middle of every scene — if it looks like the same slide with different text, the edit needs another pass |

The film sheet is the check that caught the most serious defect in this
package: every product screenshot in the film was failing to load, so twelve
sampled frames contained no product footage at all. `page.set_content()` gives
the document an `about:blank` base URL and Chromium refuses `file://`
subresources from it, so the images had been silently missing since the film
was first built. They are now inlined as data URIs.

## About the film

Two cuts, both from `build/make_film.py`, both 1920×1080 H.264/AAC with an SRT
beside them. They are **assembled product films, not screen recordings**: real
captures of the running tool are intercut with motion-designed scenes built
from real scan output. No cursor is animated, no interaction is simulated, and
no value appears on screen that the application did not produce.

Scenes are authored as HTML and driven by a deterministic `seek(t)`, so a
render is reproducible frame for frame.

**Both cuts are caption-led and carry no narration track.** The neural voice
these films were built for could not be used — the ElevenLabs account's monthly
character allowance is spent (9,994 of 10,000, resetting 19 October 2026) — and
the only remaining synthesiser, macOS `say`, reads as a robot reading a script.
Silence with typeset captions is the better film, so the `say` path was removed
from the builder rather than left in as a default. Captions are burned into the
picture and also written as a sidecar SRT; the film was designed caption-first
from the start, so nothing about the argument depends on the sound.
`presenter/video.md` records this in full, including how to restore narration
if the account is topped up.

### Portal constraints — stated as an assumption

The SIH portal's duration and file-size limits for a demonstration video were
**not available to check** while these were produced, so nothing here claims to
meet a verified limit. Both cuts were made to be safe against the usual shapes
of such a rule:

* the **full cut** runs 3:54, inside a 4-minute ceiling — by six seconds, so
  if a portal enforces exactly four minutes there is no slack to spare and the
  short cut is the safer upload;
* the **short cut** runs 1:26, inside 90 seconds, for a portal with a stricter
  limit or a reviewer who wants the argument quickly;
* both are H.264 in MP4 at 1920×1080 — the most broadly accepted combination —
  and both are well under 100 MB (6.9 MB and 2.2 MB). Each carries a silent
  AAC track so the container is well formed everywhere.

Bitrate was chosen for legible interface text rather than for the smallest
file. If the portal turns out to impose a tighter size limit, re-encode from
the same source rather than downscaling: `make_film.py` re-renders either cut
from scratch, and raising `-crf` is preferable to reducing resolution, because
the deck's value is in text that has to stay readable.

`presenter/video.md` documents the concept, the acts, the sound decision and
the rules the captions follow. `presenter/script.md` is the separate timed script for
presenting live.
