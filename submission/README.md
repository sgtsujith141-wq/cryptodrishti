# SIH submission assets — SIH26164

Everything here is built from the repository by a script. Nothing in this
directory is hand-edited, so a rebuild is reproducible and always matches the
code it describes.

| Asset | Path | State |
|---|---|---|
| Official template (unmodified) | `template/SIH2026-IDEA-Presentation-Format.pptx` | 7 slides, as supplied |
| Idea presentation | `CryptoDrishti-SIH26164-Idea-Presentation.pptx` | **6 slides, QA-clean** |
| Final submission PDF | `CryptoDrishti-SIH26164-Idea-Presentation.pdf` | **6 pages, vector text, 13.333 × 7.50 in** |
| Demonstration video | `CryptoDrishti-SIH26164-Demo.mp4` | **1920×1080, H.264 / AAC, narrated** |
| Screenshots | `screenshots/*.png` | 7 dark-theme captures of the running console |

### Build scripts

| Script | What it does |
|---|---|
| `build/capture_screens.py` | dark-theme captures of every console scene |
| `build/build_deck.py` | fills the official template |
| `build/check_deck.py` | text, geometry and completeness QA |
| `build/export_pdf.py` | PDF — LibreOffice if present, else macOS QuickLook |
| `build/make_video.py` | assembles the demonstration video |

## Registration details

These are written into the title slide, and the team name into the oval on
slides 2–6. They live in one place — the `PORTAL` dictionary at the top of
`build/build_deck.py`.

| Field | Value |
|---|---|
| Problem Statement ID | SIH26164 |
| Problem Statement Title | Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) |
| Theme | 26164 |
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
python submission/build/export_pdf.py                   # six-page PDF
python submission/build/make_video.py                   # demonstration video
```

`check_deck.py` exits non-zero if any shape leaves the canvas, collides with
another, or runs into the template's footer bar — so a layout regression fails
loudly rather than shipping.

## What the deck contains

Exactly six slides, each answering one question:

| # | Slide | Answers | Visual |
|---|---|---|---|
| 1 | Title | What is this, and who are we? | — |
| 2 | Proposed Solution | What problem, and why is this different? | inventory — three RSA findings, three answers |
| 3 | Technical Approach | How does it work? | architecture diagram |
| 4 | Feasibility and Viability | Is it built, validated, and realistic? | evidence drawer |
| 5 | Impact and Benefits | Who benefits, and what is the evidence? | assessment |
| 6 | Research and References | What standards back it? | CBOM export, remediation plan |

The template ships a seventh slide, headed *IMPORTANT INSTRUCTIONS*, whose own
text says to keep the deck to six slides including the title. The build removes
it; that is following the template, not departing from it. Everything else the
template supplies — backgrounds, branding, section titles, footer, slide
numbering, the team-name oval — is left exactly as supplied.

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

## About the video

`CryptoDrishti-SIH26164-Demo.mp4` is an **assembled product overview**, not a
screen recording. Every visual is a still capture of the running application,
or the architecture diagram, given slow motion and cut together with narration
synthesised by macOS `say`. No cursor is animated, no interaction is simulated,
and nothing appears on screen that the tool did not produce. Nobody was filmed
and no microphone was used.

The narration script and on-screen text live in `build/make_video.py`, in the
`scenes()` function — that is the one place to edit them.

`presenter/video.md` documents the scene list and the rules the narration
follows. `presenter/script.md` is the separate timed eight-minute script for
presenting live, if that is wanted instead.
