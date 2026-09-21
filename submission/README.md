# SIH submission assets — SIH26164

Everything here is built from the repository by a script. Nothing in this
directory is hand-edited, so a rebuild is always reproducible and always
matches the code it describes.

| Asset | Path | State |
|---|---|---|
| Official template (unmodified) | `template/SIH2026-IDEA-Presentation-Format.pptx` | 7 slides, as supplied |
| Idea presentation | `CryptoDrishti-SIH26164-Idea-Presentation.pptx` | **6 slides, built, QA-clean** |
| Final submission PDF | `CryptoDrishti-SIH26164-Idea-Presentation.pdf` | **6 pages, 13.333 × 7.50 in, verified** |
| Screenshots | `screenshots/*.png` | 7 genuine captures of the running console |
| Build script | `build/build_deck.py` | rebuilds the deck from the template |
| QA script | `build/check_deck.py` | text, geometry and completeness checks |
| PDF export | `build/export_pdf.py` | LibreOffice if present, else macOS QuickLook |

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
dictionary is the only thing that clears that check.

## Rebuilding

```bash
python run.py --demo                      # populate the console with real data
python submission/build/build_deck.py     # fill the template
python submission/build/check_deck.py     # QA
python submission/build/export_pdf.py     # six-page PDF
```

`check_deck.py` exits non-zero if any shape leaves the canvas, collides with
another, or runs into the template's footer bar.

## What the deck contains

Exactly six slides, in the order the template prescribes:

1. **Title** — problem statement ID, title, theme, PS category, team ID, team name
2. **CryptoDrishti | Proposed Solution**
3. **Technical Approach** — stack, sensors, risk engine, output, deployment
4. **Feasibility and Viability** — what is built, how it is validated, risks, constraints
5. **Impact and Benefits** — audience, what changes, measured evidence, adoption cost
6. **Research and References** — standards, formats, method, project

The template ships a seventh slide, headed *IMPORTANT INSTRUCTIONS*, whose own
text says to keep the deck to six slides including the title. The build removes
it; that is following the template, not departing from it. Everything else the
template supplies — backgrounds, branding, the section titles, the footer, the
slide numbering, the team-name oval — is left exactly as it was.

## Images

Every image is real:

* the seven screenshots are captures of the running application, taken from the
  database that `python run.py --demo` produces;
* the architecture diagram is rendered from `docs/architecture/architecture.mmd`.

The build trims each capture's empty outer margin, and on two of them also cuts
below the card's last row, so the interface is legible at slide size. That
cropping is the only change; no interface is mocked up, recomposed, retouched
or drawn.

## About the PDF

The PDF was produced by `build/export_pdf.py`. That script prefers LibreOffice
(`soffice --headless --convert-to pdf`), which keeps text as text. **LibreOffice
is not installed on the machine that built this file**, and neither is
PowerPoint or Keynote, so the script fell back to its second route: macOS
QuickLook — the renderer Finder uses to preview a `.pptx` — at 240 dpi, one
slide per page, assembled at exactly the template's 13.333 × 7.50 in slide size.

What that means in practice:

* the PDF is visually faithful, and every page has been inspected;
* pages are the correct size and there are exactly six of them;
* **the text is rasterised, not selectable or searchable.**

For a vector PDF, install LibreOffice and re-run the exporter — it will take
the first route automatically and overwrite the file:

```bash
brew install --cask libreoffice
python submission/build/export_pdf.py
```

Or export manually from PowerPoint: **File → Export → PDF**, with *Slides*
(not handouts), one slide per page. Then confirm the result is six pages.

## Still outstanding

**A demonstration video has not been recorded.** `presenter/video.md` holds the
script, the shot list, the expected on-screen output for each shot and a
fallback plan. No video file exists anywhere in this repository. Nothing here
should be read as saying otherwise until one does.
