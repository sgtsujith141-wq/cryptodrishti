# SIH submission assets — SIH26164

Everything here is built from the repository by a script. Nothing in this
directory is hand-edited, so a rebuild is always reproducible and always
matches the code it describes.

| Asset | Path | State |
|---|---|---|
| Official template (unmodified) | `template/SIH2026-IDEA-Presentation-Format.pptx` | 7 slides, as supplied |
| Idea presentation | `CryptoDrishti-SIH26164-Idea-Presentation.pptx` | **6 slides, built, QA-clean** |
| Final submission PDF | — | **Not produced. See "Blocked on" below.** |
| Screenshots | `screenshots/*.png` | 7 genuine captures of the running console |
| Build script | `build/build_deck.py` | rebuilds the deck from the template |
| QA script | `build/check_deck.py` | text, geometry and completeness checks |

## Rebuilding the deck

```bash
python run.py --demo                      # populate the console with real data
python submission/build/build_deck.py     # fill the template
python submission/build/check_deck.py     # QA
```

`check_deck.py` exits non-zero if any shape leaves the canvas, collides with
another, or runs into the template's footer bar. It also counts the portal
fields that are still placeholders, and says plainly that the deck is not
submittable while that count is above zero.

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

## Blocked on

The deck cannot be exported as the final submission PDF yet. Four fields are
not recoverable from this repository, and the build writes each one as a
visible `[FILL FROM SIH PORTAL]` marker rather than a plausible guess:

| Field | Where it appears | Why it is blank |
|---|---|---|
| Problem Statement Title | slide 1 | The verbatim portal wording is not recorded here |
| Theme | slide 1 | Assigned by the portal |
| Team ID | slide 1 | Issued on registration |
| Team Name | slide 1, and the oval on slides 2–6 | Chosen at registration |

`PS Category` is filled as **Software**, which is a property of this submission
rather than a portal-issued fact: CryptoDrishti is a software tool with no
hardware component.

### To finish

1. Open `submission/build/build_deck.py` and replace the four values —
   `FILL_IN` at the top of the file is the marker each one currently uses.
2. `python submission/build/build_deck.py && python submission/build/check_deck.py`
   — the check must report `portal fields still unfilled: 0`.
3. Export to PDF from PowerPoint (or `soffice --headless --convert-to pdf`) and
   confirm the result is **exactly six pages**.
4. Open every page and read it, not just the first.

Until step 3 has actually been done, this submission is not complete, and
nothing in this repository should be read as saying otherwise.
