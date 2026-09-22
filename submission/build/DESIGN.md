# Submission design system

One identity across the deck, the PDF, the diagram panels and the film. The
tokens live in `design.py`; this file is why they are what they are.

## The idea the design has to carry

> Fragmented evidence becomes one explainable inventory.

Everything below follows from that. The design's job is to make *evidence*
look like evidence and *argument* look like argument, and never to let the two
be mistaken for each other.

## Palette

Lifted from the product's own dark theme (`app/web/style.css`), not invented
for the submission. The deck is presenting this tool, so it should look like
this tool.

| Token | Value | Used for |
|---|---|---|
| `PAPER` | `#101012` | panel and film background |
| `SURF` / `SURF2` | `#1A1A1D` / `#212125` | cards, nested cards |
| `RULE` / `RULE2` | `#2E2E33` / `#3C3C42` | hairlines, chip borders |
| `INK` | `#EDEBE6` | primary text |
| `INK2` / `INK3` / `INK4` | `#ADA9A1` / `#86827A` / `#6B675F` | supporting, dim, labels |
| `BROKEN` | `#D9503C` | Shor-broken — **and the single accent** |
| `WEAKENED` | `#E0B45A` | Grover-weakened |
| `UNKNOWN` | `#8A939F` | unresolved — deliberately not alarming |
| `SAFE` | `#3FAE86` | quantum-safe, and a resolved migration target |

The classification colours carry meaning and are never used decoratively. Red
is the accent *because* it is the broken-by-Shor colour, so the accent always
points at the thing the project is about.

## Type

Two faces, and the split is the whole system:

* **Sans** (system UI stack) carries **argument** — headings, captions, the
  sentences we wrote.
* **Mono** (SF Mono / Menlo) carries **evidence** — file paths, line numbers,
  algorithm names, assurance grades, scores, migration targets.

A reader can therefore tell at a glance which words came out of the tool and
which are ours. This is the rule that does the most work, and nothing may
break it: a claim never appears in mono, and a value from a scan never appears
in sans.

### Scale

| Role | Deck | Panels | Film |
|---|---|---|---|
| Slide title | template's own, 29–32pt | — | — |
| Scene heading | — | 40–46px | 38–46px |
| Section head | 11.5pt bold, accent | — | — |
| Body | 10.5–12.5pt | 15–22px | 17–25px |
| Evidence (mono) | 10.5pt | 17–25px | 17–29px |
| Caption / note | 9.5–10pt, muted | 14–17px | 16–21px |
| Eyebrow label | — | 12–14px mono, .12em tracking, uppercase | same |

## Layout rules

* Content lives between **0.45 in** and **12.88 in** horizontally, **1.22 in**
  and **6.82 in** vertically. The template owns everything outside that.
* **One central idea per slide.** If a slide needs two, it is two slides — and
  since there are exactly six, it is instead a slide that needs rewriting.
* **Every panel answers a question.** A panel that only decorates is deleted.
* **Every screenshot proves a claim**, and its caption says which.
* Panels are cropped to their content by `render_panels.py`, so a slide never
  carries a band of empty panel.
* Screenshots are cropped **at a section boundary**, never through a line of
  text.

## Motion (film only)

* One easing curve throughout: `1 - (1-p)³`. No bounces, no overshoot.
* Elements enter with opacity plus a short upward translate (8–20 px). That is
  the only entrance.
* Screenshots get at most a **1.02–1.03×** scale over a whole scene — enough
  that the frame is not dead, not enough to read as a zoom effect.
* Scene joins dip through black over ~0.3 s. On a near-black film this reads
  as a dissolve rather than a cut.
* Choreography is *mapped* onto scene length rather than truncated, so reveals
  track the narration and the short cut re-times rather than cuts off.
* **Stillness is the default.** Nothing moves while the viewer is reading
  technical values.

## What is not allowed

No stock imagery. No padlocks, circuit boards, Matrix rain, particle fields,
fake terminals or spinning 3D anything. No progress meters that measure
nothing. No chart without data behind it. No fabricated UI, and no illustrated
diagram presented as product footage — panels are visibly panels, screenshots
are visibly screenshots.

## Checks before a slide or scene ships

1. Does it make one point, and is that point legible in five seconds?
2. Is every number on it traceable to a command in this repository?
3. Does removing any element make it clearer? Then remove it.
4. Does it read at portal-preview size, not just full screen?
