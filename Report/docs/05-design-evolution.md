# Interface Evolution

Ten distinct designs were built, screenshotted, reviewed and checkpointed. Four
survived. Every one is preserved in `snapshot/design-history/` and restorable
with `./design-history/RESTORE.sh <name>`.

The value of this record is not the designs — it is the reasoning about why
each was wrong.

---

## The rejected designs

### Dark dashboard — `dashboard` · 17:21
Conventional analytics layout: dark ground, cards, tinted accent, KPI tiles.

> **Verdict: rejected.** "ai slop."

**Lesson.** A layout that could belong to any product belongs to none. The
default dashboard vocabulary signals that no decision was made.

### Editorial document — `editorial` · 18:47
Serif display face, generous measure, a long-form document treatment.

> **Verdict: rejected.** Wanted "industrial grade".

**Lesson.** Register has to match the subject. A defence cryptography tool
reading like a magazine feature undercuts its own credibility.

### Three-pane operator console — `panes` · 21:53
Dense operator layout: filter tree, result list, detail pane.

> **Verdict: rejected.** "way tooo much technical."

**Lesson.** Density is not the same as seriousness. An interface can be
information-rich and still calm.

### Glass over aurora — `glass` · 00:10
Heavy glassmorphism over a drifting multi-hue aurora, thirteen animations.

> **Verdict: rejected.** "looks like some disco presentation… we're doing
> something so serious and important."

**Lesson, and the sharpest one.** An enthusiastic request for an effect is a
request for that effect executed with taste, not dialled to its maximum. The
subject sets the ceiling. Decorative colour and motion actively damage
credibility with the audience they are trying to impress.

### Polished v1 — `polished` · 23:30
The approved dial design with audit fixes applied.

> **Verdict: rejected as a misread.** The instruction had been to checkpoint
> *then* redesign; polishing in place was the wrong action.

**Lesson.** "Redesign" means new files, not the existing design improved.

### Institutional record — `V3` · 00:22
Sidebar contents, navy accent, dense tables — a formal assessment document.

> **Verdict: rejected.** Still read as generic.

**Lesson.** Restraint alone is not identity. Quiet and generic are different
failures with the same symptom.

---

## The designs that were kept

### V1 — the radial dial · 22:20
Soft light/dark console. Every asset one spoke on a ring: length is risk score,
colour is exposure class, ordered by urgency so the work sweeps from most
critical round to the assets that need nothing.

> **Verdict: approved.** "i love the ui."

The dial survived every later rebuild and is in the final design.

### V2 — the scene deck · 23:42
Full-viewport scroll-snapped scenes, one idea per screen, with a position rail.

> **Verdict: approved.** "all good."

Chosen because it projects well: a judge at the back of a room reads one idea
at a time, not a dense page.

### V5 — the instrument · 01:00
Rebuilt from the premise that the product is a *scanner*, not a report layout.
The page opens as a console: target field, presets, and a six-sensor array
stating what each sensor reads before it runs.

Introduced the achromatic principle: **the interface spends no accent hue at
all, so any colour on the page means exactly one thing** — quantum exposure
class. Primary actions are inverted ink rather than tinted.

### V6 — the combination · 01:07
V5's console and palette, V1's dial carrying the verdict with the headline
percentage in its hub, V2's scene deck for the record.

### V7 — final, presented · 01:49
V6 plus the last round of work:

- Folder browser fixed — it had been listing every child directory in full to
  label it, so opening a home folder hung. Now bounded marker probes: home and
  `/` both answer in under a quarter second.
- Live scan progress with stall detection.
- "Where the work is" removed on request.
- Exposure graph redesigned as a direct comparison — protection needed (X + Y)
  against time available (Z), with the shortfall named between the two ends.

---

## Principles that emerged

1. **Colour must mean one thing.** If the chrome spends no hue, every coloured
   pixel is carrying information.
2. **The subject sets the register.** Defence and cryptography earn restraint,
   not decoration.
3. **Motion must report state.** Figures counting to a new value and a progress
   bar that actually moves are functional. Ambient animation is not.
4. **Never encode by colour alone.** Every mark, row and key entry is also
   labelled, and both palettes were validated for colour-blind separation with
   a perceptual checker rather than chosen by eye.
5. **A rejected design is worth keeping.** Ten checkpoints cost almost nothing
   and made every "go back to the one with the ring" instantly actionable.
