# Engineering Decisions and Defects Found

The judgement calls, and the real bugs caught before they mattered. This is the
part of the project most worth reading.

---

## Correctness over coverage

### Two hex typos in our own constant tables

The binary sensor identifies cryptography in compiled files by matching the
constant tables an implementation must contain — the AES S-box, the SHA-256
round constants, the MD5 T-table. Those bytes cannot be obfuscated away without
breaking the algorithm.

Rather than trusting the tables as transcribed, every one was **recomputed from
first principles and matched against a real `libcrypto` binary**. That found two
errors:

| Table | Had | Correct |
|---|---|---|
| MD5 T-table | `78a46ad256b7c7e8db70202ceecebdc1` | `78a46ad756b7c7e8db702024eecebdc1` |
| SHA-1 round constant K0 | `99795a82` | `9979825a` |

Both would have produced **silent false negatives** — the scanner reporting a
binary as clean because our own reference data was wrong. Nothing in the test
suite would have caught it; only checking against ground truth did.

### A signature that matched 32 unrelated binaries

A 4-byte DES S-permutation signature was matching 32 system binaries that
contain no DES. Four bytes is not enough entropy to identify anything. Removed.

### An unverified Kyber table

A Kyber zeta table had been added but never verified against a real
implementation. Removed rather than shipped.

> **The principle.** *An unverified signature is worse than a missing one*,
> because a missing one produces a gap you can see and an unverified one
> produces a confident wrong answer you cannot.

---

## Honesty as a design requirement

### Confidence on every finding, and `Unresolved` as a first-class result

Regex detection for the nine non-Python languages has genuinely lower precision
than AST analysis. Rather than hide that:

- every finding carries a **confidence score**, surfaced in the interface
- anything that cannot be resolved statically is reported as **Unresolved**,
  never guessed

In front of cryptographers, stating the limitation first is stronger than
having it found for you.

### The network sensor was claiming a result it had never measured

It reported "classical only" for endpoints where Python's `ssl` module simply
cannot set post-quantum groups — a limitation of the library, not a property of
the server. That is an untrue statement.

Rewritten to be **three-state** — supported / not supported / **not tested** —
with an OpenSSL 3.5+ CLI fallback that can actually perform the test.

### A certificate lifetime stated absurdly

A finding read "valid for a further 988.7 years". Technically derived from the
certificate, useless as a statement. Reworded to: *"expires 3015-05-16, an
implausible lifetime that guarantees the key outlives its algorithm."*

---

## Modelling what is genuinely unknown

Q-Day is an open question. The tool therefore **never asserts a date**. It is
modelled as a distribution over 2030 / 2034 / 2044 — the Global Risk Institute
expert-survey range — and reported as a probability. Every parameter is
adjustable live, and the whole estate re-ranks against it in about 100 ms.

This is also the strongest demonstration beat: moving Q-Day from 2034 to 2030
with *restricted* sensitivity takes peak exposure from **4.5 years to 23.5
years** and moves **23 assets from medium to high**.

---

## Recommendations constrained by physics

Clause (iv) of the problem statement asks for alternatives chosen by risk
profile, latency and cost. That is a constrained choice, not a lookup, and the
constraint that dominates is **size**.

An ECDSA P-256 signature is 64 bytes. ML-DSA-65 is 3,309. On a TLS handshake
that is invisible; on a constrained radio link with a 51-byte payload it is
impossible, and recommending it there would be wrong.

The engine reasons about the size delta and states it — including when the
honest answer is that **no drop-in replacement exists and the device needs a
hardware refresh**.

---

## Defects found by looking rather than assuming

Several bugs were invisible in code review and only appeared when the interface
was actually rendered and inspected:

| Defect | Cause |
|---|---|
| Every form control rendered dark on a light page | `color-scheme: light dark` let the browser apply its own scheme to control internals. Fixed by resolving the theme in an inline `<head>` script *before* the stylesheet parses. |
| A `hidden` element still displayed | A `display: flex` rule silently defeated the `hidden` attribute. Added `[hidden] { display: none !important }`. |
| Peak exposure tile disagreed with the chart | The preloaded scan carried a stale persisted Q-Day. Fixed by rescoring on load. |
| Timeline hardcoded a migration estimate | It drew `Y = 2.0` while each asset carries its own. Now taken from the worst real asset. |
| The whole record blanked below the headline | One renderer wrote to an element that had been removed, throwing. Now each renderer is isolated, and an automated check asserts every DOM id the JavaScript touches exists. |
| Folder browser hung | It listed every child directory in full to label it. Replaced with bounded marker probes — `/` now answers in 0.21 s. |
| Progress bar looked frozen | It advanced only once per sensor, so it sat at 5% for the entire source scan. Now every scanner reports as it works, with server-side tick detection for genuine stalls. |

---

## Performance decisions

**The Q-Day control returned the full findings set on every change** — 1.8 s
and 516 KB per drag. Rewritten to return **deltas only**: a new ordering plus
the changed fields. Result: **35 ms and 40 KB**, a fifty-fold improvement, which
is the difference between a control that demonstrates well and one that does
not.

Supporting fixes: memoised design-token lookups to stop forcing a style read
per drawn mark, cancelled in-flight tweens, and sequence-numbered requests so a
slower earlier reply cannot overwrite newer state during a fast drag.

---

## Choices made for the environment, not for convenience

| Decision | Reason |
|---|---|
| Four dependencies total | The entire supply chain fits on one line. For accreditation in a classified environment that is decisive. |
| No web fonts, no CDN, no framework | An external request would make the air-gap claim false. The guarantee is demonstrated by unplugging the cable on stage. |
| Hand-written SVG instead of a charting library | No bundle, no CDN, full control of how each mark is drawn. |
| SQLite, single file | Nothing to provision; results are portable; the demo state can be pre-seeded. |
| Regex rule packs instead of tree-sitter | A multi-hour install risk for marginal gain at the available timescale — with the precision cost stated openly instead of hidden. |
