# Verification and Results

## How correctness was established

| Area | Method |
|---|---|
| Crypto constants | Recomputed from first principles, matched against a real `libcrypto` binary. Found two hex typos. |
| Detection precision | Scanned four real open-source projects — OpenSSL, Django, Paramiko, Apache Shiro — never a prepared corpus. |
| False positives | Signatures with insufficient entropy identified by cross-checking against unrelated system binaries and removed. |
| CBOM conformance | Structural validation against the vendored CycloneDX 1.6 schema, run live in the interface. |
| Risk model | Every score factor surfaced in the interface with its input value, so the arithmetic is auditable. |
| Air gap | `grep` across all assets, plus an automated preflight assertion, plus physical demonstration. |
| Interface | Rendered and screenshotted in both themes at every iteration; several defects were invisible in code review. |
| DOM integrity | Automated check that every element id the JavaScript touches exists in the markup. |

## Preflight

`python run.py --preflight` runs 15 checks and reports **ALL CLEAR** or names
what is wrong: database, seeded scan present, CBOM validity, Q-Day round trip,
demo repositories, binary scan target, air-gap grep, presenter script, Q&A
sheet, slide deck, live probe availability.

> `--preflight` runs its own scan and leaves it as the newest record. Always
> finish with `--demo-reset`.

---

## Measured results — OpenSSL

Reproducible with `python run.py --demo-reset`.

| Measure | Value |
|---|---|
| Raw detector hits | 2,102 |
| Distinct assets after normalisation | 77 |
| Quantum vulnerable | 58 — 75.3% |
| Broken outright by Shor | 26 |
| Weakened by Grover | 32 |
| Unresolved | 4 |
| Hybrid | 1 |
| Already quantum-safe | 14 |
| Critical severity | 18 |
| Peak exposure past Q-Day | 4.5 years |
| Source files read | 2,162 |
| Certificates parsed | 1,046 |
| Binaries analysed | 10 |
| Live endpoints probed | 1 |
| Scan duration | 7.8 s |
| CBOM validation | PASS — 77 components |
| Q-Day recalculation | ~100 ms full estate re-rank |
| External network requests | 0 |

## Sensitivity demonstration

Moving Q-Day from 2034 to 2030 and sensitivity to *restricted*:

| | Before | After |
|---|---|---|
| Peak exposure | 4.5 yr | **23.5 yr** |
| Severity spread (crit/high/med/low) | 18/1/42/16 | 18/24/19/16 |

23 assets move from medium to high.

## Scan performance

Time scales with per-file work. A full Python AST parse costs roughly five
times a regex pass, so Python-heavy targets are slower:

| Target | Files | Time | Rate |
|---|---|---|---|
| OpenSSL (mostly C) | 2,162 | 7.8 s | ~280 files/s |
| Django (mostly Python) | 3,043 | ~56 s | ~54 files/s |

## Accessibility

Both class palettes were validated with a perceptual colour checker rather than
chosen by eye:

| Theme | Deuteranopia | Tritanopia | Normal vision | Contrast |
|---|---|---|---|---|
| Light | 11.4 | 11.4 | 19.3 | pass |
| Dark | 14.8 | 18.2 | 21.0 | pass |

Class is never encoded by colour alone — every mark, row and key entry is also
labelled. Keyboard paths, focus rings, and a focus-trapped modal drawer with
focus restoration were implemented and audited.
