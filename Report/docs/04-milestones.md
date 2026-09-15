# Milestone Log

A chronological record of the build. Timestamps are from the checkpoint
directories preserved in `snapshot/design-history/`.

---

## Phase 0 — Domain research and problem selection

**Objective.** Understand SIH26164 well enough to build something a
cryptographer would respect, starting from no prior knowledge of post-quantum
cryptography.

Ground covered:

- **Shor's algorithm** — polynomial-time factoring and discrete logarithms.
  Ends RSA, Diffie–Hellman, ECDH and ECDSA outright.
- **Grover's algorithm** — quadratic speed-up on unstructured search. Halves
  the effective strength of symmetric ciphers and hashes.
- **Harvest-now-decrypt-later** — the reason an inventory cannot wait for the
  hardware to exist.
- **Mosca's inequality** — `X + Y > Z`. The standard formulation of the risk.
- **The standards landscape** — FIPS 203/204/205 (Aug 2024), FIPS 206 draft,
  HQC selection (Mar 2025), NIST IR 8547 deprecation dates, CycloneDX 1.6 /
  ECMA-424, CNSA 2.0, RFC 8554/8391.
- **The Indian mandate** — DST / National Quantum Mission with CERT-In,
  *Implementation of a Quantum Safe Ecosystem in India* (Feb 2026). The
  operative line: **cryptographic inventories across defence, power, telecom
  and BFSI by December 2027.**

**Outcome.** Identified that the December 2027 mandate exists and no tool
produces the inventory it requires. That gap became the pitch.

---

## Phase 1 — Planning and constraints

Constraints fixed before any code was written, and never relaxed:

| Constraint | Rationale |
|---|---|
| Zero external requests | The tool targets classified environments. The air-gap guarantee had to be literal and demonstrable. |
| No build step, no framework | Nothing that can fail to compile the night before a presentation. |
| Scan a real open-source project | A prepared corpus proves nothing. |
| Every finding carries evidence | File, line, matched symbol, technique, confidence — auditable by a reviewer. |
| Product name in one constant | `config.PRODUCT_NAME`, so renaming later is a one-line change. |

Build order was chosen so that **every stage ended with something runnable** —
if a later stage slipped, there was still a demonstrable tool.

---

## Phase 2 — The spine

Models, the algorithm knowledge base, the first scanner, the risk engine, the
CBOM emitter and a CLI.

- `models.py` — `Evidence`, `Finding`, `ScanTarget`, `ScanResult`
- `knowledge/algorithms.py` — **52 algorithms** across 29 families, each with
  quantum class, classical strength, NIST level, OID, key and signature sizes,
  and deprecation dates
- `scanners/source.py` — Python `ast` parsing plus a curated rule pack
- `engine/risk.py` — quantum classification and the Quantum Risk Score
- `cbom.py` — CycloneDX 1.6 emitter

**Verified by:** `python -m app.cli scan <path>` printing findings and writing
a structurally valid CBOM.

---

## Phase 3 — The web surface

FastAPI application with a browser console: scan trigger, findings table,
summary figures, filters, detail drawer and the Q-Day control.

This stage received disproportionate time on purpose — it is what a jury sees.

---

## Phase 4 — The remaining five sensors

Added in order of independent value, so slipping the last one cost nothing
structural:

1. **Certificates** — X.509 parsing for key type, size, validity, signature
2. **Dependencies** — manifests resolved to library crypto capability
3. **Configuration** — TLS, SSH and IPsec parameters as deployed
4. **Binary** — ELF symbol tables plus verified crypto constant matching
5. **Network** — live TLS handshake including hybrid PQC group detection

---

## Phase 5 — Recommendations and export

- Constrained recommender across **four deployment profiles**, reasoning about
  real byte sizes rather than looking up a table
- CBOM download and live structural validation
- Printable HTML assessment report

---

## Phase 6 — Correctness work

The most important phase, and the one that separates the project from a demo.
Detailed in `07-engineering-decisions.md`. In summary:

- Recomputed every cryptographic constant from first principles and matched
  them against a real `libcrypto` binary — **found two hex typos in our own
  tables** that would have caused silent false negatives
- Removed a 4-byte DES signature that matched 32 unrelated system binaries
- Removed an unverified Kyber constant table
- Fixed a certificate-scanner crash on post-quantum test certificates
- Made the network sensor three-state rather than claiming "classical only"
  when it had never actually tested

---

## Phase 7 — Performance

| Problem | Fix | Result |
|---|---|---|
| Q-Day control returned all findings on every change | Return deltas only (`order` + `deltas`) | 1.8 s / 516 KB → **35 ms / 40 KB** |
| Renderers forced a style read per mark | Memoised design-token lookups | Eliminated layout thrash |
| Slower earlier replies could overwrite newer state | Sequence-numbered requests | Correct final state under fast dragging |

---

## Phase 8 — Demo hardening

- **`--preflight`** — 15 self-checks: database, seeded scan, CBOM validity,
  Q-Day round trip, demo repositories, binary target, air-gap grep, presenter
  kit, live probe availability. Reports **ALL CLEAR** or names what is wrong.
- **`--demo-reset`** — wipes and re-seeds the exact state the script expects,
  in one command, so recovering from a mid-rehearsal mess is not a sequence of
  remembered steps.
- Air-gap verification by grep across all web assets: zero external hosts.

---

## Phase 9 — Presenter kit

- `presenter/script.md` — an 8:00 timed script with every click named
- `presenter/qa.md` — Q&A cheat sheet with a verified numbers table
- `deck/index.html` — offline slide deck
- `docs/playbook.html` — the working playbook explaining the whole project

---

## Phase 10 — Interface, fourteen iterations

Recorded separately in `05-design-evolution.md`. Ten distinct designs were
built and checkpointed between 17:21 and 01:49; four were approved and kept,
the rest were rejected and preserved for reference.

---

## Phase 11 — Final capabilities

- **Folder browser** — a server-side directory picker so the tool can be aimed
  at anything on the machine, with each folder labelled by what it looks like.
  Still entirely offline.
- **Live scan progress** — every scanner reports as it works; percentage
  advances continuously, a detail line reads the real file count, and a
  server-side tick lets the console distinguish *slow* from *stalled*.

---

## Phase 12 — Presentation

Delivered. **Positive feedback received, and a point of contact offered for an
internship.**
