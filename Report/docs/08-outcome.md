# Outcome

## Result

Presented at the Smart India Hackathon 2026 internal round.

**Positive reception. A point of contact was offered for an internship.**

---

## What was delivered

| Deliverable | State |
|---|---|
| Working tool | Complete — six sensors, risk engine, recommender, CBOM emitter, browser console |
| Real-target validation | Scanned OpenSSL, Django, Paramiko and Apache Shiro — never a prepared corpus |
| Standards conformance | CycloneDX 1.6 / ECMA-424, validated live |
| Air-gap operation | Zero external requests, demonstrated by unplugging the cable |
| Presenter kit | 8:00 timed script, Q&A sheet, offline slide deck |
| Self-check | `--preflight`, 15 assertions, ALL CLEAR |
| Recovery | `--demo-reset`, one command back to a known state |
| Documentation | Working playbook, presentation build kit, and this report |

---

## Scope built, against scope planned

Everything in the original plan was delivered, plus work added along the way:

**Planned and delivered** — models and knowledge base, source scanner, risk
engine, CBOM emitter, CLI, web console, all six sensors, recommendation engine,
export, demo hardening, presenter kit.

**Added beyond plan**

- Server-side folder browser, so the tool can be aimed at any directory on the
  machine rather than a fixed list
- Live per-file scan progress with genuine stall detection
- Preflight self-check suite
- One-command demo restoration
- Ten checkpointed interface designs with a restore script
- Colour-blind validation of both palettes with a perceptual checker
- Accessibility work: keyboard paths, focus rings, focus-trapped modal drawer

---

## Honest assessment

**What went well.** The correctness work — recomputing crypto constants from
first principles and finding two errors in our own reference data — is the part
of the project that would survive scrutiny from a cryptographer. Modelling
Q-Day as a distribution rather than asserting a date, and reporting exposure in
years rather than a severity label, gave the demonstration a moment that landed.

**What was costly.** The interface took ten iterations. Several were rejected
for reasons that were predictable in advance: matching the register of the
subject matter, and not mistaking decoration for design. Screenshotting each
build rather than reasoning about it in the abstract is what eventually made
progress reliable, and should have started earlier.

**What is unfinished.** No collector agent for remote hosts — the network
sensor probes endpoints but nothing gathers from a fleet. Detection for the
nine non-Python languages remains regex-based, with the precision cost stated
openly rather than hidden. Dynamic and reflective crypto calls are reported as
`Unresolved` rather than resolved.

---

## If this continues

In rough order of value:

1. **Collector agent** — gather from a fleet of hosts into one inventory,
   which is what "enterprise" in the problem statement ultimately requires.
2. **tree-sitter parsing** for the non-Python languages, lifting precision to
   match the Python path.
3. **Differential scanning** — track an estate over time and report migration
   progress, which is what turns a snapshot into a programme.
4. **CI integration** — fail a build that introduces a newly deprecated
   algorithm.
5. **Signed CBOM output** for chain-of-custody in an accredited environment.
