# Presentation script

**Status: script only. Nothing here has been recorded or rehearsed for you.**

This replaces an earlier draft that asserted specific national policy deadlines,
named competing products and quoted figures from a demo that no longer exists.
Every one of those was removed rather than rewritten, because none of them could
be verified from this repository. What is left is checkable: each number below
is produced by a command you can run, and the command is named.

Written for an eight-minute slot with four minutes of questions. If your slot is
shorter, the cut order is at the bottom.

---

## Before you walk in

```bash
.venv/bin/python run.py --preflight      # every path this script touches
.venv/bin/python run.py --demo           # build the estate, scan it, save the override
.venv/bin/python run.py                  # serve the console on 127.0.0.1:8000
```

`--preflight` must print **ALL CLEAR**. If anything is broken, `--demo-reset`
rebuilds the exact state this script assumes. `--preflight-offline` is the same
check with no network at all, which is what to run if the venue has no wifi.

Then:

1. **Browser tab 1** — `http://127.0.0.1:8000`, already showing the `demo-estate`
   scan. Never present from an empty console.
2. **Browser tab 2** — `submission/CryptoDrishti-SIH26164-Idea-Presentation.pptx`
   in presentation mode.
3. **Tab 3, minimised** — your recorded fallback, if you have made one.
4. **Second laptop** beside you with the same two tabs open.
5. Network cable in, loose enough to pull out in one motion.

One setting to decide during setup and not on stage: the **Dark / Light**
control, top right. The deck, the video and every screenshot in this repository
use the dark theme, so default to dark and switch to light only if the hall is
bright enough to wash it out. `?theme=dark` in the URL forces it, which is what
the capture script uses.

---

## The pitch, in three sentences

Say this to yourself before you go on. If the demo dies, this is the talk.

> Post-quantum migration is an inventory problem before it is a mathematics
> problem: NIST published the replacement algorithms in 2024, and an
> organisation still cannot migrate cryptography it cannot enumerate.
> CryptoDrishti reads source, dependencies, binaries, certificates,
> configuration and container images, and returns every cryptographic asset
> classified by what a quantum computer does to it — and, crucially, by how
> strong the evidence is that the asset is actually *used*.
> It runs offline on one machine and emits a CycloneDX CBOM that validates
> against the official schema.

---

## 0:00 – 0:40 — The hook

> *Slide 1. Do not introduce yourself yet. Deliver this cold.*

"Two things are true at the same time. The replacement cryptography is finished —
NIST published ML-KEM, ML-DSA and SLH-DSA in 2024. And almost nothing has moved.

Not because the mathematics is hard. Because nobody has the list."

*(beat)*

"I'm [name]. This is problem statement SIH26164, for the National Technical
Research Organisation, and we built the list."

> **Do not** claim a specific year by which anything must be done, and do not
> claim what other organisations are or are not able to do. You will be asked
> for a source, and there isn't one in this repository.

---

## 0:40 – 1:30 — Why there is no list

> *Slide 2.*

"Cryptography is not a component you can look up in a bill of materials. It is
smeared through everything: a hardcoded RSA call in a service written years ago,
a statically linked crypto library inside an appliance nobody has source for, a
signing key whose owner has left, a cipher list nobody has opened in years, a
private key baked into layer three of a container image and deleted in layer
four — where it is still extractable.

Six different places, six different kinds of evidence, and no single tool that
reads all six and tells you which findings are the same asset."

---

## 1:30 – 2:10 — The idea that makes it work

> *Slide 2, lower half. This is the part that is actually novel. Slow down.*

"Two ideas do the work.

**First: purpose, not keyword.** RSA is not one risk. RSA signing and RSA key
transport are the same algorithm and two completely different migrations — one
goes to ML-DSA, the other to ML-KEM — and they are urgent for different reasons.
Key establishment is urgent because traffic recorded today can be decrypted
later. Signatures are not retroactively forgeable, so the clock runs differently.
We resolve purpose from the call site, and when the evidence does not settle it,
we say so instead of guessing.

**Second: assurance.** There are four grades of evidence — capability, declared,
used, observed. A library in a manifest that *can* do RSA is not evidence that
RSA is used. Most tools flatten that. We keep it, because a migration plan
padded with libraries nobody calls is worse than no plan."

---

## 2:10 – 6:30 — Live demo

> *Switch to the console tab.*

### 2:10 — Pull the cable

*(Physically unplug the network cable and hold it up.)*

"Everything from here runs with no network. That is not a demo trick — a
cryptographic inventory is the most sensitive file an organisation owns, so the
tool is built to run where it cannot phone home."

### 2:20 — The scan that is already there

*(You are on the console, `demo-estate` loaded.)*

"This is a scan of a small service estate. Twenty-three distinct cryptographic
assets. Sixteen of them do not survive a quantum computer.

Look at the top of the inventory."

### 2:40 — The three RSAs  ← **the moment**

*(Section 05, Inventory. Point at the first three `rsa` rows in turn.)*

"Three RSA findings, in the same scan.

The first scores 100 and the recommendation is **ML-DSA-65**. It is a signing
call, in `svc-payments/signing.py`, line 15.

The second scores 74 and the recommendation is **X25519MLKEM768** — a hybrid key
exchange. Different algorithm entirely. It is RSA-OAEP in
`svc-gateway/transport.py`, line 16: key establishment, not signing.

The third scores 66 and the recommendation is *'Purpose must be resolved
first.'* We can see RSA is permitted, we cannot see what it is used for, and we
refuse to send an engineer down the wrong migration path.

Same algorithm. Three different answers. That is the whole argument for this
tool in one screen."

### 3:20 — Click into the evidence

*(Click the top row. The evidence drawer opens.)*

"Every finding opens onto what produced it: the file, the line, the symbol
matched, the detection technique, a confidence score, and the assurance grade.

Below that, the exposure arithmetic — every input, and where each input came
from: observed, derived, operator-supplied, or a default. An operator can
disagree with any of them, and see the disagreement."

### 3:50 — The operator override

*(Point at the assessment inputs in the drawer.)*

"This asset has been overridden by hand. Somebody decided this key protects data
with a twenty-five year secrecy requirement, marked it restricted, and recorded
that it is hardware-backed. That is stored against the asset, not against the
scan — so it survives rescanning, and it survives somebody editing the file
above it and changing every line number."

### 4:20 — Q-Day is a scenario, not a prediction

*(Section 03, Exposure window.)*

"Mosca's inequality. X is how long the data must stay secret. Y is how long
migration takes. Z is years until a quantum computer exists. If X plus Y is
greater than Z, data you seal today is readable by someone recording it now.

Nobody knows Z, so we do not assert it. It is a triangular distribution over
three years the operator chooses, and both its peak and its median are reported,
because they are not the same year and quoting one as the other is how this kind
of analysis goes wrong.

Every probability on this screen says what it is conditional on."

### 4:50 — Partial scans are labelled

*(Section 06, Scan history.)*

"This scan is marked **PARTIAL**, and it says why: one endpoint was refused by
the network policy. The operator pointed it at a link-local metadata address and
the tool declined.

A partial scan presented as a complete inventory is the single most damaging
thing this tool could produce, so it cannot happen silently. The flag travels
into the console, the report and the CBOM."

### 5:20 — The container image

*(Reopen the `checkout-service:2.4` scan from history.)*

"Second scan, same tool: a container image archive, read layer by layer without
extracting anything to disk. Fifteen assets, nine quantum-vulnerable.

The interesting one is a private key written in one layer and deleted in the
next. The image says it is gone. It is not gone — it is still in the archive,
and anyone who pulls the image can read it. We report it as **historical**:
present in the artefact, not present at runtime. That distinction is the
difference between a rotated key and a leaked one."

### 5:50 — The standard

*(Section 06, Machine-readable output. Click **Validate**.)*

"Output is a CycloneDX CBOM — ECMA-424. Validating right now, offline, against
the official JSON Schema, which is vendored in this repository at a pinned
commit so the check cannot drift.

Pass. And the version selector does 1.6 or 1.7 — both genuinely schema-valid,
not a version string changed in a header."

*(Click **Download CBOM**. Then **Open report**, scroll once, close it.)*

"Machine-readable for the tooling. And the same scan produces a self-contained
HTML report for the people who sign the budget — every finding, not a top-ten,
with its evidence and a stated limitations section."

### 6:15 — Plug the cable back in

*(Reconnect.)*

"And when the operator explicitly names an endpoint they are authorised to test,
there is a seventh sensor that completes a real TLS handshake and reports what
was actually negotiated — which is the only way to know whether a server is
using post-quantum key exchange. It refuses anything the operator has not named."

---

## 6:30 – 7:20 — What we can prove

> *Slide 4.*

"Three things you can check rather than take on faith.

**It is tested.** 664 automated tests, running in CI on Python 3.11, 3.12 and
3.13.

**Its accuracy is measured, and the measurement is committed.** There is a
hand-labelled corpus in this repository — 116 findings across six scanners,
labelled by reading the fixtures, not by running the tool. Over that corpus the
current build gets precision 1.000 and recall 1.000.

And the honest half of that sentence: it is a corpus we wrote. It is not an
estimate of accuracy on real enterprise code, which we have never measured and
do not claim. What the benchmark did do is find seven real defects in our own
detectors, which is why we built it.

**Its output is checked against the standard**, not against our own idea of the
standard. CI fails on a schema violation."

---

## 7:20 – 8:00 — Close

> *Slide 5, then slide 6.*

"What this changes: it turns 'we think we use RSA somewhere' into a per-asset
list with a file, a line, a purpose, an evidence grade and a named replacement —
and it separates what an estate runs from what it merely has installed.

It runs on one machine, offline, with no cloud account and no agent.

Everything I showed you came from one command. Thank you — questions."

---

## Numbers you may quote, and where each comes from

Say nothing in this table that you have not seen print on your own machine.

| Figure | Value | Command that produces it |
|---|---|---|
| Assets in the demo estate | 23, of which 16 quantum-vulnerable | `run.py --demo` |
| Assets in the container image | 15, of which 9 quantum-vulnerable | `run.py --demo` |
| Benchmark, current corpus | TP 116 / FP 0 / FN 0 — P, R, F1 all 1.000 | `python -m benchmark.run` |
| Benchmark, purpose | 114 / 114 correct, 2 excluded as ambiguous | `python -m benchmark.run` |
| Benchmark, like-for-like | F1 0.9405 → 0.9825 on the original corpus | `benchmark/results/*.json` |
| Automated tests | 664 | `python -m pytest` |
| Source rules | 60 rules; 8 languages with specific rules, plus Python's real AST | `app/knowledge/rules_source.py` |
| Binary detection | 72 symbols, 8 constants, 9 version patterns — ELF only | `app/knowledge/rules_binary.py` |
| Schema pin | CycloneDX schemas at commit `0bd48c8` | `app/schemas/cyclonedx/PROVENANCE.md` |

**Do not quote** a national deadline, a regulatory milestone, a date by which a
quantum computer will exist, a market size, a price, a latency figure, or what
any other product can or cannot do. None of those are established anywhere in
this repository, and the panel is the wrong audience to guess in front of.

---

## If something breaks

| Problem | Do this |
|---|---|
| Scan hangs or errors | The console already holds two completed scans. Say "here is a completed run" and open it from history. Never wait for a spinner on stage. |
| Console will not load | Second laptop. It is already open. |
| Both laptops fail | Your recording, if you made one. Narrate over it in the same words. |
| Projector loses the browser | Keep talking through the slides. The argument stands without the demo. |
| You are asked for a source you do not have | "I don't have a citation for that in front of me, so I won't assert it." Then move on. This is a correct answer. |

### Cut order, if your slot is shorter

Cut from the bottom up: the network sensor beat (6:15), then the container image
(5:20), then the report (5:50, keep the CBOM validation).

**Never cut** the three RSA rows at 2:40 or the CBOM validating as PASS. Those
two beats are the demonstration.
