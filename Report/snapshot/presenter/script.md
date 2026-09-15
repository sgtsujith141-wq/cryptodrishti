# Presentation script — 8:00 + 4:00 Q&A

You are presenting alone. Everything below is timed and every demo click is
named. Rehearse aloud with a timer at least four times; the timings only work
if you have actually said the words out loud.

**Setup before you walk in**

0. Sanity check, one command — it tests every path this script depends on:
   `./.venv/bin/python run.py --preflight`
   It must say **ALL CLEAR**. If anything is broken:
   `./.venv/bin/python run.py --demo-reset` rebuilds the exact demo state.


1. Terminal running (do this with network, *before* you present):
   `./.venv/bin/python run.py --seed --seed-path demo/targets/openssl --seed-endpoints www.google.com`
2. Browser tab 1: `http://127.0.0.1:8000` — console, already showing results
3. Browser tab 2: `deck/index.html` — press `F` for fullscreen, `P` for notes
3b. Pick the theme for the room with the **Dark / Light** control, top right.
    Light for a bright hall, dark for a dim one. Decide during setup, not on stage.
4. Ethernet cable plugged in but **loose enough to pull out in one motion**
4b. Optional: press **Explain** in the top right during rehearsal — it annotates
    every panel with what it means. Turn it **off** before you present; it is a
    learning aid, not part of the pitch. (Or open `?explain=1` to force it on.)
5. Fallback recording open in a third tab, minimised
6. Second laptop powered on beside you with the same two tabs open

---

## 0:00 – 0:50 — The hook

> *Slide 1. Do not introduce yourself. Deliver this cold.*

"Every encrypted message India sends today is being recorded by someone who
plans to read it in 2035."

*(one beat of silence)*

"That is not speculation. It is a documented intelligence practice called
harvest-now-decrypt-later. And not one organisation in this country can tell
you which of their systems are at risk — because nobody has a list."

*(beat)*

"We built the list. I'm [name], and this is problem statement SIH26164 for the
National Technical Research Organisation."

---

## 0:50 – 1:40 — The threat

> *Slide 2.*

"In 1994 Peter Shor showed that a quantum computer factors large numbers in
polynomial time. That breaks RSA, Diffie-Hellman, ECDH and ECDSA — not weakens
them, breaks them. A bigger key does not help.

Grover's algorithm only halves the strength of symmetric ciphers, so AES-256
survives. So the entire problem has one shape: **all public-key cryptography
falls, and public-key cryptography is what secures every TLS session, every
VPN, every digital signature and the whole of PKI.**

NIST published the replacements in 2024 — ML-KEM, ML-DSA, SLH-DSA. The
mathematics is solved. Almost nothing has migrated."

---

## 1:40 – 2:15 — Why nothing has migrated

> *Slide 3.*

"Because cryptographic migration is an **inventory problem before it is a
mathematics problem.**

Cryptography is not a product you buy. It is smeared through everything: a
hardcoded RSA call in a service written in 2011, a statically linked OpenSSL
inside vendor firmware, a signing key whose owner left the organisation, a
cipher list nobody has opened in six years. You cannot migrate an inventory you
do not have."

---

## 2:15 – 3:00 — The mandate

> *Slide 4. This is the most important slide. Slow down.*

"This is not hypothetical. In February 2026 the Department of Science and
Technology, under the National Quantum Mission and jointly with CERT-In,
published India's quantum-safe roadmap.

Certification labs by December 2026. Full post-quantum adoption by 2029 — six
years ahead of NIST's deadline. And in between, this:

**By December 2027, cryptographic inventories completed across defence, power,
telecom and banking.**

*(beat)*

Every critical infrastructure operator in India has fifteen months to produce a
cryptographic inventory. There is no sovereign tool that can produce one. The
tools that exist are foreign, commercial, and cloud-connected — which means
they cannot be deployed on the networks that need them most."

---

## 3:00 – 3:30 — What we built

> *Slide 5. Thirty seconds. Do not explain — you are about to show it.*

"Six sensors: source code, dependencies, binaries, certificates, configuration,
and live network probing. Their output is normalised into distinct
cryptographic assets, scored for quantum exposure, matched to a post-quantum
replacement, and emitted as a CycloneDX 1.6 CBOM — the international standard
for a cryptographic bill of materials.

Let me show you."

---

## 3:30 – 7:00 — LIVE DEMO

> *Slide 6, then switch to the console tab.*

### 3:30 — Pull the cable

*(Physically unplug the ethernet cable and hold it up.)*

"Everything you are about to see runs with no network. This is built for
air-gapped and classified environments, because that is where it is needed."

### 3:40 — The instrument

*(You are on the console. Point at the sensor array on the right.)*

"This is the whole tool on one screen. You aim it at a path and it fires six
sensors. Source — Python AST plus forty-nine curated rules across ten
languages. Dependency. Certificates. Configuration. Binaries — ELF symbol
tables and eight verified crypto constants. And a live TLS probe.

Nothing here is a heuristic guess dressed up as a finding. Every sensor tells
you what it read."

*(Click a preset — `openssl` — then press Run scan. The array lights up in
sequence and the elapsed clock runs. It lands in roughly eight seconds and
drops you into the record.)*

"Two thousand one hundred detector hits, grouped into **seventy-seven distinct
cryptographic assets**. Fifty-eight are quantum vulnerable. That is
seventy-five percent of the estate."

### 4:10 — The composition bar and the distribution

*(Point at the stacked bar under the headline figure, section 01.)*

"This is the whole estate in one bar. Red breaks outright under Shor's
algorithm — a third of it. Amber is weakened by Grover. Grey is what we could
not resolve statically and refuse to guess at. Green is already quantum-safe:
fifteen of the seventy-seven. This measures progress, not just debt.

Seventy-five percent of this estate does not survive a quantum computer."

*(Scroll to section 02, "Where the weight sits".)*

"A list would give a two-line finding and a three-hundred-site finding the same
row. A migration does not work that way. So here every asset is drawn at the
size of the work it is: area is call sites.

That block is RSA — three hundred and ten call sites. That one is unresolved
key material — two hundred and seventy-four. That is where the budget goes, and
you can see it without reading a single number."

*(Hover a block — the tooltip gives the algorithm, its risk, call sites and the
recommended replacement.)*

*(Point at the four figures in section 01.)*

"Seventy-seven assets, grouped from two thousand one hundred raw detections —
because an inventory that lists the same algorithm two hundred times is a log,
not an inventory."

### 4:40 — Click into a finding

*(Click any block in the map, or any row in the inventory, section 05.)*

"Click any asset and you get the evidence. File, line number, the exact matched
symbol, the detection technique, and a **confidence score**. Everything we
cannot resolve is reported as *unknown* rather than guessed — because in front
of cryptographers, a confident wrong answer is worse than an honest gap.

Below that: the Mosca calculation for this asset, every factor in the risk
score with its input value, and the recommended migration target."

### 5:20 — The Q-Day slider  ← **the moment**

*(Move to section 03, "Exposure window". Grab the Q-Day slider.)*

"This is Mosca's inequality. X is how long the data must stay secret. Y is how
long migration takes. Z is years until a quantum computer exists. If X plus Y
is greater than Z, data you seal today is readable by someone recording it now.

Nobody knows Z. So we do not assert it — we model it."

*(Point at the curve below the axis.)*

"That is the arrival distribution, not a date. The dashed line is the year
through which this data still has to be secret. The shaded area is the share of
that distribution landing before it — seventy-four percent. That is the number
you can actually defend in a review.

Watch the whole estate re-rank."

*(Drag the slider from 2034 down to 2030. Change sensitivity to `restricted`.
The curve slides left and the shaded area grows as you drag.)*

"If a quantum computer arrives in 2030 instead of 2034, and this is defence
data with a twenty-five year classification — exposure goes from four and a
half years to **twenty-three and a half**, and **twenty-three assets move from
medium to high**. That is the argument a CISO takes to a budget committee."

> Verified numbers: severity goes from 18/1/42/16 to 18/24/19/16
> (critical/high/medium/low), peak exposure 4.5 → 23.5 years.

### 6:00 — The standard

*(Scroll to section 06, "Machine-readable output". Click Validate.)*

"Output is a CycloneDX 1.6 CBOM — standardised as ECMA-424. Validating live:
**seventy-seven cryptographic-asset components, pass.**"

*(Click Download CBOM.)*

"That file is the deliverable the December 2027 mandate asks for."

*(Click Executive report — opens in a new tab. Scroll once, then close it.)*

"And for the people who sign the budget, the same scan produces this: exposure,
the migration programme grouped by target algorithm, and a stated limitations
section. Machine-readable for compliance, human-readable for the decision."

### 6:25 — Beyond source code

*(Switch preset to `system libraries (binary scan)`, run scan.)*

"One more thing. Source scanners only see source. Critical infrastructure runs
vendor firmware and appliances nobody has source for.

This is scanning compiled binaries — no source at all. We parse ELF symbol
tables and match cryptographic constants: AES S-boxes, SHA-256 round constants.
Those survive stripping, because they are data, not code."

*(Point at a result.)*

"Found AES, SHA-256, SHA-1, and the exact OpenSSL version, from a binary."

### 6:50 — Plug the cable back in

*(Reconnect ethernet. Switch to a terminal or the network scan.)*

"And with a network, it probes live endpoints. Google negotiates hybrid
post-quantum key exchange today — X25519 with ML-KEM-768. Most Indian
infrastructure does not. The TLS version does not tell you that; only the
negotiated group does."

---

## 7:00 – 7:40 — Differentiation and impact

> *Slides 7 and 9. Move fast.*

"IBM, SandboxAQ and Keyfactor all have tools. We conform to IBM's CBOM standard
— it is the right standard. But none of them can be deployed air-gapped, none
of them prioritise by Mosca, none of them produce a migration plan rather than
a list, and none of them will ever map to Indian regulation.

The inventory is the gate every other migration step waits behind. Removing it
moves the entire national timeline."

---

## 7:40 – 8:00 — Close

> *Slide 10.*

"Built against FIPS 203, 204 and 205, NIST IR 8547, CycloneDX 1.6, and the DST
National Quantum Mission roadmap. Open, sovereign, and deployable inside a
classified network today.

Thank you — I'll take questions."

---

## If something breaks

| Problem | Do this |
|---|---|
| Scan hangs or errors | The console already holds a completed scan. Say "here's a completed run" and keep going. Never wait for a spinner on stage. |
| Console will not load | Switch to the second laptop. It is already open. |
| Both laptops fail | Fallback recording, third tab. Narrate over it in the same words. |
| Projector loses the browser | Keep talking through the slide content — the argument stands without the demo. |
| You run over time | Cut the binary-scan beat (6:25) and the network beat (6:50). Never cut the Q-Day slider or the CBOM validation. |

**The two beats you must never cut:** the Q-Day slider, and the CBOM validating
as PASS. Everything else is negotiable.
