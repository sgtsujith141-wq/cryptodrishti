# Technical Q&A

Answers written to be said in about twenty seconds. Answer, then stop.

Three rules:

1. **Answer, then stop.** Silence after a short answer reads as confidence.
2. **"I don't know, and here is how I'd find out"** beats a bluff. This panel
   can smell one.
3. **Never characterise a product you have not measured.** If you are asked to
   compare against a named tool, describe what *this* tool does and say you
   have not benchmarked theirs. An earlier draft of this file asserted what
   three commercial products could and could not do; none of it was verifiable
   and all of it has been removed.

---

## The likely five

### "What is your false positive rate?"

"Measured, on a corpus we hand-labelled: zero false positives and zero false
negatives over 116 findings across six scanners — precision and recall both
1.000.

And the caveat that has to travel with that number: it is a synthetic corpus
that we wrote. It is not an estimate of accuracy on real enterprise code, which
we have never measured. What the benchmark is genuinely good for is regression —
it found seven real defects in our own detectors, and CI now fails if precision
or recall drops."

> If pressed on whether the corpus was tuned to the tool: the ground truth was
> written by reading the fixtures, not by running CryptoDrishti. Where labels
> were corrected, the correction, its justification and its effect on the score
> are recorded in the manifest's changelog. Offer to show it.

### "How do you know an algorithm is actually used, not just available?"

"That is the assurance field, and it is the thing I would point at first. Four
grades: **capability** — a library in a manifest that could do it; **declared** —
a configuration file that permits it; **used** — a call site; **observed** — a
live handshake or a key we read directly.

A dependency manifest gives you capability, and capability never silently
becomes used. Cross-sensor correlation links findings that share a concrete
artefact, and it is explicitly forbidden from promoting assurance or raising
confidence — correlation is evidence that two sensors saw the same thing, not
evidence that the thing is more certain."

### "RSA is RSA. Why does purpose matter?"

"Because it decides both the target and the urgency.

RSA doing key establishment migrates to ML-KEM, and it is urgent today, because
traffic captured now can be decrypted once a quantum computer exists. RSA doing
signing migrates to ML-DSA, and it is not retroactively forgeable — a signature
made today cannot be forged backwards, so the clock is different.

We resolve purpose from the call site. When the evidence does not settle it — a
cipher list that permits RSA without saying what for — we report
'purpose must be resolved first' rather than recommending the wrong migration.
Sending an engineer down the wrong path costs more than saying we don't know."

### "How do you justify a Q-Day estimate? Nobody knows when that is."

"We don't assert one. Z is a triangular distribution over three years the
operator picks — earliest, most likely, latest — and the tool reports both the
mode and the median, because for the default scenario those are two different
years and quoting one as the other is exactly how this analysis goes wrong.

The exposure probability is a seeded simulation over that distribution, so it is
reproducible, and every figure derived from it carries the sentence saying what
it is conditional on. A tool that hardcodes a Q-Day year is asserting something
nobody knows."

### "What happens with a stripped or obfuscated binary?"

"Layered, and honest about where the layers stop. First ELF symbol tables, parsed
directly. If it is stripped, cryptographic constants — S-boxes and round
constants are data, so they survive stripping — and version banners. If those are
obfuscated too, we do not claim a detection.

The limits, plainly: it is ELF only, so Mach-O and PE are out of scope today,
and obfuscated call sites are a known gap in the source scanner as well. Both
are written down as limitations rather than glossed."

---

## Also likely

**"Your scanner uses patterns for languages other than Python. Isn't that fragile?"**

"For Python we use the real AST. Seven other languages — C, C#, Go, Java,
JavaScript, PHP and Ruby — have curated rule packs with per-rule confidence,
and comments are stripped before matching. Rust and Swift are recognised but
only get the four language-agnostic rules, so I would call them uncovered
rather than supported. It is less precise than full parsing and every finding carries
a confidence score saying so. The benchmark corpus deliberately includes
crypto-shaped identifiers and prose that should *not* match."

**"A private key in a test fixture isn't a real finding."**

"Agreed, and it is weighted accordingly — evidence is weighted by where it
lives, so a test fixture is inventoried but never heads the remediation queue.
The thing I would rather you take away is the container case: a key deleted by a
later image layer is reported as historical, because it is still extractable
from the archive even though it is not on the running filesystem."

**"How do you handle cryptography inside a cloud KMS or an HSM?"**

"We don't, and the architecture diagram deliberately has no box for it. There is
no KMS, HSM, cloud or registry integration in this tool. Pretending to see
inside an HSM would be dishonest, and claiming an integration we have not built
would be worse. It is a reasonable next sensor; it is not a shipped feature."

**"What if the code uses a custom crypto wrapper?"**

"That is the standing blind spot of every rule-based scanner, and the honest
answer is that a wrapper whose algorithm is chosen at runtime is reported as
unresolved rather than skipped silently — which is why 'purpose must be resolved
first' is a first-class outcome in this tool rather than an error state. Classifying
wrapper bodies properly is not solved here."

**"You have just built a map of every weak cryptographic asset in an organisation.
What if it leaks?"**

> **Raise this yourself if nobody asks it.**

"It is the most sensitive file the organisation owns, so: it runs offline, binds
to loopback, and refuses to start on a non-loopback address without an access
token. Evidence is redacted before it reaches a CBOM or a report — the location
is kept, because that is what makes a finding actionable, but the secret itself
is not. There is a test that fails if a fixture secret reaches an export."

**"What stops it being pointed at something it shouldn't be?"**

"Two gates, and they are in the diagram. The filesystem boundary refuses symlink
escapes and vets every archive member, streaming under a size budget with nothing
extracted to disk. The network policy resolves a name, vets every address it
resolves to by property, and then connects to the vetted literal — so a name that
resolves to a mix of internal and external addresses is refused outright rather
than raced. The TLS sensor only ever probes an endpoint the operator names."

**"Is this a real product or a hackathon project?"**

"It is a working prototype with 664 tests and CI on three Python versions, and
it has not been run against a production estate. Everything in the demo is a
synthetic fixture we wrote, and I would rather say that than imply a pilot we
have not done."

**"What does a non-technical stakeholder get out of it?"**

"A self-contained HTML report from the same scan: exposure in years, the
migration programme grouped by target algorithm, every finding with its
evidence — not a top-ten — and an explicit limitations section. The CBOM is the
machine-readable half; the report is the half a director reads."

**"How long does a scan take?"**

"The demo estate and the container image both complete in seconds on a laptop.
I have not benchmarked it on a large estate, so I am not going to give you a
figure for one — there is a configurable file cap and a per-file parallel walk,
and that is as much as I can honestly say."

---

## If you genuinely don't know

> "I don't know that off the top of my head. What I can tell you is how we'd
> determine it: [one sentence]. I'd rather check than guess."

Then stop. That answer loses you nothing.

---

## Numbers to have ready

Every row is reproducible by the command or file named. Nothing else should
leave your mouth as a number.

| Thing | Value | Source |
|---|---|---|
| Demo estate | 23 assets, 16 quantum-vulnerable, scan **PARTIAL** | `run.py --demo` |
| Demo container image | 15 assets, 9 quantum-vulnerable, **COMPLETE** | `run.py --demo` |
| Benchmark, current corpus | 116 expected findings, 6 scanners, 4 negative files | `benchmark/manifest.json` |
| Benchmark result | TP 116 / FP 0 / FN 0 — precision, recall, F1 all 1.000 | `benchmark/results/after-m6.json` |
| Purpose accuracy | 114 / 114, with 2 excluded as genuinely ambiguous | same file |
| Assurance accuracy | 116 / 116 | same file |
| Like-for-like improvement | F1 0.9405 → 0.9825 on the unchanged original corpus | `baseline-382e7d1.json`, `after-m6-same-corpus.json` |
| Automated tests | 664, CI on Python 3.11 / 3.12 / 3.13 | `python -m pytest` |
| Discovery sensors | 7 | `app/scanners/` |
| Source rules | 60 rules, 10 languages, plus Python's real AST | `app/knowledge/rules_source.py` |
| Binary detection | 72 symbols, 8 constants, 9 version patterns, ELF only | `app/knowledge/rules_binary.py` |
| CBOM | CycloneDX 1.6 (ECMA-424) and 1.7, schemas pinned at `0bd48c8` | `app/schemas/cyclonedx/PROVENANCE.md` |
| ECDSA P-256 signature | 64 bytes | `app/engine/recommend.py` |
| ML-DSA-65 signature | 3,309 bytes | `app/engine/recommend.py` |
| PQC standards | FIPS 203 ML-KEM · FIPS 204 ML-DSA · FIPS 205 SLH-DSA, published 2024 | — |

**Not in this table, so not in your answer:** any national or regulatory
deadline, any date for a quantum computer, any market size, price, licence cost
or latency figure, and any statement about what a competing product does.
