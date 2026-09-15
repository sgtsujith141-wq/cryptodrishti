# Q&A cheat sheet — 4 minutes, roughly 5 questions

Print this. Hold it. Answers are written to be said in **20 seconds** — answer,
then stop. Rambling invites a follow-up you cannot answer.

Three rules:
1. **Answer, then stop.** Silence after a short answer reads as confidence.
2. **"I don't know, here's how I'd find out"** beats a bluff. This panel can
   smell one.
3. **Never disparage the incumbents.** IBM wrote the CBOM standard and we
   conform to it. Our claim is about the four layers above it.

---

## The five most likely

### "How is this different from IBM's CBOMkit? It already exists and it's free."

"CBOMkit is source-centric — hyperion is a SonarQube plugin, so it needs source
and a supported language. It's weak on stripped binaries and vendor firmware,
which is exactly where critical infrastructure lives. It produces an inventory,
not a prioritised plan: no Mosca scoring, no business-criticality weighting. And
it has no mapping to Indian regulatory milestones. We use its CBOM schema —
that's the right standard — and build the layers above it."

### "What's your false positive rate?"

"We don't have a measured number yet, and I won't invent one. What we do have
is a confidence score on every finding, surfaced in the CBOM's evidence field,
and anything we can't resolve statically is reported as *unknown* rather than
guessed. Building a hand-labelled benchmark corpus and publishing precision and
recall per detector is the top item on our roadmap to the Grand Finale."

> This is the answer that wins the room *because* it is honest. Do not
> fabricate a number — a cryptographer will ask how you measured it.

### "What happens with an obfuscated or stripped binary?"

"Layered fallback. First, ELF symbol tables — we parse the section headers
directly. If it's stripped, cryptographic constants via byte-pattern matching:
AES S-boxes and SHA-256 round constants are data, so they survive stripping. If
those are obfuscated too, we report an unresolved region and flag it for manual
review. We never claim certainty we don't have."

### "How do you justify your Q-Day estimate? Nobody knows when that is."

"We don't assert one — that's the point. Z is a distribution, not a constant.
We run a Monte Carlo over an expert-elicited range and report the probability
of exposure, and the range is configurable per deployment, because a defence
estate and a retail bank shouldn't use the same assumption. Any tool that
hardcodes a Q-Day is bluffing."

### "Is this a real product or a hackathon project?"

"Today it's a working tool that scans real codebases — what you saw was
OpenSSL, unmodified, scanned live. It's not yet been run against a production
estate. Between now and the Grand Finale we're adding container scanning, the
asset graph, and a pilot against our campus network."

---

## Also likely

**"Your source scanner uses regex for Java and C. Isn't that fragile?"**
"For Python we use the real AST. For other languages it's a curated rule pack
with per-rule confidence, and comment lines are stripped first. It's less
precise than full parsing and we say so — that's why every finding carries a
confidence score. Full tree-sitter parsing is on the roadmap."

**"A private key in a test fixture isn't a real finding."**
"Agreed, and we handle that. Findings are weighted by where the evidence lives
— production, vendored, or test. A test fixture is inventoried but weighted
down so it never heads the remediation queue. You can filter to production-only
in the interface."

**"How do you handle cryptography inside a cloud KMS or an HSM you can't see?"**
"We enumerate at the boundary — key specs and rotation policy from read-only
KMS APIs, slot and mechanism lists over PKCS#11 — and label it as
boundary-level evidence with lower confidence. Pretending to see inside an HSM
would be dishonest. That sensor is on the roadmap, not shipped today."

**"What if the code uses a custom crypto wrapper?"**
"That's the number-one blind spot of every rule-based scanner, and we detect it
explicitly — a `getInstance` call with a non-literal argument is reported as
'algorithm selected at runtime' for manual review rather than skipped silently.
We also match framework wrapper classes directly. Classifying wrapper bodies
with a local model is the next step."

**"You've just built a map of every weak crypto asset in an organisation.
What if it leaks?"**

> **Raise this yourself on the impact slide if nobody asks it.**

"It's the most sensitive file the organisation owns, so it's treated that way:
air-gapped deployment with zero egress, everything vendored locally, and no
outbound call anywhere in the codebase. RBAC, encryption at rest and signed
reports are the next hardening step."

**"Why should NTRO use this instead of buying a commercial tool?"**
"Because they can't. AQtive Guard and Keyfactor are cloud-tethered SaaS. On a
classified network the procurement question never gets asked, because the tool
cannot be installed. Sovereignty here is not a preference, it's a constraint."

**"How long does it take on a large estate?"**
"Seventy-seven assets from two thousand one hundred detector hits across the
OpenSSL codebase in about twelve seconds on this laptop — all six sensors,
including a live TLS probe. It's parallelised per file with a configurable
file cap."

**"What does a non-technical stakeholder actually get out of this?"**
"An executive report from the same scan — exposure in years, the migration
programme grouped by target algorithm with effort estimates, and an explicit
limitations section. The CBOM is the machine-readable half for compliance
submission; that report is the half a director reads."

**"What's the business model / who maintains it?"**
"It's open source. The natural home is a CERT-In or TEC reference tool, because
the December 2027 mandate applies to hundreds of operators who all need the
same thing and cannot each buy a foreign licence."

---

## If you genuinely don't know

Say exactly this:

> "I don't know that off the top of my head. What I can tell you is how we'd
> determine it: [one sentence]. I'd rather check than guess."

Then stop. That answer loses you nothing. A bluff loses you the room.

---

## Numbers to have on the tip of your tongue

| Thing | Number |
|---|---|
| Assets found in OpenSSL scan | 77, from 2,102 detector hits |
| Already quantum-safe | 15 of 77 |
| Severity split | 18 critical / 1 high / 42 medium / 16 low |
| Quantum vulnerable | 58 (75%) |
| Scan time, all six sensors | ~12 seconds (2,162 source files, 1,046 cert files, 1 live endpoint) |
| Q-Day slider 2034 → 2030 | peak exposure 4.5 → 23.5 years; 23 assets medium → high |
| CBOM components validated | 77, CycloneDX 1.6, PASS |
| ECDSA P-256 signature | 64 bytes |
| ML-DSA-65 signature | 3,309 bytes — 50× larger |
| ML-KEM-768 public key | 1,184 bytes |
| India inventory deadline | December 2027 |
| India full PQC adoption | December 2029 |
| NIST disallows RSA-2048 | after 2035 |
| FIPS 203 / 204 / 205 | ML-KEM / ML-DSA / SLH-DSA |
