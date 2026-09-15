# Problem and Context

## The problem statement

**SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**
Issued by the **National Technical Research Organisation (NTRO)**
Theme: Blockchain & Cybersecurity · Category: Software

Five clauses, each a hard requirement:

| # | The clause asks for | How it was answered |
|---|---|---|
| i | Discover cryptographic assets across an enterprise | Six independent sensors, each reading a different surface |
| ii | Analyse and classify by quantum vulnerability | 52-algorithm knowledge base, five exposure classes |
| iii | Quantify risk and prioritise remediation | Quantum Risk Score plus Mosca over a Q-Day distribution |
| iv | Recommend post-quantum alternatives by risk, latency and cost | Constrained recommender using real key and signature sizes |
| v | Output a standardised CBOM and an interactive GUI | CycloneDX 1.6 / ECMA-424 with live validation, plus the console |

---

## The cryptography

**Shor's algorithm** (1994) factors large integers and solves discrete
logarithms in polynomial time. That destroys RSA, Diffie–Hellman, ECDH and
ECDSA outright — not weakens them, ends them.

**Grover's algorithm** (1996) gives a quadratic speed-up on unstructured
search, halving the effective strength of symmetric ciphers and hashes.
AES-128 drops to roughly 64 bits and must become AES-256.

**Harvest now, decrypt later.** An adversary does not need a quantum computer
today to benefit from one tomorrow — they record encrypted traffic now and
decrypt it when the machine arrives. Any data whose secrecy must outlive Q-Day
is *already* compromised. This is why an inventory cannot wait for the
hardware.

**Mosca's inequality.** If `X + Y > Z` — where **X** is how long the data must
stay secret, **Y** is how long migration takes and **Z** is the years until a
quantum computer exists — then data recorded today is readable before migration
completes.

---

## The standards landscape

| Standard | Status |
|---|---|
| FIPS 203 — ML-KEM | Final, August 2024 |
| FIPS 204 — ML-DSA | Final, August 2024 |
| FIPS 205 — SLH-DSA | Final, August 2024 |
| FIPS 206 — FN-DSA (Falcon) | Draft |
| HQC | Selected March 2025 |
| NIST IR 8547 | RSA-2048 and ECC P-256 **deprecated 2030, disallowed 2035** |
| CycloneDX 1.6 | Standardised as **ECMA-424** |
| CNSA 2.0 | NSA suite for national security systems |
| RFC 8554 / 8391 | LMS / XMSS stateful hash-based signatures |

---

## The Indian mandate

Not speculative policy. The DST / National Quantum Mission report
*Implementation of a Quantum Safe Ecosystem in India* (February 2026, with
CERT-In) sets a dated national timeline:

| By | Requirement |
|---|---|
| December 2026 | PQC certification labs established |
| **December 2027** | **Cryptographic inventories across defence, power, telecom and BFSI** |
| December 2028 | Priority migration begins |
| December 2029 | Full PQC transition |

TEC, BIS and MeitY act as nodal bodies.

**The December 2027 line is the whole argument.** A cryptographic inventory
across four national sectors is a mandate with a date attached, and no tool
exists to produce one. That gap is what this project fills.
