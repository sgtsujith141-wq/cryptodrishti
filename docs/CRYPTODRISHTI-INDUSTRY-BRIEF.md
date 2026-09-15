# CryptoDrishti
### Enterprise Cryptographic Discovery & Quantum-Risk Analysis
SIH26164 | NTRO | Blockchain & Cybersecurity | Prototype v0.9.0

## 1. What is CryptoDrishti?

CryptoDrishti scans a software estate — source trees, dependency manifests, binaries,
certificates and keys, cryptographic configuration, live TLS endpoints — and produces one
evidence-backed inventory of the cryptography in use. Each asset resolves against an
algorithm registry, is classified (Shor-broken, Grover-weakened, quantum-safe, hybrid or
unresolved), scored for migration urgency by Mosca's inequality, given a post-quantum
migration direction suited to its deployment profile, and emitted as a CycloneDX 1.6 CBOM.

PQC migration is gated on inventory: an organisation that cannot name its algorithms, key
sizes and certificate expiries cannot sequence or fund one. Traffic captured today is
decryptable later, so that ordering is a present-tense decision.

---

## 2. How It Works

```
 TARGET  filesystem path, or named TLS endpoints
   |
 DISCOVERY  6 independent sensors; one failing does not abort the scan
   |   source        Python `ast` parsing; regex rule packs for other languages
   |   dependency    manifests -> library crypto capability + PQC support
   |   binary        ELF symbol tables, crypto constants, version banners
   |   certificate   X.509 PEM/DER, PKCS#12, private keys, PQC OIDs
   |   config        nginx, Apache, sshd, openssl.cnf, java.security
   |   network       live TLS versions + hybrid-PQC group negotiation
   |
 NORMALISATION  hits merged into assets, evidence pooled, paths weighted
   |
 CRYPTO ASSET INVENTORY  <- 52-algorithm registry
   |
 QUANTUM RISK  Mosca X+Y>Z over a Q-Day distribution
   |
 PRIORITISATION  transparent score, every factor exposed
   |
 MIGRATION GUIDANCE  profile-aware target, size delta, library support
   |
 CBOM (CycloneDX 1.6) + HTML report
```

No container or image scanning. No outbound connections except operator-named endpoints.

---

## 3. What We Have Built

| Capability | What it does | Status |
|---|---|---|
| Source detection | Python: real `ast` pass resolving `key_size=2048`, `ec.SECP256R1`, pyca/cryptography hazmat idioms. Others: 49 rules, dedicated packs for 8 languages plus 4 cross-language. Resolvers decompose `AES/ECB/PKCS5Padding` into algorithm, mode and padding, not a keyword hit. | Working; regex precision below AST |
| Knowledge base | 52 algorithms, 29 families: quantum class, classical strength, NIST level, OID, key/signature/ciphertext sizes, IR 8547 deprecation dates. Served over the API. | Working |
| Dependency analysis | 13 manifest types across 8 ecosystems (pip, npm, Maven, Gradle, Go, Cargo, Composer, Bundler) mapped to 22 crypto libraries and their minimum PQC-capable versions. | Working |
| Binary analysis | Own ELF section parser reading `.dynstr`/`.strtab`; 72 symbols, 8 constant signatures, 9 version banners. PE and Mach-O degrade to string matching at reduced confidence, and report that. | Partial |
| Normalisation / inventory | Hits merged into distinct assets with pooled evidence; paths weighted production 1.0 / vendored 0.75 / test 0.40, so fixtures are inventoried without heading the queue. | Working |
| Quantum-risk engine | Mosca with Q-Day Monte-Carlo sampled: exposure years at the median plus probability of exposure. Score is a product of named factors — class base, disallowance dates, blast radius, confidence — each shown beside its input. | Working |
| Recommendation engine | Four profiles (general, high-assurance, constrained/IoT, firmware signing). Reasons about real size deltas (ECDSA P-256 64 B -> ML-DSA-65 3,309 B), names library support, and returns "manual review required" rather than guess. | Working; expert rules, unvalidated |
| CBOM | CycloneDX 1.6 (ECMA-424) `cryptographic-asset` components with `cryptoProperties`, `evidence.occurrences` and `evidence.identity` confidence. Validator covers required fields, enums and `bom-ref` uniqueness — not full JSON-Schema, and says so. | Working |
| Dashboard / API / CLI | FastAPI, 11 API routes, threaded scans with live progress; offline single-page console in dependency-free vanilla JS; CLI emits a validated CBOM. | Working |
| Evidence / provenance | Every finding carries file, line, symbol, snippet, technique and confidence, carried into the CBOM. | Working |

---

## 4. Quantum-Risk Approach

Mosca's inequality: **X + Y > Z** — X the required confidentiality lifetime, Y the time to
migrate, Z the time to a cryptographically relevant quantum computer. If it holds, data
sealed today is exposed.

X comes from a sensitivity tier (25 / 10 / 5 / 1 years). Y is estimated per surface: a
config change is cheaper than a vendor binary. Z is not asserted — it is a triangular
distribution (default 2030 / 2034 / 2044, operator-adjustable) sampled by Monte Carlo, so
each asset carries a probability of exposure as well as exposure years at the median.

We do not claim to predict when a quantum computer will arrive. Z is the operator's input;
the tool shows how the ranking moves when it changes.

---

## 5. Example Result

| | |
|---|---|
| Target | OpenSSL (`demo/targets/openssl`, commit `5ce57ab`) |
| Files scanned | 2,162 source · 1,046 certificate · 119 config · 10 binaries · 0 manifests |
| Raw detector hits | 2,098 |
| Cryptographic assets | 73 |
| Quantum-vulnerable | 55 (75.3%) |
| Example finding | RSA-2048 X.509 certificate, `apps/client.pem`, 260 occurrences, score 85.3 (critical); also an MD5-signed certificate at `apps/cert.pem`. |
| Example recommendation | Hybrid `X25519MLKEM768` key establishment, enabled in TLS configuration rather than application code; support: OpenSSL 3.5+, Chrome, Firefox, AWS-LC. |
| Scan time | 8.0 s warm cache (25 s cold first pass over the 200 MB tree) |
| CBOM | 73 components, CycloneDX 1.6 structural validation PASS |

Moving the Q-Day median from 2034 to 2030 at *restricted* sensitivity moves 23 assets into
the high band and raises maximum exposure from 4.0 to 23.0 years. Separately verified: the
live TLS sensor negotiated `X25519MLKEM768` against a public endpoint, recording it as
already migrated.

**Prototype assessment — not an enterprise benchmark.**

---

## 6. Why This Is More Than a Crypto Scanner

DISCOVERY → EVIDENCE → INVENTORY → QUANTUM RISK → PRIORITISATION → MIGRATION GUIDANCE

A grep-class tool answers "what cryptography are we using?". We care about the next two
questions: which assets to migrate first, and what they migrate to. That needs an inventory
unit coarser than a call site, a risk model whose inputs an operator can argue with, and
recommendations that account for what the deployment can carry.

---

## 7. Current Limitations

- **No automated test suite.** Verification is a preflight harness against a running server
  plus manual scans of four real repositories. No labelled corpus, so precision and recall
  are unmeasured, and we will not invent a figure.
- **Non-Python detection is regex, not parsing**, so precision trails the AST pass despite
  per-rule confidence. The Python pass targets weak and asymmetric primitives, so routine
  quantum-safe use (e.g. `hashlib.sha256`) is under-inventoried.
- **Binary analysis is shallow.** ELF symbol tables are parsed properly; PE and Mach-O
  degrade to string matching. No disassembly, no reachability analysis.
- **Surfaces absent:** container and image layers, HSM/KMS/PKCS#11 key custody,
  infrastructure-as-code, runtime observation. Live probing is TLS only, not SSH or IPsec.
- **Risk and recommendation constants are assumptions.** Q-Day bounds, shelf-life tiers and
  per-surface migration effort are defaults, not measurements; the recommender is expert
  rules no real migration has validated. Largest target: ~3,000 files.

---

## 8. What We Want Industry Feedback On

1. Is filesystem-plus-endpoint discovery enough to call an enterprise estate inventoried, or
   does credible coverage need agent, runtime or network-capture telemetry?
2. Which missing surface would you consider disqualifying — HSM/KMS key custody, container
   images, IaC, mainframe, or something we have not named?
3. Is grouping call sites into assets, weighted by production / vendored / test path, the
   right inventory unit for a CBOM consumer, or do downstream tools need raw hits?
4. Does exposure probability over a Q-Day distribution beat a fixed-date model, or do real
   programmes prioritise on data classification and criticality and ignore Z?
5. What would our recommendations need — measured handshake and latency impact,
   protocol-field audits, certificate-chain sizing — before you would act on them in
   production?
