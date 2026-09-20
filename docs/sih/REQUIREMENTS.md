# REQUIREMENTS — SIH26164 traceability matrix

Requirement text is taken from the scope as stated in the project engineering
directive. Where the official problem statement uses different wording, the
requirement IDs below are ours and the mapping, not the wording, is what
matters.

**Status vocabulary.** `DONE` means implemented *and* covered by a test that
would fail if it broke. `PARTIAL` means implemented but incomplete or
unverified. `GAP` means not implemented. `CLAIMED-ONLY` means asserted
somewhere in the repository without an implementation behind it — treated as a
defect.

Baseline column = state at `90f4da3`. This file is updated as milestones land.

---

## R1 — Discovery

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R1.1 | Source repositories | `app/scanners/source.py` — Python AST + 10-language rule packs | `tests/test_scan_end_to_end.py` (16) | Verified scan of `app/`: 26 files, 6 hits | DONE |
| R1.2 | Dependencies / manifests | `app/scanners/deps.py` — 13 manifest formats, 22-library matrix | none dedicated | Reads pip/npm/maven/gradle/go/cargo | PARTIAL — untested |
| R1.3 | Binaries | `app/scanners/binary.py` — ELF section headers, constants, version banners | none dedicated | `_elf_string_sections` parses real `.dynstr` | PARTIAL — untested, ELF only |
| R1.4 | Libraries | `app/scanners/deps.py` + `rules_binary.VERSION_PATTERNS` | none | Library capability recorded | PARTIAL — capability not marked as such (see D5) |
| R1.5 | Configuration | `app/scanners/configs.py` — nginx, sshd, OpenSSL, Java, Apache, HAProxy | none dedicated | Disable-lists correctly excluded | PARTIAL — untested |
| R1.6 | Certificates and key material | `app/scanners/certs.py` — PEM/DER X.509, PKCS#12, private keys, PQC OIDs | `test_cbom.py::certificate_findings_emit_certificate_asset_type` | PQC OID fallback verified in code | PARTIAL |
| R1.7 | Container images | — | — | — | **GAP** |
| R1.8 | Explicitly authorized infrastructure | `app/scanners/network.py` — live TLS probe | none | Works; **no authorization control** | PARTIAL — see S1 |

## R2 — Standardized CBOM

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R2.1 | CycloneDX 1.6 CBOM | `app/cbom.py` | `tests/test_cbom.py` (18) | CI `smoke` job asserts conformance on every push | DONE |
| R2.2 | Detection evidence in the BOM | `cbom._evidence` → `evidence.occurrences` + `evidence.identity` | `test_cbom.py::detection_evidence_is_carried_into_the_bom` | Technique and confidence per component | DONE |
| R2.3 | Schema validation | `cbom.validate` — structural only, states its own scope | 8 validator tests | Honest about not being JSON-Schema | PARTIAL |
| R2.4 | Additional export version | — | — | — | GAP — must first verify whether a newer applicable spec exists |

## R3 — Quantum exposure classification

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R3.1 | Shor / Grover / safe classification | `app/knowledge/algorithms.py` — 52 entries | `tests/test_knowledge.py` (12) | Every entry has a valid class and primitive | DONE |
| R3.2 | Unknown stays unknown | `algorithms.get` → `unknown` fallback | `test_knowledge.py::unknown_is_reported_not_guessed` | Verified | DONE |
| R3.3 | Correct hash-family identification | `source.py:_PY_HASHES`, `_PY_HASHLIB` | 20 | SHA3-512, BLAKE2b, BLAKE2s each keep their own identity through the whole pipeline | **DONE** |
| R3.4 | Complete SHA-3 / BLAKE coverage | `algorithms.py` — SHA3-224/256/384/512, SHAKE128/256, BLAKE2b/2s/3, SHA-512/224, SHA-512/256 | 20 | Registry 52 → 74 entries | **DONE** |
| R3.5 | Capability vs use vs runtime observation | `models.py` assurance states; set by every sensor | 9 | `capability` / `declared` / `used` / `observed`, exported in the CBOM | **DONE** |
| R3.6 | TLS version vs negotiated group | `network.py` — version, suite, KEX and auth are four findings | 6 | Verified against a local TLS 1.3 and a TLS 1.2 server | **DONE** |
| R3.7 | Probe failure vs observed classical KEX | `network.py:scan_endpoint` | 3 | A refused hybrid probe now yields `unknown`, never `ecdh` | **DONE** |
| R3.8 | Certificate observation vs verified trust | `certs.py`, `network._verify_trust` | 5 | `trust_verified` from a separate verifying handshake | **DONE** |
| R3.9 | Current PQC identifiers | `network.PQ_GROUPS` / `OBSOLETE_PQ_GROUPS` | 2 | Draft groups recognised but never offered | **DONE** (M1) |
| R3.10 | Cipher suite decomposition | `network.parse_cipher_suite` | 3 | TLS 1.3 suites correctly report that they encode no key exchange | **DONE** |

## R4 — Mosca-style risk reasoning

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R4.1 | X + Y > Z evaluated | `app/engine/risk.py:mosca` | `tests/test_risk.py` (23) | `exposure = max(0, X+Y-Z)` | DONE |
| R4.2 | Q-Day as an assumption, not a fact | `QDayModel` triangular distribution, `probability_exposed` | `test_risk.py::probability_is_reported_not_a_hardcoded_qday` | Deterministic under fixed seed | DONE |
| R4.3 | Transparent, auditable factors | `finding.extra["factors"]` | `test_risk.py::scoring_records_every_factor_it_used` | Seven named multipliers | DONE |
| R4.4 | Explicit confidentiality lifetime | `SHELF_LIFE_BY_SENSITIVITY`, estate-wide | — | Not per-asset | PARTIAL |
| R4.5 | Explicit migration duration | `MIGRATION_EFFORT_YEARS` by sensor | `test_risk.py::binary_findings_carry_a_longer_migration_cost_than_config` | Not overridable per asset | PARTIAL |
| R4.6 | Business criticality | `normalize.CRITICALITY` inferred from path | `test_normalize.py` (4) | Path-derived only, not operator-set | PARTIAL |
| R4.7 | Evidence confidence feeds the score | `conf_term` in `score_finding` | `test_risk.py::low_confidence_findings_cannot_outrank_certain_ones` | | DONE |
| R4.8 | Cryptographic purpose feeds risk | `risk.PURPOSE_URGENCY` | 3 | Key establishment weighted above signing: only the former is exposed to harvest-now-decrypt-later | **DONE** |
| R4.9 | Evidence assurance feeds risk | `risk.ASSURANCE_WEIGHT` | 2 | A named factor distinct from confidence; capability findings rank below equivalent call sites | **DONE** |

## R5 — Migration recommendations

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R5.1 | Purpose-correct alternatives | `recommend.py` dispatches on the finding's resolved **purpose**, not the algorithm's primitive | 31 | `knowledge/purposes.py` is the model | **DONE** |
| R5.2 | **RSA signing must not get a KEM** | RSA carries two purposes; the detector resolves which from the call site | 9 | Verified: RSA-PSS → ML-DSA-65, RSA-OAEP → X25519MLKEM768, `GenerateKey` → unresolved | **DONE** |
| R5.10 | Unknown purpose yields an explicit unresolved recommendation | `recommend._unresolved_purpose` | 4 | No target named; the action says what evidence would resolve it | **DONE** |
| R5.3 | Key establishment → KEM / hybrid | `recommend.py:117-149` | 3 tests | | DONE |
| R5.4 | Signatures → ML-DSA / SLH-DSA / FN-DSA by profile | `recommend.py:152-189` | 5 tests | | DONE |
| R5.5 | Symmetric → AES-256 without family change | `recommend.py:192-210` | 2 tests | | DONE |
| R5.6 | Hashing → SHA-256/384 by profile | `recommend.py:212-224` | 2 tests | | DONE |
| R5.7 | Size / latency / cost reasoning | `_sig_delta`, `_size_note`, `LIBRARY_SUPPORT` | 3 tests | Byte deltas are real registry data | DONE |
| R5.8 | Never recommend a vulnerable target | `recommend.py` | `test_recommend.py::vulnerable_algorithms_are_never_sent_to_another_vulnerable_target` | | DONE |
| R5.9 | Say what must be validated before deployment | `size_note`, `agility_note`, `library_support` | | Present but not uniformly | PARTIAL |

## R6 — Reporting

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R6.1 | Machine-readable export | `GET /api/scan/{id}/cbom` | `test_api.py` (3) | | DONE |
| R6.2 | Human-readable report | `app/report.py` → `GET /api/scan/{id}/report` | none | HTML executive report | PARTIAL |
| R6.3 | Asset → Evidence → Classification → Risk → Recommendation → Action chain | `report.py` gains "What the evidence establishes" and "Cryptographic purpose" sections | 1 | Assurance and purpose columns in the findings table | PARTIAL — chain is visible, not yet a single traced view |
| R6.4 | Incomplete scans and unresolved findings surfaced | `stats["sensor_errors"]` captured | — | **Never shown in the UI or report** | **GAP** |

## R7 — Interactive interface

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R7.1 | Scan configuration | `app/web/` + `/api/browse` | `test_api.py` (2) | Folder picker works | DONE |
| R7.2 | Progress and partial failures | progress DONE; failures **not surfaced** | `test_api.py::a_scan_runs_to_completion` | Tick counter distinguishes slow from stalled | PARTIAL |
| R7.3 | Cryptographic inventory | ledger scene with filters | | | DONE |
| R7.4 | Evidence inspection | drawer shows purpose, assurance, evidence mix and per-item assurance | | Assurance chips in the ledger; unresolved recommendations styled distinctly | PARTIAL — still no cross-file drill-down |
| R7.5 | Quantum-risk assessment | radial + composition + Mosca scene | | | DONE |
| R7.6 | Migration planner | plan scene | | | DONE |
| R7.7 | CBOM export | download + validate buttons | `test_api.py` | | DONE |
| R7.8 | Reports and history | report button; **no history browser** | | `/api/scans` exists, unused by UI | PARTIAL |

## R8 — Security of the tool itself

Closed by M1 (`sih/milestone-hardening`). Every row has an adversarial test in
`tests/test_security.py` that fails against the code at `90f4da3`.

| ID | Requirement | Implementation | Tests | Baseline | Now |
|---|---|---|---|---|---|
| R8.1 | SSRF-resistant destination validation | `app/netpolicy.py` — resolve, vet every returned address by property, connect to the vetted literal | 24 | GAP (S1) | **DONE** |
| R8.2 | Correct IPv4 / IPv6 / URL parsing | `netpolicy.parse_destination` — brackets, bare v6, schemes, trailing dot | 18 | DEFECT (S5) | **DONE** |
| R8.3 | Explicit authorized destinations | `CD_ALLOWED_HOSTS` allowlist, `CD_ALLOWED_PORTS`, `CD_MAX_ENDPOINTS` | 3 | GAP | **DONE** |
| R8.4 | Filesystem boundaries and symlink handling | `app/fspolicy.py` — root boundary, symlink escape, credential-store denylist, synthetic filesystems | 10 | GAP (S3, S8) | **DONE** |
| R8.5 | AuthN/AuthZ when not local-only | `app/auth.py` + middleware — bearer, custom header or cookie | 8 | GAP (S2) | **DONE** |
| R8.6 | Secure localhost-only default | `auth.check_binding` — the server **refuses to start** on a non-loopback bind with no token | 6 | PARTIAL | **DONE** |
| R8.7 | Bounded scanning | scan semaphore, wall-clock budget, entry budget, endpoint cap, job eviction | 5 | PARTIAL | **DONE** |
| R8.8 | Safe handling of malformed input and incomplete scans | schema bounds, per-sensor isolation, clean deadline stop, `stats["complete"]` | 4 | PARTIAL | **DONE** |
| R8.9 | Security failures visible to the operator | `_scan_warnings` on every status and scan payload; `/api/meta` publishes the active policy | 3 | GAP | **DONE** |

### What M1 deliberately did not do

- **Rate limiting.** A single-operator local tool with a concurrency cap does
  not need it, and adding one would imply a multi-tenant threat model we do
  not have.
- **TLS on the console itself.** Loopback by default; behind a reverse proxy
  when it is not. Terminating TLS here would be a second, worse copy of what
  the proxy already does.
- **Sandboxing the sensors.** They are pure-Python readers with no `exec` and
  one subprocess call (an OpenSSL CLI given a vetted literal address). The
  boundary is the filesystem policy, not a sandbox, and that is stated rather
  than implied.

## R9 — Measurement

| ID | Requirement | Baseline |
|---|---|---|
| R9.1 | Labelled ground-truth corpus (positive and negative) | **GAP** |
| R9.2 | Precision / recall / F1 / FP / FN per detector | **GAP — never measured** |
| R9.3 | Published method and results | **GAP** |

## R10 — Submission readiness

| ID | Requirement | Baseline |
|---|---|---|
| R10.1 | README | DONE — 422 lines, honest limitations |
| R10.2 | Architecture diagram | PARTIAL — Mermaid in README, no standalone asset |
| R10.3 | Install / run instructions | DONE |
| R10.4 | Test instructions | DONE |
| R10.5 | Benchmark instructions | GAP |
| R10.6 | Demo fixtures | PARTIAL — `tests/conftest.py` has a synthetic tree; no shipped fixture corpus |
| R10.7 | Genuine screenshots | DONE — 9 in `Report/assets/screenshots/` |
| R10.8 | Limitations | DONE |
| R10.9 | Demonstration script | DONE — `presenter/script.md` |
| R10.10 | Six-section official deck exported as a six-page PDF | GAP — `deck/index.html` exists but is not the official six-section structure |
| R10.11 | Real-product video script | GAP |

---

## Summary at baseline

| Status | At 90f4da3 | After M1 | After M2 |
|---|---|---|---|
| DONE | 26 | 35 | 48 |
| PARTIAL | 25 | 22 | 18 |
| GAP | 17 | 12 | 11 |
| DEFECT | 5 | 4 | **0** |

M1 closed all nine R8 rows and one detection defect (D7, the obsolete Kyber
draft group). Test count rose from 226 to 317.

M2 closed the remaining four detection defects — D1 and D2 (hash identity),
D4 (RSA purpose), D5 (capability reported as use) — and D6 (certificate trust),
plus the TLS semantic defect where a refused hybrid probe named a specific
classical mechanism it had never observed. Test count rose from 317 to 413.
**No defect rows remain open.**
