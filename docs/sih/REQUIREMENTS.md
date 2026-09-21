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
| R1.7 | Container images | `app/container.py` (archive safety), `app/scanners/container.py` (sensor) | 71 | OCI layout dir, OCI archive, Docker save. Layer replay with whiteouts; effective vs historical | **DONE** — see coverage note below |
| R1.8 | Explicitly authorized infrastructure | `app/scanners/network.py` — live TLS probe | none | Works; **no authorization control** | PARTIAL — see S1 |

## R2 — Standardized CBOM

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R2.1 | CycloneDX 1.6 CBOM | `app/cbom.py` | `tests/test_cbom.py` (18) | CI `smoke` job asserts conformance on every push | DONE |
| R2.2 | Detection evidence in the BOM | `cbom._evidence` → `evidence.occurrences` + `evidence.identity` | `test_cbom.py::detection_evidence_is_carried_into_the_bom` | Technique and confidence per component | DONE |
| R2.3 | Official schema validation | `app/schema_validation.py` against the vendored official schemas | 11 | Offline, pinned commit, checksummed; CI fails on violation | **DONE** |
| R2.6 | Structural check kept separate | `cbom.validate` | 6 | Reported beside the official result, never as conformance | **DONE** |
| R2.5 | Container provenance in the CBOM | `cbom._metadata_properties`, `container:*` properties | 4 | Image, digest, platform, layer index/digest and effective state per component | **DONE** |
| R2.4 | Additional export version | CycloneDX 1.7, genuinely implemented | 7 | `ellipticCurve`, `algorithmFamily`, `relatedCryptographicAssets`; both versions validated against their own schema | **DONE** |

### Container coverage, stated exactly

What is supported, and nothing beyond it:

| Supported | Not supported |
|---|---|
| OCI image layout, unpacked directory | Pulling from a registry (by design — no network) |
| OCI image layout packed as a tar | zstd-compressed layers (named and refused, not skipped) |
| `docker save` tar archives | A running Docker daemon or any privileged access |
| gzip, bzip2, xz compression | Windows container images |
| Layer replay with `.wh.` and `.wh..wh..opq` whiteouts | Squashed-image reconstruction beyond whiteout replay |
| Image config: env, labels, history | Signature or attestation verification (cosign, in-toto) |
| Reuse of the source, binary, config, manifest and certificate analysers | Anything the underlying analysers cannot do — e.g. Mach-O symbol tables |

Every file is streamed into memory and analysed there. **Nothing is extracted
to disk at any point**, which is both the security property and the reason
there is no cleanup path to get wrong.

## R11 — Cross-sensor correlation

| ID | Requirement | Implementation | Tests | Evidence | Status |
|---|---|---|---|---|---|
| R11.1 | Link findings that are one logical asset | `app/engine/correlate.py` | 11 | Union-find over shared concrete artefacts | **DONE** |
| R11.2 | Links must be evidence-backed | `artefact_keys` — same file, same layer+path, or same identified component | 3 | A shared algorithm name links nothing | **DONE** |
| R11.3 | RSA signing and key establishment stay distinct | bucketed by `(algorithm, purpose)` before any linking | 1 | No shared artefact can bridge two purposes | **DONE** |
| R11.4 | CAPABILITY never becomes OBSERVED | correlation writes only to `extra["correlation"]` | 2 | `own_assurance_unchanged` asserted equal to `f.assurance` | **DONE** |
| R11.5 | Correlation must not invent confidence | no write to `confidence` anywhere in the module | 1 | Confidence map asserted identical before and after | **DONE** |
| R11.6 | Conflicting evidence stays visible | `_conflicts` records key size, mode, padding and assurance spread | 1 | Surfaced in API, drawer, report and CBOM | **DONE** |
| R11.7 | Unlinkable findings are left alone | clusters of one are discarded | 1 | Most findings carry no `correlation` key | **DONE** |
| R11.8 | Exposed in API, dashboard and reports | `logical_assets` in the payload; drawer section; `correlation:*` CBOM properties | 4 | | **DONE** |

**Correlation basis kinds, and what each one actually claims.**

| Basis | Claim | Why it is safe |
|---|---|---|
| `file:<path>` | Two detectors read the same file | The file is one artefact |
| `layer:<digest>:<path>` | Same file in the same image layer | Same path in two layers is two files |
| `component:<library>` | Both belong to a library a detector *identified* | Only from a version banner, or a finding's own `library` key |

A path maps to a component only when every library-naming finding at that
path agrees. A `requirements.txt` listing six packages is a list, not a
component, so it maps to none of them — otherwise every algorithm any of the
six provides would attach to every artefact of whichever parsed first.

### Standards conformance, stated exactly

Two checks exist and they are **not** the same thing.

| Check | What it is | Where |
|---|---|---|
| Structural | Required fields, enum membership, bom-ref uniqueness, reference integrity. Fast, no dependencies. **Not conformance.** | `cbom.validate` |
| Official | Validation against the JSON Schema the CycloneDX project publishes, vendored at a pinned commit and checksummed on load. | `schema_validation.validate` |

Both are reported separately by the API, the CLI and the console. A run where
official validation could not happen reports `checked: false`, never a pass —
a check that silently did not run is worse than one that failed.

**Versions genuinely supported: 1.6 (default) and 1.7.** 1.7 is a real
implementation, not a relabelled 1.6: it uses `ellipticCurve` (a namespaced
closed enum, `nist/P-256`) in place of the deprecated `curve`,
`relatedCryptographicAssets` in place of the deprecated
`signatureAlgorithmRef`, and `algorithmFamily`, which splits RSA by purpose —
`RSASSA-PSS`, `RSAES-OAEP` — and is therefore **omitted** when the purpose is
unresolved. CI validates both against their own schema.

### CBOM defects found by the audit and fixed

Every one was reproduced before being changed.

| Defect | Was | Now |
|---|---|---|
| Library components | Dependencies emitted as `cryptographic-asset` with `assetType: algorithm`. The module comment already claimed otherwise. | `type: library`, no `cryptoProperties` |
| `mode` enum | `xts`, `cfb8`, `gcm-siv` emitted raw — **rejected by the official schema** | Mapped, unmappable values to `other` |
| `padding` enum | `pkcs5padding`, `OAEPWith…` emitted raw — **rejected** | Mapped to `pkcs5`, `oaep`, … |
| `executionEnvironment` | Hardcoded `software-plain-ram` — a guess, and exactly wrong for an HSM key | `unknown`, or `hardware` when an operator says so |
| `parameterSetIdentifier` | Fell back to `classical_bits`, reporting ECDSA P-256 as parameter set "128" (its strength) | Key size only; named curves go in `curve` |
| `signatureAlgorithmRef` | Held a name (`sha256WithRSAEncryption`); the schema declares it a `refType` | A real bom-ref, or omitted |
| Certificate dates | Bare dates against `format: date-time` | RFC 3339 |
| Secret material | `SECRET_KEY = "hunter2…"` exported verbatim in `additionalContext` **and** `symbol` | Redacted; location kept |

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
| R4.4 | Explicit confidentiality lifetime | `app/assessment.py` per-asset override, persisted | 12 | Operator-set X, validated and bounded; meaning varies by exposure model | **DONE** |
| R4.5 | Explicit migration duration | per-asset override, falling back to the sensor-derived estimate | 4 | | **DONE** |
| R4.6 | Business criticality | per-asset override, falling back to path inference | 4 | An override on one asset never touches another with the same algorithm | **DONE** |
| R4.10 | Input provenance is visible | `assessment.RiskInput` — observed / derived / operator / default | 6 | Shown in the console, the report and the CBOM | **DONE** |
| R4.11 | Purpose-specific exposure models | `risk.EXPOSURE_MODELS` | 9 | HNDL, forgery-after-Q-Day, Grover margin, unresolved | **DONE** |
| R4.12 | Q-Day terminology is correct | `QDayModel.mode_year` / `.median_year` | 5 | `likely` is the **mode**; the median is computed and reported beside it | **DONE** |
| R4.13 | Assessment date is explicit | `risk.assessment_date()`, `CD_ASSESSMENT_DATE` | 2 | Three hardcoded `2026` defaults removed | **DONE** |
| R4.14 | Recomputation is never stale | `score_finding` overwrites rather than `setdefault` | 3 | The audit trail moves with the score | **DONE** |
| R4.15 | Preview never mutates saved data | `POST /api/assessment/preview` | 4 | Scores a copy and discards it | **DONE** |
| R4.16 | Overrides survive restart and rescan | `asset_overrides` table, keyed on `asset_key` | 6 | Outlive the scan lifecycle by design | **DONE** |
| R4.7 | Evidence confidence feeds the score | `conf_term` in `score_finding` | `test_risk.py::low_confidence_findings_cannot_outrank_certain_ones` | | DONE |
| R4.8 | Cryptographic purpose feeds risk | `risk.PURPOSE_URGENCY` | 3 | Key establishment weighted above signing: only the former is exposed to harvest-now-decrypt-later | **DONE** |
| R4.9 | Evidence assurance feeds risk | `risk.ASSURANCE_WEIGHT` | 2 | A named factor distinct from confidence; capability findings rank below equivalent call sites | **DONE** |

### What the Mosca model does and does not claim

`X + Y > Z` is one inequality, but **X does not mean the same thing for every
asset**, and treating it as though it did is how a tool ends up asserting that
a TLS handshake signature must stay unforgeable for twenty-five years.

| Purpose | Model | X means | Retroactive? |
|---|---|---|---|
| Key establishment, encryption, transport | Harvest now, decrypt later | how long the data must stay confidential | **Yes** — traffic already recorded is already lost |
| Signature, authentication | Forgery from Q-Day onward | how long the key must stay unforgeable | **No** — a CRQC cannot un-sign a 2026 release |
| Hashing, KDF, randomness; any symmetric primitive | Grover margin | confidentiality lifetime, but there is no arrival cliff | Yes, gradually |
| Unresolved purpose | Unresolved | assumed confidentiality lifetime | Assumed yes |

The unresolved case deliberately assumes the *more* urgent model. Assuming the
milder one would reward the tool for failing to resolve the purpose.

**Q-Day is not forecast.** The `likely` parameter is the **mode** of a
triangular distribution — its peak — and an earlier version used it as a
median and said so in a docstring. Under the shipped defaults (2030 / 2034 /
2044) the true median is **2035.63**, so the error was about 1.6 years, always
in the direction that understates exposure. Both are now computed; the mode
remains the default basis because that is what the slider sets, and the median
is reported beside it. Every probability is labelled conditional on the chosen
scenario and `is_forecast` is emitted as `false` in the CBOM.

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
| R5.9 | Say what must be validated before deployment | `recommend.enrich` — evidence, exposure, compatibility, validation steps, unknowns | 8 | Every recommendation carries all six | **DONE** |
| R5.11 | Latency and cost are never invented | `UNKNOWN_LATENCY`, `UNKNOWN_COST` | 2 | Both report a status of *not measured* / *not estimated*, with the reason | **DONE** |
| R5.12 | Operator constraints warn rather than silently retarget | `_apply_constraints` | 2 | e.g. a constrained link against a 3,309-byte ML-DSA signature | **DONE** |

## R6 — Reporting

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R6.1 | Machine-readable export | `GET /api/scan/{id}/cbom` | `test_api.py` (3) | | DONE |
| R6.2 | Human-readable report | `app/report.py` | 12 | Executive summary plus a full inventory: every asset, not the top 15 | **DONE** |
| R6.3 | Asset → Evidence → Classification → Risk → Recommendation → Action chain | `report._chain_block` — six numbered steps per asset | 3 | One traced block per finding, all of them | **DONE** |
| R6.4 | Incomplete scans and unresolved findings surfaced | `report._status_cell`, `_sensor_error_rows`, `_refusal_rows`, `_coverage_rows` | 3 | A partial scan says so at the top and lists why | **DONE** |
| R6.5 | Report safety: escaping and redaction | `html.escape` throughout; `cbom.redact` | 5 | Hostile input cannot inject markup; secrets never exported | **DONE** |
| R6.6 | Offline, print-to-PDF reporting | `@media print` rules, no scripts, no external fetches | 1 | Browser Print → Save as PDF; no direct export and none claimed | **DONE** |

## R7 — Interactive interface

| ID | Requirement | Implementation | Tests | Evidence | Baseline |
|---|---|---|---|---|---|
| R7.1 | Scan configuration | `app/web/` + `/api/browse` | `test_api.py` (2) | Folder picker works | DONE |
| R7.2 | Progress and partial failures | `renderIntegrity` banner above the verdict; error and refusal states in `poll` | | A partial scan says so where it cannot be missed | **DONE** |
| R7.3 | Cryptographic inventory | ledger scene with filters | | | DONE |
| R7.4 | Evidence inspection | drawer shows every evidence item with file, line, technique, confidence and assurance, plus correlated peers as followable findings | | A link you can follow is evidence; a link you cannot is an assertion | **DONE** |
| R7.5 | Quantum-risk assessment | radial + composition + Mosca scene | | | DONE |
| R7.6 | Migration planner | plan scene | | | DONE |
| R7.7 | CBOM export | download + validate buttons | `test_api.py` | | DONE |
| R7.8 | Reports and history | scene 06: every stored scan, with target, date, kind, status, count, reopen, report and CBOM | | `/api/scans` had always existed; the console simply never showed it | **DONE** |

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
| R9.1 | Labelled ground-truth corpus | `benchmark/corpus` + `benchmark/manifest.json`, hand-labelled, versioned, with a changelog | 6 | 116 expected findings, 4 negative files, all 6 batch scanners | **DONE** |
| R9.2 | Precision / recall / F1 / FP / FN per detector | `benchmark/run.py` | 12 | Per scanner and overall; purpose and assurance scored separately | **DONE** |
| R9.3 | Published method and results | `benchmark/README.md`, `benchmark/results/` | 2 | Baseline preserved; CI enforces a floor | **DONE** |
| R9.4 | Benchmark cannot silently rot | `tests/test_benchmark_harness.py` + a CI step | 16 | Matching honesty is itself tested | **DONE** |

### Measured accuracy

Over `benchmark/corpus`, manifest 1.2.0, 116 hand-labelled findings across six
scanners:

| Scanner | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| source | 58 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| dependency | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| config | 14 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| container | 14 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| certificate | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| binary | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **Overall** | **116** | **0** | **0** | **1.000** | **1.000** | **1.000** |

Purpose 114/114, assurance 116/116, with 2 genuinely ambiguous cases excluded
rather than guessed.

**A perfect score here means the corpus has stopped finding defects, not that
the tool is perfect.** The same person wrote the fixtures and the detectors.
These numbers measure this corpus; they are not an estimate of accuracy on
real-world code, which this project has never measured.

The honest improvement figure is the like-for-like one — the same corpus
before and after the fixes:

| | Precision | Recall | F1 | TP / FP / FN |
|---|---|---|---|---|
| Before (382e7d1) | 0.941 | 0.941 | 0.941 | 79 / 5 / 5 |
| After, same corpus | 0.966 | 1.000 | 0.983 | 84 / 3 / 0 |

The 3 residual false positives in the after-column are findings the tool got
right and the first pass of labelling missed; they are expected in manifest
1.1.0 and the correction is recorded in its changelog.

**The network sensor is excluded from these figures.** What a TLS handshake
negotiates depends on the local OpenSSL build, so an expected-results label
would be a label for one machine. It is probed against a loopback server and
its structural properties are asserted instead.

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

| Status | 90f4da3 | M1 | M2 | M3 | M4 | M5 | M6 |
|---|---|---|---|---|---|---|---|
| DONE | 26 | 35 | 48 | 59 | 73 | 83 | 91 |
| PARTIAL | 25 | 22 | 18 | 18 | 14 | 9 | 6 |
| GAP | 17 | 12 | 11 | 9 | 9 | 8 | 5 |
| DEFECT | 5 | 4 | **0** | **0** | **0** | **0** | **0** |

M6 measured detection accuracy for the first time. The benchmark found seven
detector defects that reading the code had not — four false negatives from one
regex treating a hyphen as an exclusion marker, a TLS 1.0 finding invented from
a 1.2-only configuration, an AES finding in a file containing no AES, and the
M2 purpose work missing entirely from the binary sensor. It also found a
double-count in the benchmark harness itself. Test count rose from 618 to 664.

M5 made the CBOM independently schema-valid against the official CycloneDX
schemas, added genuine 1.7 export, and found eight emitter defects by audit —
four of which the official schema rejects outright and one of which exported
hardcoded secrets into a document meant to be shared. Test count rose from
557 to 617.

M4 made risk assessment per-asset rather than estate-wide, corrected two
mathematical defects found by reading the code (the mode/median mislabelling
and the `setdefault` stale-factor bug), gave every purpose its own exposure
model, and separated scenario previews from saved assessments. Test count rose
from 487 to 557.

M1 closed all nine R8 rows and one detection defect (D7, the obsolete Kyber
draft group). Test count rose from 226 to 317.

M3 closed the container-image gap (R1.7) and added the correlation layer
(R11), plus CBOM container provenance (R2.5). CI now runs on `sih/**` branches,
which it did not before, so this branch was previously unverified until merge.
Test count rose from 413 to 487. One fidelity bug was found and fixed during
M3 verification: container findings originally all carried `scanner =
"container"`, which made normalisation merge a source call site with a binary
symbol — the distinction a directory scan preserves. The scanner name now
keeps the inner analyser.

M2 closed the remaining four detection defects — D1 and D2 (hash identity),
D4 (RSA purpose), D5 (capability reported as use) — and D6 (certificate trust),
plus the TLS semantic defect where a refused hybrid probe named a specific
classical mechanism it had never observed. Test count rose from 317 to 413.
**No defect rows remain open.**
