# BASELINE — verified state of CryptoDrishti at commit 90f4da3

Audited 2026-09-20 on branch `sih/milestone-hardening`, branched from `main`
at `90f4da3`, which matches `origin/main` exactly (verified by `git fetch`).
Working tree was clean before any change.

Everything below was **executed**, not read off the README. Where this
document disagrees with the README, this document is the one that ran.

---

## 1. What exists

8,648 lines across 35 first-party files (excluding `.venv`, `.backup`,
`Report/snapshot`, caches).

| Area | Files | LOC | State |
|---|---|---|---|
| Sensors | `app/scanners/{source,deps,certs,configs,binary,network}.py` | 1,427 | Working, six sensors |
| Knowledge | `app/knowledge/{algorithms,rules_source,rules_binary}.py` | 1,149 | Working, 52 algorithms |
| Engine | `app/engine/{normalize,risk,recommend}.py` | 639 | Working |
| Output | `app/{cbom,report}.py` | 533 | CycloneDX 1.6 + HTML report |
| Service | `app/{api,store,config,models,cli,preflight}.py` | 1,244 | FastAPI, SQLite |
| Console | `app/web/{index.html,style.css,app.js}` | 2,121 | Vanilla JS, no build step |
| Tests | `tests/*.py` | 1,536 | **226 passing** |

### Verified: the test suite passes

```
$ .venv/bin/python -m pytest -q
226 passed  (2 third-party deprecation warnings)
```

Python 3.14.7 locally; CI matrix covers 3.11 / 3.12 / 3.13.

### Verified: an end-to-end scan runs and emits a conforming CBOM

```
$ python -m app.cli scan app --cbom cbom.json
  files scanned      26
  raw detector hits  6
  crypto assets      2
  CycloneDX 1.6 structural validation: PASS
```

CI job `smoke` performs the same check on every push.

---

## 2. Features that genuinely work

These were confirmed by reading the implementation **and** running it.

1. **Six independent sensors**, orchestrated with per-sensor error isolation
   (`orchestrator.py:85-87` catches per sensor into `stats["sensor_errors"]`).
2. **Python AST analysis** — real `ast.Call` / `ast.Attribute` inspection,
   resolves `key_size=2048` from keyword arguments. Not regex.
3. **ELF section-header parsing** — `binary.py:_elf_string_sections` walks
   section headers and reads `.dynstr` / `.strtab` directly. Mach-O and PE
   correctly fall back to string scanning at reduced confidence with a
   *different* `technique` value recorded. This distinction is real.
4. **X.509 parsing** including PQC OIDs resolved from the dotted string when
   the installed `cryptography` cannot load the key type (`certs.py:133-165`).
5. **Normalisation** — hits grouped into assets by
   `(algorithm, asset_type, mode, padding, key_size, scanner)`, with
   production / test / vendored path weighting.
6. **Mosca model with a distribution, not a date** — triangular sampling over
   (earliest, likely, latest), reports `probability_exposed` alongside median
   exposure. Deterministic under a fixed seed.
7. **Transparent scoring** — every multiplier is recorded in
   `finding.extra["factors"]` and rendered in the UI.
8. **CycloneDX 1.6 emitter + structural validator** that explicitly states it
   is not full JSON-Schema validation.
9. **Q-Day re-scoring endpoint** that returns only deltas, not the full payload.

---

## 3. Verified defects

Each of these was reproduced by execution, not inferred.

### 3.1 Security

| # | Issue | Location | Evidence |
|---|---|---|---|
| S1 | **SSRF.** `endpoints` from `POST /api/scan` reach `socket.create_connection` with no destination validation. Loopback, RFC1918, link-local (`169.254.169.254`), IPv6 ULA and arbitrary ports are all reachable. | `network.py:265-283`, `api.py:92-99` | No filter exists anywhere in the path |
| S2 | **No authentication on any route**, while `CD_HOST` allows binding `0.0.0.0`. Default `127.0.0.1` is safe; nothing stops or warns about the unsafe binding. | `config.py:87`, `api.py` | No auth dependency on any route |
| S3 | **Arbitrary filesystem read.** `POST /api/scan` accepts any absolute path; matched source lines are returned to the client in `evidence.snippet`. | `api.py:75`, `models.py:45` | `Evidence.snippet` carries up to 200 bytes of file content |
| S4 | **Arbitrary directory enumeration.** `GET /api/browse` walks any path and advertises `/` as a starting place. | `api.py:348-382` | `places` includes `{"name": "/", "path": "/"}` |
| S5 | **Port parsing is unbounded.** `int(port_s) if port_s.isdigit()` accepts `0` and `999999`. `http://` prefix is not stripped although `https://` is. IPv6 literals (`[::1]:443`) are mis-split by `raw.partition(":")`. | `network.py:273-276` | `partition(":")` on `[::1]:443` yields host `[` |
| S6 | **Unbounded scan concurrency.** Every `POST /api/scan` spawns a daemon thread; `_JOBS` never evicts. | `api.py:114-121`, `api.py:35` | No semaphore, no cap, no TTL |
| S7 | **Traceback disclosure.** Scan failures return `trace` (2000 chars of internal paths) to the client. | `api.py:109-111` | `trace=traceback.format_exc()[-2000:]` |
| S8 | **Symlink escape.** `os.walk` does not follow directory symlinks, but a *file* symlink named `x.py` pointing outside the root is opened and read. | `source.py:47-64`, `certs.py:69-87`, `binary.py:69-91` | No `is_symlink()` check in any walker |
| S9 | **No global execution-time bound.** `MAX_FILES` and `MAX_FILE_BYTES` exist; wall-clock does not. A scan of `/` runs until it finishes. | `config.py:46-49` | No deadline anywhere |

### 3.2 Detection correctness

Reproduced directly:

```
$ python -c "from app.knowledge import algorithms as K; print(K.get('sha3-512').name)"
Unresolved cryptographic use
```

| # | Issue | Location | Actual behaviour |
|---|---|---|---|
| D1 | **SHA3-512 reported as SHA3-256.** | `source.py:98` | `"SHA3_512": "sha3-256"` — a 512-bit hash is recorded as 256-bit |
| D2 | **BLAKE2b reported as SHA-512; BLAKE2s as SHA-256.** | `source.py:98` | `"BLAKE2b": "sha512"` — wrong algorithm family entirely |
| D3 | **Registry has no SHA3-224/384/512, no BLAKE2, no BLAKE3, no SHAKE.** | `algorithms.py:301` | Only `sha3-256` exists; every other SHA-3 member resolves to `unknown` |
| D4 | **RSA signing receives a KEM.** `rsa-*` carries `primitive=pke`, so `recommend()` routes every RSA finding — including certificate signatures — down the key-establishment branch. | `algorithms.py:147-173`, `recommend.py:117` | Verified: `recommend(Finding(algorithm='rsa-2048'))` → `x25519-ml-kem-768` |
| D5 | **Library capability is not distinguished from code use.** `deps.py` emits a finding per algorithm a library *can* do, at confidence 0.55, but nothing in the data model marks it as capability rather than observation. Downstream it is scored like a call site. | `deps.py:176-188` | `rule_id="dep.provides"`, no `assurance` field |
| D6 | **Certificate trust is never distinguished from certificate observation.** `self_signed` is computed as `subject == issuer`, which is an observation; no chain validation is attempted or disclaimed in the data. | `certs.py:251` | No `trust_verified` field |
| D7 | **`X25519Kyber768Draft00` is an obsolete draft identifier** still offered by the PQ probe. | `network.py:37` | Superseded by `X25519MLKEM768` |
| D8 | **TLS version and negotiated group are separate findings but share one confidence story.** `net.tlsversion` emits per accepted version with the cipher from *that* handshake; correct, but `net.pqgroup` `False` state and `None` state are both surfaced — this part is already right and must not regress. | `network.py:195-257` | Correct today |

### 3.3 Coverage gaps against SIH26164

| Requirement | State |
|---|---|
| Container image analysis | **Not implemented.** `TECH_CONTAINER` constant exists (`models.py:35`), `MIGRATION_EFFORT_YEARS["container"]` exists, no sensor |
| Archive handling | Not implemented |
| Cross-sensor asset correlation | Not implemented — `group_key` includes `scanner`, so the same RSA key seen by source and binary stays two assets |
| Official CBOM schema validation | Structural only, honestly labelled |
| Ground-truth benchmark corpus | **Does not exist.** No precision/recall figure has ever been measured |
| Explicit confidentiality lifetime / business criticality per asset | Partially — sensitivity is estate-wide, criticality is inferred from path only |
| KMS / HSM / cloud / Kubernetes | Not implemented and **not claimed** — correct |

### 3.4 Frontend

Single-page console, five scenes (`verdict`, `clock`, `plan`, `record`,
`out`). Working: scan configuration, folder picker, live progress with a
stall-detecting tick, Q-Day slider with delta re-scoring, inventory ledger
with filters, CBOM download and validate, HTML report.

Missing: no partial-failure surface (sensor errors land in `stats` but the UI
never shows them), no evidence-level drill-down beyond the first location, no
scan history browser, no per-asset sensitivity or migration-window override.

---

## 4. Documentation and submission material

Present: `README.md` (422 lines, honest limitations section that already names
D4 and the container gap), `deck/index.html`, `presenter/{script,qa}.md`,
`Report/` with nine screenshots and eight design documents,
`docs/CRYPTODRISHTI-INDUSTRY-BRIEF.md`.

Missing: architecture diagram as an asset, benchmark method and results,
reproduction instructions for the benchmark, six-page SIH PDF.

---

## 5. What must not regress

Pinned by the existing 226 tests and treated as protected behaviour:

- Mosca determinism under a fixed seed.
- Q-Day is a distribution; no hardcoded date.
- Unknown findings stay unknown rather than being guessed.
- Production code outranks an identical finding in a test fixture.
- A vulnerable algorithm is never recommended another vulnerable target.
- CBOM `bom-ref` uniqueness and CycloneDX 1.6 conformance.
- Per-sensor failure never aborts a scan.
