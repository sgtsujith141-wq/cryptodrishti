# Technical Reference

## Knowledge base

| Component | Size |
|---|---|
| Algorithms | **52** across 29 families |
| Source detection rules | **49** across 9 languages |
| Verified binary constants | **8** |
| Binary symbols | **72** |
| Version banner patterns | **9** |

Each algorithm entry carries: quantum class, classical strength in bits, NIST
security level, OID, public-key and signature sizes in bytes, deprecation and
disallowed dates, and a risk adjustment term.

Languages covered by the rule pack: C, C#, Go, Java, JavaScript, PHP, Python,
Ruby, plus language-agnostic rules.

---

## The six sensors

| # | Sensor | Technique | Reports |
|---|---|---|---|
| 01 | Source | Python `ast` for `.py`; curated rule pack for the rest | files scanned, language breakdown |
| 02 | Dependency | Manifests resolved to library crypto capability | manifests read |
| 03 | Certificate | X.509 key type, size, validity, signature algorithm | certificates parsed |
| 04 | Configuration | TLS, SSH, IPsec parameters as deployed | config files read |
| 05 | Binary | ELF symbol tables plus crypto constant byte-matching | binaries analysed, kinds |
| 06 | Network | Live TLS handshake including hybrid PQC groups | endpoints probed |

The certificate sensor resolves post-quantum OIDs — ML-DSA, ML-KEM, SLH-DSA —
which the underlying library does not yet name, so PQC test certificates parse
rather than crash.

The network sensor is **three-state**: supported, not supported, or **not
tested**. Python's `ssl` module cannot set post-quantum groups, so an
OpenSSL 3.5+ CLI fallback performs the real test where available.

---

## Exposure classes

| Class | Meaning | Examples |
|---|---|---|
| Broken by Shor | Destroyed outright | RSA, DH, ECDH, ECDSA, DSA |
| Weakened by Grover | Effective strength halved | AES-128, SHA-256, 3DES |
| Unresolved | Not determinable statically | opaque key material, indirect calls |
| Hybrid | Classical + PQC; safe if either holds | X25519 + ML-KEM-768 |
| Quantum-safe | Believed secure post-quantum | ML-KEM, ML-DSA, SLH-DSA, AES-256 |

---

## Risk model

**Quantum Risk Score** — 0 to 100, composed of named factors all surfaced in
the interface: quantum class, classical key strength, deployment context
(production / test / vendored), number of call sites, detection confidence,
NIST IR 8547 deprecation dates, and the Mosca exposure term.

Bands: medium at 25, high at 45, critical at 70.

**Q-Day model** — a distribution over 2030 / 2034 / 2044 (earliest / likely /
latest), defaults following the Global Risk Institute expert-survey range.
Never asserted as a date.

**Secrecy lifetimes (X)**

| Sensitivity | X | Typical use |
|---|---|---|
| Restricted | 25 yr | Defence, national security classification |
| Confidential | 10 yr | Commercial, financial records |
| Internal | 5 yr | Business operations |
| Public | 1 yr | Nothing sensitive |

---

## Recommendation profiles

| Profile | Key establishment | Signatures | Reasoning |
|---|---|---|---|
| General purpose | X25519 + ML-KEM-768 (hybrid) | ML-DSA-65 | Mainstream posture; already negotiated by browsers and OpenSSL 3.5+ |
| High assurance | ML-KEM-1024 | ML-DSA-87 | Category 5 parameters for material outliving Q-Day |
| Constrained / IoT | ML-KEM-512 | FN-DSA-512 | Smallest standardised sets; flagged where the link budget still cannot carry them |
| Firmware signing | — | SLH-DSA-128s | Hash-based; the most conservative assumption available |

The engine states the **size delta in bytes** for every recommendation, and
says so explicitly when no drop-in replacement exists.

---

## HTTP API

13 routes.

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Console, with the latest scan inlined so first paint is populated |
| POST | `/api/scan` | Start a scan; returns a scan id |
| GET | `/api/scan/{id}/status` | Progress, phase, detail, tick, state |
| GET | `/api/scan/{id}` | Full result — findings and summary |
| GET | `/api/scans` | Scan history |
| POST | `/api/qday` | Recompute against new assumptions — **returns deltas only** |
| GET | `/api/scan/{id}/cbom` | CycloneDX 1.6 document |
| GET | `/api/scan/{id}/cbom/validate` | Live structural validation |
| GET | `/api/scan/{id}/report` | Printable assessment |
| GET | `/api/browse` | Server-side directory listing for the folder picker |
| GET | `/api/meta` | Product metadata, profiles, sensitivities, presets |
| GET | `/api/knowledge/algorithms` | The algorithm registry |

---

## Command line

```bash
python run.py                    # start the console
python run.py --seed             # scan first so it opens populated
python run.py --seed-path PATH   # choose the seed target
python run.py --preflight        # 15 self-checks
python run.py --demo-reset       # wipe and restore the canonical demo state
python run.py --port N --open    # port choice, open a browser
```

## Interface URL parameters

| Parameter | Effect |
|---|---|
| `?theme=light\|dark` | Force a theme |
| `?still=1` | Disable count-up animation and smooth scrolling — for capture |
| `?compact=1` | Size every scene to its content so the deck prints as one page |
| `?explain=1` | Open with the Notes layer on |
| `?qday=YYYY` | Preset the Q-Day estimate |
| `?sensitivity=NAME` | Preset the secrecy lifetime |
