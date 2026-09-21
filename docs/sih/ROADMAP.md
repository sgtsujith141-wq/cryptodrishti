# ROADMAP — engineering sequence from 90f4da3 to submission

Branch: `sih/milestone-hardening`, cut from `main` at `90f4da3`.
One commit per milestone. `main` is never force-pushed and never rewritten.

Ordering rationale: security first because the tool takes untrusted input and
makes outbound connections; detection correctness second because every
downstream number is built on it, and fixing risk or reporting on top of wrong
classification would be building on sand; coverage, intelligence, reporting
and measurement after that.

---

## M1 — Security hardening  *(complete)*

Closes R8.1–R8.9, S1–S9.

1. `app/netpolicy.py` — a destination policy module.
   - Parse `host`, `host:port`, `[v6]:port`, `scheme://host[:port]` correctly.
   - Resolve the name, then check **every** returned address against a deny
     set: loopback, private, link-local (incl. `169.254.169.254`), multicast,
     reserved, unspecified, IPv4-mapped IPv6. Connect to the vetted address,
     not to the name, so DNS cannot be re-resolved between check and connect.
   - Port allowlist, default `{443, 8443, 993, 995, 465, 587, 636, 22}`,
     overridable.
   - Opt-in `CD_ALLOW_PRIVATE_TARGETS` for a lab, off by default, and the
     relaxation is recorded on every finding it produced.
   - Cap the number of endpoints per scan.
2. `app/fspolicy.py` — filesystem boundary.
   - Resolve the scan root; reject any file whose real path escapes it.
   - Reject symlinked files whose target leaves the root.
   - Deny a configurable set of sensitive roots (`/etc`, `~/.ssh`, `/proc`,
     `/sys`, `/dev`, keychains) unless explicitly allowed.
3. `app/auth.py` + wiring — bearer-token middleware. Silent when bound to
   loopback; **required** the moment the bind address is not loopback, and the
   server refuses to start on a non-loopback bind with no token set.
4. Bounds: a scan semaphore, a wall-clock deadline that ends a scan cleanly and
   marks the result partial, `_JOBS` eviction.
5. Stop returning tracebacks to the client; log them server-side, return a
   stable error id.
6. Surface `sensor_errors`, policy refusals and partial completion in the API
   payload so the operator sees them.
7. Adversarial tests using controlled local fixtures only — no unauthorized
   external hosts.

**Exit criteria:** every S1–S9 item has a test that fails without the fix.
Existing 226 tests still pass.

## M2 — Detection correctness  *(complete)*

Closed D1–D7, R3.3–R3.10, R4.8–R4.9, R5.1, R5.2, R5.10.

**What shipped.** `knowledge/purposes.py` makes cryptographic purpose a
property of the finding, resolved from the call site, rather than a property
of the algorithm name. RSA now carries two purposes in the registry, so
nothing downstream can infer one; the detector resolves it from the padding
object (PSS signs, OAEP encrypts, PKCS#1 v1.5 resolves nothing), the API
called, or a certificate's KeyUsage extension, and where none of those
settle it the recommendation says so instead of guessing.

The registry grew from 52 to 74 entries: the full SHA-3 family, SHAKE, BLAKE2b
/ BLAKE2s / BLAKE3, the truncated SHA-512 variants, and five block ciphers
that were previously collapsed to `unknown`. MD2 is no longer aliased onto MD5.

`Evidence.assurance` distinguishes capability, declared, used and observed,
and is a named factor in the risk score separate from confidence. The
confidence bump for repeated sightings was removed: forty matches from one
rule are forty chances for that rule to be wrong in the same way.

TLS reporting was split into four independent findings — version, cipher
suite, key exchange, authentication — and a refused hybrid probe now yields
`unknown` rather than naming ECDH it never saw.

**Verified against.** A local TLS 1.3 server (negotiated X25519MLKEM768, read
from the handshake) and a local TLS 1.2 server (suite decomposed to
ECDHE + RSA; PQ group correctly reported as unobserved). Both on loopback,
under `CD_ALLOW_PRIVATE_TARGETS`. 413 tests pass. The eleven tests that matter
most were confirmed to fail when the defects were temporarily reintroduced.

**Original plan, for the record:**

1. Register the full SHA-3 family (224/384/512), SHAKE128/256, BLAKE2b,
   BLAKE2s, BLAKE3; fix `_PY_HASHES` and `_norm_alg`.
2. Split RSA by purpose: `rsa-*-sig` vs `rsa-*-enc`, resolved from the call
   site where the detector can tell (`PSS`/`PKCS1v15`-sign/`sign()`/
   certificate signature ⇒ signature; `OAEP`/`encrypt()` ⇒ key transport) and
   left as unresolved-purpose otherwise. Recommend ML-DSA for the first,
   ML-KEM/hybrid for the second, and **both with a caveat** for the third
   rather than guessing. Replace the test that pins the current behaviour.
3. Add an `assurance` dimension to `Evidence`: `capability` (a library can do
   it) / `declared` (configuration says so) / `used` (a call site) /
   `observed` (seen on the wire). Feed it into confidence and make it visible
   in the CBOM and the UI.
4. Certificates: record `trust_verified: false` explicitly and say chain
   validation was not attempted.
5. Drop `X25519Kyber768Draft00` from the offered groups; keep parsing it if a
   server names it, labelled obsolete.
6. Purpose becomes an input to the risk score.

**Exit criteria:** a test for each corrected identification; no finding gains
precision it did not earn.

## M3 — Scanning coverage  *(complete)*

Closed R1.7, R2.5, R11.1-R11.8.

**What shipped.** `app/container.py` reads OCI layout directories, OCI tar
archives and `docker save` archives with no daemon, no network and no
privileged access. Nothing is ever extracted: members are streamed into memory
and analysed there, which is both the security property and the reason there
is no cleanup path to get wrong. Every member is vetted for traversal,
absolute paths, drive letters, control characters, link escapes and special
files before a byte is read, and member count, per-file size, total
uncompressed bytes, nesting depth and wall clock are all bounded.

`app/scanners/container.py` reuses the existing source, binary, config,
manifest and certificate analysers rather than reimplementing detection, so an
ELF inside an image is analysed by the code that analyses an ELF on disk, at
the same confidence, recording the technique that actually ran. Layers are
replayed in order with `.wh.` and `.wh..wh..opq` whiteout handling, so a file
deleted by a later layer is reported as **historical** — still extractable, so
still inventoried, but not part of what the image runs.

`app/engine/correlate.py` links findings that share a concrete artefact: the
same file, the same file in the same layer, or the same identified component.
It never merges. Findings are bucketed by `(algorithm, purpose)` before any
linking, so RSA signing can never join RSA key establishment; assurance and
confidence are never written to; and disagreements are recorded rather than
resolved.

**Verified against.** A generated OCI archive scanned through a live server on
port 8123: 23 assets across 2 layers from 5 analysed files, 1 historical
finding (a private key deleted by the next layer), 2 evidence-backed logical
assets, and a CycloneDX 1.6 CBOM that validates and carries image digest,
layer digest and effective state per component. 487 tests pass.

**Two real bugs were found by this verification, not by the tests:**

1. Container findings all carried `scanner = "container"`, so normalisation
   merged a source call site with a binary symbol — a distinction a directory
   scan preserves. The scanner name now keeps the inner analyser.
2. A `requirements.txt` declaring several libraries mapped its path to
   whichever parsed first, producing a false correlation between MD5 from
   pycryptodome and an OpenSSL binary. A path now maps to a component only
   when every library-naming finding there agrees.

**Original plan, for the record:**

1. Container images, read-only: OCI layout directories, `docker save` tars,
   and `.tar`/`.tar.gz` layers. Bounded extraction with a decompression-ratio
   cap, entry-count cap, byte cap and path-traversal rejection. Analyse layer
   contents with the existing sensors rather than writing a parallel one.
2. Document supported formats and limitations honestly; claim nothing about
   registries, KMS, HSM, cloud or Kubernetes.
3. Cross-sensor logical correlation: group the same logical asset across
   sensors **while preserving each original evidence item's technique,
   confidence and assurance**. Correlation is presentation, never erasure.

## M4 — Risk and migration intelligence  *(complete)*

Closed R4.4–R4.16, R5.9, R5.11, R5.12.

**What shipped.** `app/assessment.py` makes confidentiality lifetime,
migration duration, business criticality, sensitivity and deployment
constraints per-asset and operator-settable, validated and bounded, persisted
in their own table outside the scan lifecycle. Every input on screen carries
its origin — observed, derived, operator-supplied or an unreviewed default —
because a score built from four guesses and one built from four reviewed
values look identical unless the tool says which is which.

Override identity is `assessment.asset_key`: algorithm, asset type, purpose,
scanner and location with line numbers stripped. It survives edits elsewhere
in the file and a rescan; it deliberately does not survive a file move or a
newly resolved purpose, because each of those is a different migration.

Three exposure models replace the single confidentiality reading. Signatures
are no longer described as a confidentiality problem: a CRQC cannot un-sign a
release, so X becomes a trust horizon and `retroactive` is recorded as false.

**Two mathematical defects, both found by reading the code and confirmed by
running it:**

1. `QDayModel.years_from` returned `likely - now` and its docstring called it
   "Z at the median". `likely` is the **mode** of a triangular distribution.
   For the shipped defaults the true median is 2035.63, not 2034 — a 1.6-year
   error, always understating exposure. Both are now computed and reported,
   with the mode kept as the default basis because that is what the slider sets.
2. `score_finding` wrote its mosca and factor records with `setdefault`, so a
   rescored finding showed a **new risk score beside the previous
   assessment's arithmetic**. The API worked around it by popping keys first,
   which meant every caller had to remember. Now it overwrites.

**Verified against.** A live server on port 8124 over a two-service estate:
preview changed risk 59.5 → 100.0 and wrote nothing; an explicit save applied
to one asset and left the other on derived inputs; the override survived a
server restart and a rescan; the CBOM validated and carried the operator's
four inputs with provenance alongside `assessment:qdayIsForecast=false`. 557
tests pass.

**Original plan, for the record:**

Per-asset confidentiality lifetime, migration window and business criticality
overrides; purpose in the score; explainable factor list rendered next to each
number; Q-Day assumptions labelled as assumptions everywhere they appear.

## M5 — CBOM and reporting  *(complete)*

Closed R2.3, R2.4, R2.6, R6.2–R6.6.

**What shipped.** The official CycloneDX 1.6 and 1.7 JSON Schemas are vendored
under `app/schemas/cyclonedx` at a pinned upstream commit, checksummed on load
so a locally edited schema is refused rather than trusted, and validated
against offline with no network call. The hand-written structural check stays,
reported separately and never as conformance; a run where official validation
could not happen reports `checked: false`, because a check that silently did
not run is worse than one that failed. CI validates directory-scan and
container-scan CBOMs in both versions and fails on any violation.

CycloneDX 1.7 is a genuine implementation rather than a relabelled 1.6. Its
`algorithmFamily` enum splits RSA by purpose, which means an RSA finding whose
purpose M2 could not resolve gets **no** family — the correct answer falling
out of the earlier work rather than needing a special case.

The report gained a scan-integrity section that says plainly when an inventory
is partial and why, and a full inventory in which **every** asset carries a
six-step traced chain from evidence to action. The executive table still shows
fifteen; it is now labelled as a ranking of the full set rather than standing
in for it.

**Eight emitter defects found by auditing field-by-field against the schema,
each reproduced before being changed.** Four were hard schema violations
(`mode`, `padding`); the rest were semantic and a schema could never have
caught them: dependencies emitted as cryptographic algorithms, an execution
environment asserted rather than observed, a security strength reported as a
parameter set, a certificate reference holding a name instead of a bom-ref.

**One was a leak.** A hardcoded secret the scanner found was exported verbatim
into the CBOM — a document made to be attached to tickets and sent to vendors.
Redaction was added, and the first attempt was itself wrong twice: too blunt
(it ate `AES/ECB/PKCS5Padding`, the most informative field in a Java finding)
and then incomplete (it redacted `additionalContext` while the same secret sat
in `symbol` one field over).

**Verified against.** A live server on port 8125: a partial scan with a refused
endpoint, an operator override saved and applied, both CBOM versions passing
official schema validation with zero problems, and a 63 KB report carrying
eight traced chains, the partial-scan banner, the refusal, operator-versus-
derived provenance, and no secret anywhere in it. 617 tests pass.



Closes R2.3, R2.4, R6.2–R6.4.

Verify the current applicable CycloneDX version; add real schema validation
where a schema can be shipped or vendored; full chain report
(asset → evidence → classification → risk → recommendation → action)
including incomplete scans and unresolved findings.

## M6 — Benchmark and product experience  *(complete)*

Closed R9.1–R9.4, R7.2, R7.4, R7.8.

**What shipped.** `benchmark/` holds a hand-labelled corpus — source in five
languages, dependency manifests, configuration, generated binaries,
certificates and an OCI image — with a versioned manifest whose changelog
records every label correction, its justification and its effect on the score.
Binaries, certificates and images are generated at benchmark time rather than
committed, because a committed private key is a private key in a repository
however loudly the filename says otherwise.

`benchmark/run.py` measures TP, FP, FN, precision, recall and F1 per scanner
and overall, with purpose and assurance scored separately over the true
positives. Matching is one-to-one on a distinct `(file, line, algorithm)` with
exact algorithm keys; duplicates are collapsed first so one artefact reported
by two rules cannot inflate the score. CI runs it and fails below a floor.

**Seven detector defects, none of which reading the code had found:**

1. A hyphen inside a cipher name treated as an OpenSSL exclusion marker, so
   `ECDHE-RSA-AES256` silently dropped RSA and AES-256 — four false negatives,
   all in the direction that makes an estate look cleaner than it is.
2. `TLSv1` matching inside `TLSv1.2`, because `\b` treats the dot as a word
   boundary. TLS 1.0 reported as enabled on a server offering only 1.2 and 1.3.
3. `DES` matching inside `DES-CBC3`, which is Triple DES.
4. `HmacSHA256` unresolved — a MAC whose name states exactly what it is.
5. The ECB rule asserting `aes` for every match, producing an AES finding from
   `RSA/ECB/OAEPPadding` in a file with no AES in it.
6. Certificate signature digests inventoried only when broken, so a healthy
   estate's CBOM listed no certificate hash functions at all.
7. Binary symbols whose names state the operation — `RSA_sign` — leaving the
   purpose unresolved. The M2 purpose work had never reached the sensor that
   exists to read vendor binaries where no source is available.

Defect 7's first fix introduced 7b: every `_encrypt` mapped to key
establishment, which claimed `AES_encrypt` was wrapping keys. The next run
caught it. A double-count in the harness itself was found by its own tests —
negative-file hits were counted twice, understating precision.

**UI.** Scene 06 lists every stored scan with target, date, kind, status and
count, and reopens any of them with its report and CBOM. A partial scan now
says so in a banner above the verdict rather than leaving it in the payload.
Correlated findings are shown as followable peers with their own evidence: a
link you can follow is evidence, a link you cannot is an assertion. Loading,
empty and error states are real, and a refused scan reports its reason and the
server-log reference rather than "failed".

**Verified.** A live server on port 8126: a partial scan with a refused
endpoint, 29 assets, both CBOM versions passing official schema validation with
zero problems, a 169 KB report with 29 traced chains, history listing the scan
as PARTIAL, and no secret in any output. 664 tests pass.



## M7 — Submission readiness  *(complete, with two items open)*

Closed R10.1–R10.10, R10.12, R10.14. **R10.11 is BLOCKED and R10.13 is a GAP** —
see below.

**What shipped.**

*Architecture.* `docs/architecture/architecture.mmd` is the editable source;
SVG and PNG are rendered from it. It shows container archive processing as its
own input, and draws the TLS probe dashed because it is the only path that
leaves the machine. It has no box for a cloud provider, a KMS, an HSM or a
registry, because none of those integrations exists.

*Demo.* `python run.py --demo` builds a container image and certificates from
committed synthetic fixtures, scans a synthetic estate — deliberately including
one endpoint the destination policy refuses, so the scan finishes PARTIAL with
its reason — scans the image with layer replay, and saves an operator override
that survives the rescan. `--preflight-offline` checks every dependency the
demo needs without touching the network, and fails if any file carrying a
`PRIVATE KEY` marker is not also marked synthetic.

*Deck.* `submission/CryptoDrishti-SIH26164-Idea-Presentation.pptx`, built by
script from the official template. Exactly six slides: the template ships a
seventh whose own text says to keep the deck to six, so the build removes it.
The template's backgrounds, branding, section titles, footer and numbering are
untouched. `submission/build/check_deck.py` fails if any shape leaves the
canvas, collides with another or runs into the footer bar, and counts the
portal fields still unfilled.

*Benchmark presentation.* The README now gives both result sets separately —
the like-for-like improvement on the unchanged original corpus, and the current
corpus — each traceable to a committed JSON file, each with the sentence saying
it measures a synthetic corpus and not real-world accuracy, and with the corpus
gaps named.

**What the audit removed, which was the more useful half.** `presenter/script.md`
and `presenter/qa.md` asserted a set of specific national policy deadlines, a
fixed year by which recorded traffic would be read, and what three named
commercial products could and could not do. None of it could be sourced from
this repository, so it was removed rather than reworded. Three documentation
claims were also corrected against the code:

1. The source rule packs cover **eight** languages with specific rules, not ten.
   Rust and Swift are recognised by extension but reach only the four
   language-agnostic rules, so they are effectively uncovered — now stated as a
   limitation.
2. The algorithm registry holds **74** entries, not 52. The README's
   classification counts were wrong in three places.
3. `python -m app.cli` runs the **source sensor only**. The README presented it
   as a general scan, so its CBOM was a silent subset — 7 assets against the
   console's 23 for the same directory. Documented, not quietly widened.

The Python 3.11 syntax guard was widened from `app/` and `tests/` to every
Python file git tracks, driven by `git ls-files` so it cannot wander into the
third-party clones under `demo/targets/`.

**Open, and recorded as open.**

- **R10.11 — six-page submission PDF: BLOCKED.** The problem-statement title,
  theme, team ID and team name are not recoverable from this repository. The
  build writes each as a visible `[FILL FROM SIH PORTAL]` marker and refuses to
  guess; `check_deck.py` counts them and says the deck is not submittable while
  the count is above zero.
- **R10.13 — demonstration video: GAP.** `presenter/video.md` is a script and a
  shot list. No recording exists, and nothing in the repository says otherwise.

**Verified.** 664 tests pass. The benchmark reproduces 116/0/0 at P = R = F1 =
1.000 with the committed ground truth unmodified. Both CBOM versions pass
official schema validation. The demo runs end to end from a clean database:
23 assets PARTIAL for the estate, 15 COMPLETE for the image. A repository-wide
check of every file git would commit finds no unmarked key material, cloud
credential or token. All 91 tracked Python files parse under Python 3.11.

---

## Rules held across every milestone

- No fabricated accuracy figures, no simulated backend behaviour.
- A feature is complete only when it runs and a test covers it.
- Existing scan history and the SQLite store stay readable.
- Only destinations the operator explicitly authorizes are probed.
- `main` is never force-pushed; nothing outside this repository is touched.
