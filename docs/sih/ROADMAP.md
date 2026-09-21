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

## M4 — Risk and migration intelligence  *(next)*

Closes R4.4–R4.8, R5.9.

Per-asset confidentiality lifetime, migration window and business criticality
overrides; purpose in the score; explainable factor list rendered next to each
number; Q-Day assumptions labelled as assumptions everywhere they appear.

## M5 — CBOM and reporting

Closes R2.3, R2.4, R6.2–R6.4.

Verify the current applicable CycloneDX version; add real schema validation
where a schema can be shipped or vendored; full chain report
(asset → evidence → classification → risk → recommendation → action)
including incomplete scans and unresolved findings.

## M6 — Benchmark and product experience

Closes R9.1–R9.3, R7.2, R7.4, R7.8.

A labelled corpus with positives **and negatives** (crypto-adjacent code that
must not fire), a harness that computes precision/recall/F1 per detector, and
publication of whatever the real numbers turn out to be. UI work on partial
failures, evidence drill-down and scan history.

## M7 — Submission readiness

Closes R10.2, R10.5, R10.6, R10.10, R10.11.

Architecture diagram asset, benchmark reproduction instructions, shipped demo
fixtures, the official six-section deck exported as a six-page PDF, and a
video script describing only what the product actually does.

---

## Rules held across every milestone

- No fabricated accuracy figures, no simulated backend behaviour.
- A feature is complete only when it runs and a test covers it.
- Existing scan history and the SQLite store stay readable.
- Only destinations the operator explicitly authorizes are probed.
- `main` is never force-pushed; nothing outside this repository is touched.
