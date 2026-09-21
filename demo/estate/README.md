# Demo estate

Synthetic. Nothing here is a real key, a real secret or real customer data.
Every file exists to demonstrate one behaviour of the scanner, and each says
which in its own docstring.

| Path | Demonstrates |
|---|---|
| `svc-payments/signing.py` | RSA resolved to **signing** → ML-DSA |
| `svc-gateway/transport.py` | RSA resolved to **key establishment** → hybrid KEM |
| `svc-gateway/requirements.txt` | a **capability-only** dependency |
| `svc-cache/digest.py` | hash identity: MD5, SHA3-512, BLAKE2b |
| `legacy/nginx.conf` | **declared** configuration policy |

The container image and its layers are generated at demo time by
`demo/build.py`; they are not committed.
