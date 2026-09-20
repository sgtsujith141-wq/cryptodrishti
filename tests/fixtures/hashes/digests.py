"""Ground truth for hash identity. One call per supported variant.

Every line here is a labelled positive: the algorithm named in the call is the
algorithm the scanner must report, at its real output length and in its real
family. The file exists because three of these were previously wrong --
SHA3-512 was recorded as SHA3-256, BLAKE2b as SHA-512, BLAKE2s as SHA-256 --
and nothing in the suite would have caught it.
"""

import hashlib

from cryptography.hazmat.primitives import hashes

hashlib.md5(b"x")
hashlib.sha1(b"x")
hashlib.sha224(b"x")
hashlib.sha256(b"x")
hashlib.sha384(b"x")
hashlib.sha512(b"x")
hashlib.sha3_224(b"x")
hashlib.sha3_256(b"x")
hashlib.sha3_384(b"x")
hashlib.sha3_512(b"x")
hashlib.shake_128(b"x")
hashlib.shake_256(b"x")
hashlib.blake2b(b"x")
hashlib.blake2s(b"x")

hashes.SHA3_224()
hashes.SHA3_256()
hashes.SHA3_384()
hashes.SHA3_512()
hashes.BLAKE2b(64)
hashes.BLAKE2s(32)
hashes.SHA512_224()
hashes.SHA512_256()
