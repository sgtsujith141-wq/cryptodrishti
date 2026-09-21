"""Positive cases: every line here is a real cryptographic call site.

Line numbers matter — the manifest refers to them. Do not reformat.
"""

import hashlib                                                    # 6
import hmac                                                       # 7

from cryptography.hazmat.primitives import hashes                 # 9
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa   # 10
from cryptography.hazmat.primitives.ciphers import algorithms, modes     # 11

hashlib.md5(b"legacy checksum")                                   # 13
hashlib.sha1(b"legacy signature")                                 # 14
hashlib.sha256(b"modern")                                         # 15
hashlib.sha512(b"modern")                                         # 16
hashlib.sha3_256(b"sponge")                                       # 17
hashlib.sha3_512(b"sponge")                                       # 18
hashlib.blake2b(b"fast")                                          # 19
hashlib.blake2s(b"fast")                                          # 20
hashlib.shake_256(b"xof")                                         # 21

rsa.generate_private_key(public_exponent=65537, key_size=2048)    # 23
rsa.generate_private_key(public_exponent=65537, key_size=1024)    # 24

padding.PSS(mgf=None, salt_length=32)                             # 26
padding.OAEP(mgf=None, algorithm=None, label=None)                # 27
padding.PKCS1v15()                                                # 28

ec.SECP256R1()                                                    # 30
ec.SECP384R1()                                                    # 31

algorithms.AES(b"0" * 32)                                         # 33
algorithms.TripleDES(b"0" * 24)                                   # 34
algorithms.ChaCha20(b"0" * 32, b"0" * 16)                         # 35
modes.ECB()                                                       # 36
modes.GCM(b"0" * 12)                                              # 37

hashes.SHA3_512()                                                 # 39
hashes.BLAKE2b(64)                                                # 40
