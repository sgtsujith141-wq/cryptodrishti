"""Payment authorisation signing.

Demonstration 1: RSA used for SIGNING. The PSS padding object is what settles
the purpose, so this must be recommended a signature scheme (ML-DSA) and never
a KEM. Getting this wrong was the defect Milestone 2 existed to fix.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def sign_authorisation(private_key, payload: bytes) -> bytes:
    return private_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
