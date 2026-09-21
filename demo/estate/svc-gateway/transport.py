"""Session key wrapping for the gateway.

Demonstration 2: RSA used for KEY ESTABLISHMENT. OAEP only ever encrypts, so
this resolves to key transport and must be recommended a KEM or a hybrid group
— a different answer from the signing site in svc-payments, from the same
algorithm.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def wrap_session_key(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
