"""The Python case, where the padding object is the signal.

PSS only ever signs. OAEP only ever encrypts. PKCS#1 v1.5 does both, which is
why it must resolve nothing.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
padding.PKCS1v15()
