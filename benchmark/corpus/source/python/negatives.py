"""Negative cases: nothing on any line here is a cryptographic call site.

Every line is deliberately crypto-adjacent. A detector that fires on any of
them is trading precision for nothing.
"""

# We evaluated MD5, SHA-1 and RSA-2048 before choosing the current design.  # 6
DESIGN_NOTE = "The AES key is derived elsewhere; see the design document."   # 7

md5_migration_ticket = "PROJ-1421"                                # 9
sha256_column_name = "sha256_digest"                              # 10
blake2b_enabled = False                                           # 11
rsa_owner_email = "crypto-team@example.invalid"                   # 12
aes_config_path = "/etc/app/aes.conf"                             # 13


def describe() -> str:                                            # 16
    """Return prose about hashlib.md5 without calling it."""      # 17
    return "hashlib.md5 is not used in this module"                # 18


# A constant that looks like an S-box but is a lookup table for colours.
PALETTE = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]        # 22

# A variable named like a cipher mode.
ecb_layout_mode = "grid"                                          # 25
