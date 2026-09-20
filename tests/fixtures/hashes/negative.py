"""Labelled negatives: crypto-adjacent code that must NOT produce a finding.

A detector that fires here is trading precision for recall, and a CBOM full of
false positives is worse than a short one -- it costs a reviewer more to
dismiss each entry than the entry was ever worth.
"""

# Mentions in prose and comments. SHA3-512, BLAKE2b and MD5 all appear here.
DOC = "We considered SHA3-512 and BLAKE2b before settling on the current design."

# A variable whose name resembles an algorithm.
sha256_of_record = None
blake2b_enabled = False
md5_migration_ticket = "PROJ-1421"


def describe():
    # MD5 is named in a comment, which is not a call site.
    return "md5 is not used here"
