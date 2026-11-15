"""Clean: good patterns and known false-positive traps. Zero findings.

Note: RSA-4096 key generation is NOT in this file — it is a real
finding (weakness 3, quantum-vulnerable) and belongs in the CBOM,
so it cannot be "clean".
"""
import hashlib
import random
import secrets
import ssl

from Crypto.Cipher import AES

# good: SHA-256, AES-GCM, the secrets module, a default TLS context
digest = hashlib.sha256(b"hello").hexdigest()
token = secrets.token_bytes(32)
cipher = AES.new(secrets.token_bytes(32), AES.MODE_GCM,
                 nonce=secrets.token_bytes(12))
ctx = ssl.create_default_context()
# trap: random used for a test fixture, not a secret — no finding
sample = random.choice(["a", "b", "c"])
random.shuffle(sample)
