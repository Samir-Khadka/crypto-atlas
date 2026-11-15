"""The rule catalogue: what v0.1 looks for, and what each rule means.

High-confidence only. A rule that cannot stay under the 5%
false-positive budget on the demo corpus gets narrowed or dropped.
"""
from __future__ import annotations

RULES: dict[str, dict] = {
    "rsa-keygen": {
        "name": "RSA key generation",
        "description": "An RSA key pair is generated here. RSA is "
                       "quantum-vulnerable: it belongs in the CBOM "
                       "and in the migration plan.",
        "fix": "Plan the move to ML-KEM for key exchange and ML-DSA "
               "for signatures; for now, use at least 2048 bits.",
        "change_difficulty": 1,
    },
    "ecc-keygen": {
        "name": "ECC key generation",
        "description": "An elliptic-curve key pair is generated here. "
                       "ECC is quantum-vulnerable: it belongs in the "
                       "CBOM and in the migration plan.",
        "fix": "Plan the move to ML-KEM / ML-DSA; for now, use at "
               "least P-256.",
        "change_difficulty": 1,
    },
    "weak-hash": {
        "name": "Weak hash (MD5, SHA1)",
        "description": "MD5 and SHA1 are broken for collision "
                       "resistance. If this is a file checksum rather "
                       "than a password or signature, it is safe to "
                       "ignore — mark it as accepted.",
        "fix": "Use SHA-256 (hashlib.sha256, crypto.createHash("
               "'sha256'), crypto/sha256).",
        "change_difficulty": 1,
    },
    "weak-cipher": {
        "name": "Weak cipher or mode (DES, 3DES, RC4, ECB)",
        "description": "DES, 3DES, and RC4 are broken; ECB mode leaks "
                       "plaintext patterns because identical blocks "
                       "encrypt identically.",
        "fix": "Use AES-256-GCM (an authenticated mode) instead.",
        "change_difficulty": 2,
    },
    "weak-random": {
        "name": "Weak randomness for a secret",
        "description": "A non-cryptographic random source is used to "
                       "make a key, token, password, or nonce. Its "
                       "output is predictable.",
        "fix": "Use the cryptographic source: secrets (Python), "
               "crypto.randomBytes (Node), crypto/rand (Go).",
        "change_difficulty": 1,
    },
    "hardcoded-key": {
        "name": "Hardcoded key or IV",
        "description": "A key or IV is written directly in the code. "
                       "Anyone who reads the source has the key.",
        "fix": "Load the key from a secret store or environment "
               "variable; never commit one.",
        "change_difficulty": 3,
    },
    "tls-disabled": {
        "name": "TLS verification disabled",
        "description": "Certificate verification is switched off, so "
                       "the connection can be intercepted.",
        "fix": "Remove the flag and let verification run; pin the "
               "certificate if the peer uses a private CA.",
        "change_difficulty": 1,
    },
    "tls-old-version": {
        "name": "Outdated TLS version or config",
        "description": "TLS 1.0 or 1.1 is allowed, or a config enables "
                       "old protocols or weak ciphers.",
        "fix": "Allow TLS 1.2 and 1.3 only; drop RC4, DES, and 3DES "
               "from the cipher list.",
        "change_difficulty": 1,
    },
    "pq-algorithm": {
        "name": "Post-quantum algorithm in use",
        "description": "A NIST post-quantum algorithm (ML-KEM, "
                       "ML-DSA, SLH-DSA) is already in use here. "
                       "This is a positive signal: it belongs in the "
                       "CBOM as migrated.",
        "fix": "None — already quantum-safe. Keep it in the CBOM.",
        "change_difficulty": 1,
    },
}
