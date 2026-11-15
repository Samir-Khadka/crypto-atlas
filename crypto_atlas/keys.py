"""Key strength grading, shared by the config and TLS scanners.

Weakness follows the plan's scale: below the recommended minimum
is 5, the common-but-quantum-vulnerable default (RSA-2048, P-256)
is 4, stronger is 3.
"""
from __future__ import annotations


def weakness_for_rsa(size: int | None) -> int:
    if size is None or size < 2048:
        return 5
    return 4 if size == 2048 else 3


def weakness_for_curve(name: str | None) -> int:
    if not name:
        return 4
    if any(c in name for c in ("secp192", "secp224", "P-192", "P-224")):
        return 5
    if any(c in name for c in ("secp384", "secp521", "P-384", "P-521")):
        return 3
    return 4
