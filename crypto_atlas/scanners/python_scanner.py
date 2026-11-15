"""Python scanner: exact, using the stdlib ast.

Tracks imports so aliases resolve (``from hashlib import md5`` and
``import hashlib as hl`` both fire the weak-hash rule). A finding
fires only on a call the scanner can name — no guessing from bare
text.
"""
from __future__ import annotations

import ast

from ..findings import Finding
from ..rules import RULES

# variable names that suggest a value is a secret
_SECRET_NAMES = ("key", "token", "secret", "password", "passwd",
                 "nonce", "salt", "iv")

# ECC curves, weakest first (the scanner maps a curve name to a
# weakness: below P-256 is 5, P-256 is 4, above is 3)
_WEAK_CURVES = {"SECP192R1", "SECP224R1", "SECP192K1", "SECT163R1",
                "SECT163K1", "SECT233R1", "BRAINPOOLP160R1"}
_STRONG_CURVES = {"SECP384R1", "SECP521R1", "BRAINPOOLP384R1",
                  "BRAINPOOLP512R1"}


def _dotted(node: ast.AST) -> str | None:
    """The dotted name of a Name/Attribute chain, or None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _int_arg(node: ast.Call, index: int = 0,
             keyword: str | None = None) -> int | None:
    """An integer literal argument, by position or keyword."""
    if keyword:
        for kw in node.keywords:
            if kw.arg == keyword and isinstance(kw.value, ast.Constant) \
                    and isinstance(kw.value.value, int):
                return kw.value.value
        return None
    if len(node.args) > index \
            and isinstance(node.args[index], ast.Constant) \
            and isinstance(node.args[index].value, int):
        return node.args[index].value
    return None


def _str_arg(node: ast.Call, index: int = 0) -> str | None:
    if len(node.args) > index \
            and isinstance(node.args[index], ast.Constant) \
            and isinstance(node.args[index].value, str):
        return node.args[index].value
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str]):
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        # imported name -> full dotted path
        self.aliases: dict[str, str] = {}

    def _line(self, node: ast.AST) -> str:
        n = getattr(node, "lineno", 1)
        return self.lines[n - 1].strip() if 0 < n <= len(self.lines) \
            else ""

    def _add(self, rule_id: str, node: ast.AST, algorithm: str,
             weakness: int, evidence: str, **kw) -> None:
        rule = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id, algorithm=algorithm, weakness=weakness,
            file=self.path, line=getattr(node, "lineno", 1),
            snippet=self._line(node), evidence=evidence,
            fix=rule["fix"], language="python",
            change_difficulty=rule["change_difficulty"], **kw))

    def _resolve(self, name: str | None) -> str | None:
        """Resolve the first segment through the import aliases."""
        if not name:
            return None
        head, _, rest = name.partition(".")
        full = self.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full

    # -- imports ------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = \
                alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.aliases[name] = f"{module}.{alias.name}" if module \
                else alias.name
        self.generic_visit(node)

    # -- calls --------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(_dotted(node.func))
        if name:
            self._check_call(node, name)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call, name: str) -> None:
        # weak hash
        if name in ("hashlib.md5", "hashlib.sha1"):
            algo = "MD5" if name.endswith("md5") else "SHA1"
            self._add("weak-hash", node, algo, 5,
                      f"{algo} used here", primitive="hash",
                      parameter_set=algo)
            return
        # RSA key generation
        if name.endswith("RSA.generate_private_key") or \
                name == "Crypto.PublicKey.RSA.generate":
            size = _int_arg(node, 1, "key_size") \
                or _int_arg(node, 0) \
                or _int_arg(node, 0, "bits")
            weakness = 5 if size is None or size < 2048 else \
                4 if size == 2048 else 3
            self._add("rsa-keygen", node, "RSA", weakness,
                      f"RSA key generated ({size or 'unknown'} bits)",
                      key_size=size, primitive="pke",
                      parameter_set=f"RSA-{size}" if size else "RSA")
            return
        if name.endswith("rsa.generate_private_key"):
            size = _int_arg(node, 1, "key_size") or _int_arg(node, 0)
            weakness = 5 if size is None or size < 2048 else \
                4 if size == 2048 else 3
            self._add("rsa-keygen", node, "RSA", weakness,
                      f"RSA key generated ({size or 'unknown'} bits)",
                      key_size=size, primitive="pke",
                      parameter_set=f"RSA-{size}" if size else "RSA")
            return
        # ECC key generation
        if name.endswith("ec.generate_private_key") or \
                name == "Crypto.PublicKey.ECC.generate":
            curve = _str_arg(node, 0)
            if not curve:
                for kw in node.keywords:
                    if kw.arg == "curve":
                        curve = _dotted(kw.value) or ""
            weakness = 5 if curve in _WEAK_CURVES else \
                3 if curve in _STRONG_CURVES else 4
            self._add("ecc-keygen", node, "ECC", weakness,
                      f"ECC key generated (curve {curve or 'unknown'})",
                      curve=curve or None, primitive="signature",
                      parameter_set=curve or "ECC")
            return
        # weak ciphers
        if name in ("Crypto.Cipher.DES.new", "Crypto.Cipher.ARC4.new",
                    "Crypto.Cipher.DES3.new"):
            algo = name.split(".")[-2]
            self._add("weak-cipher", node, algo, 5,
                      f"{algo} used here", primitive="block-cipher"
                      if algo != "ARC4" else "stream-cipher",
                      parameter_set=algo)
            return
        if name == "Crypto.Cipher.AES.new":
            # AES.new(key, mode, iv?) — the mode is args[1], or the
            # mode= keyword
            mode = None
            if len(node.args) > 1:
                mode = _dotted(node.args[1])
            if not mode:
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode = _dotted(kw.value)
            if mode and mode.endswith("MODE_ECB"):
                self._add("weak-cipher", node, "AES-ECB", 5,
                          "AES in ECB mode", primitive="block-cipher",
                          parameter_set="AES-ECB")
            self._check_hardcoded_key(node)
            return
        # weak randomness passed straight into a crypto call is
        # caught by the assignment heuristic in visit_Assign (the
        # high-confidence signal); a bare random.* call on its own
        # is not flagged, so test fixtures and shuffles stay clean
        # TLS disabled / old version
        if name in ("ssl.PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1"):
            self._add("tls-old-version", node, "TLS 1.0/1.1", 5,
                      "TLS 1.0 or 1.1 explicitly selected",
                      asset_type="protocol", primitive=None,
                      parameter_set="TLS 1.0/1.1")
            return
        if name == "ssl._create_unverified_context":
            self._add("tls-disabled", node, "TLS", 5,
                      "unverified SSL context (no certificate check)",
                      asset_type="protocol", parameter_set="TLS")
            return
        # post-quantum: already migrated, record it as a positive
        if "mlkem" in name.lower() or "ml_kem" in name.lower() \
                or "mldsa" in name.lower() or "ml_dsa" in name.lower() \
                or "slhdsa" in name.lower() or "slh_dsa" in name.lower():
            algo = "ML-KEM" if "kem" in name.lower() else \
                "ML-DSA" if "dsa" in name.lower() else "SLH-DSA"
            self._add("pq-algorithm", node, algo, 1,
                      f"{algo} in use (already quantum-safe)",
                      primitive="kem" if algo == "ML-KEM" else "signature",
                      parameter_set=algo)
            return

    def _check_hardcoded_key(self, node: ast.Call) -> None:
        for arg in node.args:
            if isinstance(arg, ast.Constant) \
                    and isinstance(arg.value, (bytes, str)) \
                    and len(arg.value) >= 16:
                self._add("hardcoded-key", node, "AES key", 5,
                          "a key is written directly in the code",
                          asset_type="related-crypto-material",
                          primitive=None, parameter_set="secret-key")
                return

    # -- assignments: check_hostname = False, and weak randomness
    # by target name ---------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            tname = _dotted(target)
            if tname and tname.endswith("check_hostname") \
                    and isinstance(node.value, ast.Constant) \
                    and node.value.value is False:
                self._add("tls-disabled", node, "TLS", 5,
                          "hostname checking disabled",
                          asset_type="protocol", parameter_set="TLS")
        # weak randomness by target name (see above)
        for target in node.targets:
            tname = _dotted(target)
            if not tname:
                continue
            low = tname.lower()
            if any(s in low for s in _SECRET_NAMES) \
                    and isinstance(node.value, ast.Call):
                called = self._resolve(_dotted(node.value.func))
                if called and called.startswith("random."):
                    self._add("weak-random", node.value, "random", 5,
                              f"non-cryptographic random used for "
                              f"'{tname}'", primitive="other",
                              parameter_set="random")
        self.generic_visit(node)

    # -- attribute use: CERT_NONE, PROTOCOL_TLSv1 ---------------
    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = self._resolve(_dotted(node))
        if name == "ssl.CERT_NONE":
            self._add("tls-disabled", node, "TLS", 5,
                      "certificate verification disabled (CERT_NONE)",
                      asset_type="protocol", parameter_set="TLS")
        elif name in ("ssl.PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1"):
            # an attribute, not a call: SSLContext(PROTOCOL_TLSv1)
            version = "TLS 1.0" if name.endswith("TLSv1") else "TLS 1.1"
            self._add("tls-old-version", node, version, 5,
                      f"{version} explicitly selected",
                      asset_type="protocol", parameter_set=version)
        self.generic_visit(node)


def scan_python(path: str, text: str) -> list[Finding]:
    """Scan one Python file. Returns findings (empty when clean)."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    visitor = _Visitor(path, text.splitlines())
    visitor.visit(tree)
    return visitor.findings
