"""JavaScript / TypeScript scanner, via tree-sitter.

Walks ``call_expression`` nodes and matches on the function text.
Assignment context (for weak randomness) comes from the parent
node: ``Math.random()`` only fires when its result lands in a
secret-named variable or a crypto call.
"""
from __future__ import annotations

from tree_sitter import Language, Parser

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from ..findings import Finding
from ..rules import RULES
from .tsutil import (call_args, call_function_text, node_text,
                     object_pairs, parent_map, string_value, walk)

_JS = Language(tsjs.language())
_TS = Language(tsts.language_typescript())

_SECRET_NAMES = ("key", "token", "secret", "password", "passwd",
                 "nonce", "salt", "iv")


def _weakness_for_rsa(modulus: int | None) -> int:
    if modulus is None or modulus < 2048:
        return 5
    return 4 if modulus == 2048 else 3


def _weakness_for_curve(curve: str | None) -> int:
    if not curve:
        return 4
    low = curve.lower()
    if any(c in low for c in ("p-192", "p-224", "secp192", "secp224")):
        return 5
    if any(c in low for c in ("p-384", "p-521", "secp384", "secp521")):
        return 3
    return 4


class _Scanner:
    def __init__(self, path: str, source: bytes, language: str):
        self.path = path
        self.source = source
        self.language = language
        self.findings: list[Finding] = []
        self.lines = source.decode("utf-8", errors="replace") \
            .splitlines()

    def _line(self, node) -> str:
        row = node.start_point[0]
        return self.lines[row].strip() if 0 <= row < len(self.lines) \
            else ""

    def _add(self, rule_id: str, node, algorithm: str, weakness: int,
             evidence: str, **kw) -> None:
        rule = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id, algorithm=algorithm, weakness=weakness,
            file=self.path, line=node.start_point[0] + 1,
            snippet=self._line(node), evidence=evidence,
            fix=rule["fix"], language=self.language,
            change_difficulty=rule["change_difficulty"], **kw))

    def scan(self, tree) -> list[Finding]:
        for node, ancestors in walk(tree.root_node):
            if node.type == "call_expression":
                self._check_call(node, ancestors)
        return self.findings

    def _check_call(self, node, ancestors) -> None:
        func = call_function_text(node, self.source)
        if not func:
            return
        args = call_args(node, self.source)

        # weak hash / hmac
        if func in ("crypto.createHash", "crypto.createHmac") \
                and args:
            algo = string_value(args[0], self.source)
            if algo and algo.lower() in ("md5", "sha1"):
                self._add("weak-hash", node, algo.upper(), 5,
                          f"{algo.upper()} used here", primitive="hash",
                          parameter_set=algo.upper())
            return
        # RSA / ECC key generation (sync and async forms)
        if func in ("crypto.generateKeyPair",
                    "crypto.generateKeyPairSync") and args:
            kind = string_value(args[0], self.source)
            opts = object_pairs(args[1], self.source) \
                if len(args) > 1 else {}
            if kind == "rsa":
                size = None
                raw = opts.get("modulusLength", "")
                if raw.isdigit():
                    size = int(raw)
                self._add("rsa-keygen", node, "RSA",
                          _weakness_for_rsa(size),
                          f"RSA key pair generated "
                          f"({size or 'unknown'} bits)",
                          key_size=size, primitive="pke",
                          parameter_set=f"RSA-{size}" if size else "RSA")
            elif kind == "ec":
                curve = opts.get("namedCurve", "").strip("\"'")
                self._add("ecc-keygen", node, "ECC",
                          _weakness_for_curve(curve),
                          f"ECC key pair generated (curve "
                          f"{curve or 'unknown'})",
                          curve=curve or None, primitive="signature",
                          parameter_set=curve or "ECC")
            return
        # WebCrypto generateKey
        if func in ("crypto.subtle.generateKey",
                    "subtle.generateKey") and args:
            opts = object_pairs(args[0], self.source)
            name = opts.get("name", "").strip("\"'").lower()
            if "rsa" in name:
                size = None
                raw = opts.get("modulusLength", "")
                if raw.isdigit():
                    size = int(raw)
                self._add("rsa-keygen", node, "RSA",
                          _weakness_for_rsa(size),
                          f"RSA key generated via WebCrypto "
                          f"({size or 'unknown'} bits)",
                          key_size=size, primitive="pke",
                          parameter_set=f"RSA-{size}" if size else "RSA")
            elif "ecdsa" in name or "ecdh" in name:
                curve = opts.get("namedCurve", "").strip("\"'")
                self._add("ecc-keygen", node, "ECC",
                          _weakness_for_curve(curve),
                          f"ECC key generated via WebCrypto (curve "
                          f"{curve or 'unknown'})",
                          curve=curve or None, primitive="signature",
                          parameter_set=curve or "ECC")
            return
        # weak ciphers
        if func == "crypto.createCipheriv" and args:
            algo = string_value(args[0], self.source) or ""
            low = algo.lower()
            if "ecb" in low:
                self._add("weak-cipher", node, "AES-ECB", 5,
                          "AES in ECB mode", primitive="block-cipher",
                          parameter_set="AES-ECB")
            elif low.startswith(("des", "3des", "des-ede")):
                self._add("weak-cipher", node, "DES/3DES", 5,
                          f"{algo} used here", primitive="block-cipher",
                          parameter_set=algo.upper())
            elif low.startswith("rc4"):
                self._add("weak-cipher", node, "RC4", 5,
                          "RC4 used here", primitive="stream-cipher",
                          parameter_set="RC4")
            return
        if func == "crypto.createCipher" and args:
            self._add("weak-cipher", node, "createCipher", 5,
                      "crypto.createCipher is deprecated and defaults "
                      "to ECB-like behaviour",
                      primitive="block-cipher", parameter_set="ECB")
            return
        # TLS disabled / old version
        if func in ("tls.connect", "https.request", "https.get") \
                and args:
            for arg in args:
                opts = object_pairs(arg, self.source)
                if opts.get("rejectUnauthorized", "").lower() == "false":
                    self._add("tls-disabled", node, "TLS", 5,
                              "certificate verification disabled "
                              "(rejectUnauthorized: false)",
                              asset_type="protocol", parameter_set="TLS")
                    return
                version = opts.get("minVersion", "").strip("\"'")
                if version in ("TLSv1", "TLSv1.1"):
                    self._add("tls-old-version", node, version, 5,
                              f"TLS {version} explicitly allowed",
                              asset_type="protocol",
                              parameter_set=version)
                    return
            return
        # weak randomness, by assignment context
        if func == "Math.random":
            target = self._secret_target(ancestors)
            if target:
                self._add("weak-random", node, "random", 5,
                          f"Math.random() used for '{target}'",
                          primitive="other", parameter_set="random")
            return
        # post-quantum: already migrated
        low = func.lower()
        if "mlkem" in low or "ml-kem" in low or "mldsa" in low \
                or "ml-dsa" in low or "slhdsa" in low \
                or "slh-dsa" in low:
            algo = "ML-KEM" if "kem" in low else \
                "ML-DSA" if "dsa" in low else "SLH-DSA"
            self._add("pq-algorithm", node, algo, 1,
                      f"{algo} in use (already quantum-safe)",
                      primitive="kem" if algo == "ML-KEM" else "signature",
                      parameter_set=algo)
            return

    def _secret_target(self, ancestors) -> str | None:
        """The secret-named variable this call's result lands in,
        climbing the ancestor chain (the call may sit inside a
        chained call like Math.random().toString(36))."""
        for parent in reversed(ancestors):
            if parent.type == "variable_declarator":
                name = parent.child_by_field_name("name")
                if name is not None:
                    text = node_text(name, self.source)
                    if any(s in text.lower() for s in _SECRET_NAMES):
                        return text
                return None
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left is not None:
                    text = node_text(left, self.source)
                    if any(s in text.lower() for s in _SECRET_NAMES):
                        return text
                return None
        return None


def scan_js(path: str, text: str) -> list[Finding]:
    """Scan one JavaScript or TypeScript file."""
    source = text.encode("utf-8", errors="replace")
    lang = _TS if path.endswith((".ts", ".tsx", ".mts", ".cts")) \
        else _JS
    parser = Parser(lang)
    tree = parser.parse(source)
    return _Scanner(path, source, "javascript").scan(tree)
