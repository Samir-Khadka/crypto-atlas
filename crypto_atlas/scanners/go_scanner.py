"""Go scanner, via tree-sitter.

Matches on the function text of ``call_expression`` nodes
(``rsa.GenerateKey``, ``md5.New``) and on ``tls.Config``
composite literals for the TLS flags.
"""
from __future__ import annotations

from tree_sitter import Language, Parser

import tree_sitter_go as tsgo

from ..findings import Finding
from ..rules import RULES
from .tsutil import (call_args, call_function_text, node_text,
                     parent_map, string_value, walk)

_GO = Language(tsgo.language())

_SECRET_NAMES = ("key", "token", "secret", "password", "passwd",
                 "nonce", "salt", "iv")


def _weakness_for_rsa(size: int | None) -> int:
    if size is None or size < 2048:
        return 5
    return 4 if size == 2048 else 3


def _weakness_for_curve(curve: str | None) -> int:
    if not curve:
        return 4
    if any(c in curve for c in ("P224", "P192")):
        return 5
    if any(c in curve for c in ("P384", "P521")):
        return 3
    return 4


class _Scanner:
    def __init__(self, path: str, source: bytes):
        self.path = path
        self.source = source
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
            fix=rule["fix"], language="go",
            change_difficulty=rule["change_difficulty"], **kw))

    def scan(self, tree) -> list[Finding]:
        for node, ancestors in walk(tree.root_node):
            if node.type == "call_expression":
                self._check_call(node, ancestors)
            elif node.type == "composite_literal":
                self._check_composite(node)
        return self.findings

    def _check_call(self, node, ancestors) -> None:
        func = call_function_text(node, self.source)
        if not func:
            return
        args = call_args(node, self.source)

        # RSA key generation: rsa.GenerateKey(rand, bits)
        if func == "rsa.GenerateKey" and len(args) >= 2:
            size = self._int_arg(args[1])
            self._add("rsa-keygen", node, "RSA",
                      _weakness_for_rsa(size),
                      f"RSA key generated ({size or 'unknown'} bits)",
                      key_size=size, primitive="pke",
                      parameter_set=f"RSA-{size}" if size else "RSA")
            return
        # ECC key generation: ecdsa.GenerateKey(curve, rand) or
        # ecdh.P256() / ecdh.P384()
        if func == "ecdsa.GenerateKey" and args:
            curve = node_text(args[0], self.source)
            self._add("ecc-keygen", node, "ECC",
                      _weakness_for_curve(curve),
                      f"ECC key generated (curve {curve})",
                      curve=curve, primitive="signature",
                      parameter_set=curve)
            return
        if func in ("ecdh.P256", "ecdh.P384", "ecdh.P521",
                    "ecdh.P224"):
            curve = func.split(".")[-1]
            self._add("ecc-keygen", node, "ECC",
                      _weakness_for_curve(curve),
                      f"ECDH key generated (curve {curve})",
                      curve=curve, primitive="key-agree",
                      parameter_set=curve)
            return
        # weak hash
        if func in ("md5.New", "md5.Sum", "sha1.New", "sha1.Sum"):
            algo = "MD5" if "md5" in func else "SHA1"
            self._add("weak-hash", node, algo, 5,
                      f"{algo} used here", primitive="hash",
                      parameter_set=algo)
            return
        # weak ciphers
        if func in ("des.NewCipher", "des.NewTripleDESCipher",
                    "rc4.NewCipher"):
            algo = "3DES" if "Triple" in func else \
                "DES" if "des" in func else "RC4"
            self._add("weak-cipher", node, algo, 5,
                      f"{algo} used here",
                      primitive="block-cipher" if algo != "RC4"
                      else "stream-cipher",
                      parameter_set=algo)
            return
        # weak randomness, by assignment context
        if func in ("rand.Int", "rand.Read", "rand.Intn",
                    "rand.Uint64", "rand.Float64"):
            target = self._secret_target(ancestors)
            if target:
                self._add("weak-random", node, "random", 5,
                          f"math/rand used for '{target}'",
                          primitive="other", parameter_set="random")
            return
        # post-quantum: already migrated
        low = func.lower()
        if "mlkem" in low or "mldsa" in low or "slhdsa" in low:
            algo = "ML-KEM" if "kem" in low else \
                "ML-DSA" if "dsa" in low else "SLH-DSA"
            self._add("pq-algorithm", node, algo, 1,
                      f"{algo} in use (already quantum-safe)",
                      primitive="kem" if algo == "ML-KEM" else "signature",
                      parameter_set=algo)
            return

    def _check_composite(self, node) -> None:
        """tls.Config{InsecureSkipVerify: true, MinVersion: ...}"""
        type_node = node.child_by_field_name("type")
        if type_node is None:
            return
        if node_text(type_node, self.source) != "tls.Config":
            return
        body = node.child_by_field_name("body")
        if body is None:
            return
        for elem in body.named_children:
            if elem.type != "keyed_element":
                continue
            key = elem.child_by_field_name("key")
            value = elem.child_by_field_name("value")
            if key is None or value is None:
                continue
            ktext = node_text(key, self.source)
            vtext = node_text(value, self.source)
            if ktext == "InsecureSkipVerify" and vtext == "true":
                self._add("tls-disabled", node, "TLS", 5,
                          "certificate verification disabled "
                          "(InsecureSkipVerify: true)",
                          asset_type="protocol", parameter_set="TLS")
            elif ktext == "MinVersion" and vtext in (
                    "tls.VersionTLS10", "tls.VersionTLS11"):
                version = "TLS 1.0" if "10" in vtext else "TLS 1.1"
                self._add("tls-old-version", node, version, 5,
                          f"{version} explicitly allowed",
                          asset_type="protocol",
                          parameter_set=version)

    def _int_arg(self, node) -> int | None:
        text = node_text(node, self.source).strip()
        return int(text) if text.isdigit() else None

    def _secret_target(self, ancestors) -> str | None:
        """The secret-named variable this call's result lands in,
        climbing the ancestor chain (the call sits inside an
        expression_list on the right of := or =)."""
        for parent in reversed(ancestors):
            if parent.type == "short_var_declaration":
                left = parent.child_by_field_name("left")
                if left is not None:
                    for name in left.named_children:
                        text = node_text(name, self.source)
                        if any(s in text.lower()
                               for s in _SECRET_NAMES):
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


def scan_go(path: str, text: str) -> list[Finding]:
    """Scan one Go file."""
    source = text.encode("utf-8", errors="replace")
    parser = Parser(_GO)
    tree = parser.parse(source)
    return _Scanner(path, source).scan(tree)
