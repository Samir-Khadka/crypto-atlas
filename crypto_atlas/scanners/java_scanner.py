"""Java scanner, via tree-sitter.

Covers the JCA/JCE calls the other scanners cover: MessageDigest,
Cipher, KeyPairGenerator, KeyGenerator, SSLContext, SecureRandom vs
Random, SecretKeySpec / PBEKeySpec, and the trust-all patterns
(HostnameVerifier returning true, X509TrustManager with empty
check methods). Assignment context matters: KeyPairGenerator
variables are tracked from getInstance to initialize, and Random
only fires when its output lands in a secret-named value.
"""
from __future__ import annotations

from tree_sitter import Language, Parser

import tree_sitter_java as tsj

from ..findings import Finding
from ..keys import weakness_for_curve, weakness_for_rsa
from ..rules import RULES
from .tsutil import node_text, walk


def _java_string(node, source: bytes) -> str | None:
    """The unquoted value of a Java string_literal, or None.
    (tsutil.string_value is for JS/Go, whose string node is called
    ``string``; Java calls it ``string_literal``.)"""
    if node is None or node.type != "string_literal":
        return None
    text = node_text(node, source)
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text

_JAVA = Language(tsj.language())

_SECRET_NAMES = ("key", "token", "secret", "password", "passwd",
                 "nonce", "salt", "iv")

_WEAK_HASHES = {"MD5", "MD2", "SHA-1", "SHA1", "SHA", "SHA0"}
_BROKEN_CIPHERS = {"DES", "DESEDE", "3DES", "RC4", "ARCFOUR",
                   "BLOWFISH"}
_OLD_TLS = {"SSL", "SSLV3", "SSLV2", "TLSV1", "TLSV1.1"}
_PQ_ALGORITHMS = {"ML-KEM", "ML-DSA", "SLH-DSA", "MLKEM", "MLDSA",
                  "SLHDSA"}


def _is_secret_name(name: str) -> bool:
    low = name.lower()
    return any(part in low for part in _SECRET_NAMES)


def _method_parts(node, source: bytes) -> tuple[str | None, str | None]:
    """(object text, method name) of a method_invocation."""
    if node.type != "method_invocation":
        return None, None
    obj = node.child_by_field_name("object")
    name = node.child_by_field_name("name")
    obj_text = node_text(obj, source) if obj is not None else None
    name_text = node_text(name, source) if name is not None else None
    return obj_text, name_text


def _args(node, source: bytes) -> list:
    args = node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _string_arg(node, source: bytes, index: int = 0) -> str | None:
    args = _args(node, source)
    if len(args) > index:
        return _java_string(args[index], source)
    return None


def _int_arg(node, source: bytes, index: int = 0) -> int | None:
    args = _args(node, source)
    if len(args) > index and args[index].type == "decimal_integer_literal":
        try:
            return int(node_text(args[index], source))
        except ValueError:
            return None
    return None


class _Scanner:
    def __init__(self, path: str, source: bytes):
        self.path = path
        self.source = source
        self.findings: list[Finding] = []
        self.lines = source.decode("utf-8", errors="replace") \
            .splitlines()
        # variable name -> "RSA" / "EC" for KeyPairGenerator vars
        self.kpg_vars: dict[str, str] = {}
        # variable names holding a java.util.Random
        self.random_vars: set[str] = set()

    def add(self, rule_id: str, algorithm: str, weakness: int,
            node, evidence: str, **kw) -> None:
        rule = RULES[rule_id]
        line = node.start_point[0] + 1
        snippet = self.lines[line - 1].strip() if line <= len(
            self.lines) else ""
        self.findings.append(Finding(
            rule_id=rule_id, algorithm=algorithm, weakness=weakness,
            file=self.path, line=line, snippet=snippet,
            evidence=evidence, fix=rule["fix"], language="java",
            change_difficulty=rule["change_difficulty"], **kw))

    def _declarator_name(self, node) -> str | None:
        """The variable name of a variable_declarator, or None."""
        name = node.child_by_field_name("name")
        return node_text(name, self.source) if name is not None else None

    def _enclosing_declarator(self, ancestors) -> object | None:
        for node in reversed(ancestors):
            if node.type == "variable_declarator":
                return node
        return None

    def _body_is_return_true(self, method) -> bool:
        body = method.child_by_field_name("body")
        if body is None:
            return False
        statements = [c for c in body.named_children]
        return len(statements) == 1 \
            and statements[0].type == "return_statement" \
            and node_text(statements[0], self.source).strip() \
            == "return true;"

    def _body_is_empty(self, method) -> bool:
        body = method.child_by_field_name("body")
        if body is None:
            return False
        return len(body.named_children) == 0

    def _first_arg_is_hardcoded(self, node) -> bool:
        """The first argument is a string literal, a .getBytes() /
        .toCharArray() call on one, or a byte-array literal."""
        args = _args(node, self.source)
        if not args:
            return False
        first = args[0]
        if first.type == "string_literal":
            return True
        if first.type == "array_initializer":
            return True
        if first.type == "method_invocation":
            obj, _ = _method_parts(first, self.source)
            return obj is not None and obj.startswith('"')
        if first.type == "object_creation_expression":
            inner = node_text(first, self.source)
            return "byte" in inner and "{" in inner
        return False

    def _scan_method(self, node, ancestors) -> None:
        obj, name = _method_parts(node, self.source)
        if obj is None or name is None:
            return
        obj_base = obj.split(".")[-1]

        if name == "getInstance":
            algo = _string_arg(node, self.source)
            if algo is None:
                return
            upper = algo.upper().replace("-", "")
            if obj_base == "MessageDigest" \
                    and algo.upper() in _WEAK_HASHES:
                self.add("weak-hash", algo.upper(), 5, node,
                         f"MessageDigest.getInstance(\"{algo}\")",
                         primitive="hash", parameter_set=algo.upper())
            elif obj_base == "Cipher":
                parts = algo.split("/")
                cipher_algo = parts[0].upper()
                mode = parts[1].upper() if len(parts) > 1 else ""
                primitive = "stream-cipher" \
                    if cipher_algo in ("RC4", "ARCFOUR") \
                    else "block-cipher"
                if cipher_algo in _BROKEN_CIPHERS:
                    self.add("weak-cipher", cipher_algo, 5, node,
                             f"Cipher.getInstance(\"{algo}\")",
                             primitive=primitive,
                             parameter_set=cipher_algo)
                elif mode == "ECB":
                    self.add("weak-cipher", "AES-ECB", 5, node,
                             f"Cipher.getInstance(\"{algo}\") uses ECB",
                             primitive="block-cipher",
                             parameter_set="ECB")
            elif obj_base == "KeyGenerator" \
                    and algo.upper().replace("-", "") \
                    in ("DES", "DESEDE", "3DES", "RC4", "ARCFOUR"):
                self.add("weak-cipher", algo.upper(), 5, node,
                         f"KeyGenerator.getInstance(\"{algo}\")",
                         primitive="block-cipher",
                         parameter_set=algo.upper())
            elif obj_base == "SSLContext" \
                    and algo.upper().replace(".", "") in _OLD_TLS:
                self.add("tls-old-version", algo, 5, node,
                         f"SSLContext.getInstance(\"{algo}\")",
                         asset_type="protocol", parameter_set=algo)
            if upper in _PQ_ALGORITHMS or algo.upper() in _PQ_ALGORITHMS:
                self.add("pq-algorithm", algo.upper(), 1, node,
                         f"getInstance(\"{algo}\") — already "
                         f"quantum-safe",
                         primitive="kem", parameter_set=algo.upper())
            # remember KeyPairGenerator variables for initialize()
            if obj_base == "KeyPairGenerator":
                declarator = self._enclosing_declarator(ancestors)
                if declarator is not None:
                    var = self._declarator_name(declarator)
                    if var:
                        self.kpg_vars[var] = algo.upper()
            return

        if name == "initialize" and obj in self.kpg_vars:
            algo = self.kpg_vars[obj]
            args = _args(node, self.source)
            if not args:
                return
            if algo == "RSA":
                size = _int_arg(node, self.source)
                self.add("rsa-keygen", "RSA",
                         weakness_for_rsa(size), node,
                         f"KeyPairGenerator RSA initialized to "
                         f"{size} bits" if size else
                         "KeyPairGenerator RSA with unknown size",
                         key_size=size, primitive="pke",
                         parameter_set=f"RSA-{size}" if size else "RSA")
            elif algo in ("EC", "ECDSA"):
                curve = None
                if args[0].type == "object_creation_expression":
                    inner_args = _args(args[0], self.source)
                    if inner_args:
                        curve = _java_string(inner_args[0], self.source)
                elif args[0].type == "decimal_integer_literal":
                    size = _int_arg(node, self.source)
                    curve = {192: "P-192", 224: "P-224",
                             256: "P-256", 384: "P-384",
                             521: "P-521"}.get(size)
                self.add("ecc-keygen", "ECC",
                         weakness_for_curve(curve), node,
                         f"KeyPairGenerator EC initialized to {curve}",
                         curve=curve, primitive="signature",
                         parameter_set=curve)
            return

        if name in ("nextBytes", "nextInt", "nextLong", "nextDouble") \
                and obj in self.random_vars:
            # the output lands in a secret-named value?
            args = _args(node, self.source)
            target = None
            if args:
                target = node_text(args[0], self.source)
            declarator = self._enclosing_declarator(ancestors)
            if declarator is not None:
                target = self._declarator_name(declarator)
            if target and _is_secret_name(target):
                self.add("weak-random", "Random", 5, node,
                         f"java.util.Random.{name}() fills "
                         f"secret-named value {target}",
                         primitive="other", parameter_set="random")
            return

    def _scan_creation(self, node, ancestors) -> None:
        type_node = node.child_by_field_name("type")
        if type_node is None:
            return
        type_text = node_text(type_node, self.source)
        type_base = type_text.split(".")[-1]
        declarator = self._enclosing_declarator(ancestors)
        var = self._declarator_name(declarator) if declarator \
            is not None else None

        if type_base == "Random":
            if var:
                self.random_vars.add(var)
            if var and _is_secret_name(var):
                self.add("weak-random", "Random", 5, node,
                         f"java.util.Random assigned to secret-named "
                         f"variable {var}",
                         primitive="other", parameter_set="random")
            return

        if type_base in ("SecretKeySpec", "PBEKeySpec"):
            if self._first_arg_is_hardcoded(node):
                self.add("hardcoded-key", type_base, 5, node,
                         f"new {type_base}(...) with a hardcoded "
                         f"literal key",
                         primitive=None, parameter_set="secret-key")
            return

    def _scan_method_decl(self, node) -> None:
        name = node.child_by_field_name("name")
        if name is None:
            return
        method_name = node_text(name, self.source)
        # a HostnameVerifier whose verify() always returns true
        if method_name == "verify" and self._body_is_return_true(node):
            self.add("tls-disabled", "TLS", 5, node,
                     "HostnameVerifier.verify() always returns true",
                     asset_type="protocol")
        # a TrustManager that accepts everything: empty check methods
        if method_name in ("checkServerTrusted", "checkClientTrusted") \
                and self._body_is_empty(node):
            self.add("tls-disabled", "TLS", 5, node,
                     f"X509TrustManager.{method_name}() is empty — "
                     f"all certificates accepted",
                     asset_type="protocol")

    def _scan_lambda(self, node, ancestors) -> None:
        # a lambda that always returns true, used as a
        # HostnameVerifier (assigned to one, or passed to
        # setHostnameVerifier)
        body = node.child_by_field_name("body")
        if body is None:
            return
        if node_text(body, self.source).strip() != "true":
            return
        declarator = self._enclosing_declarator(ancestors)
        if declarator is not None:
            parent = ancestors[-2] if len(ancestors) >= 2 else None
            type_text = ""
            if parent is not None:
                type_node = parent.child_by_field_name("type")
                if type_node is not None:
                    type_text = node_text(type_node, self.source)
            if "HostnameVerifier" in type_text:
                self.add("tls-disabled", "TLS", 5, node,
                         "HostnameVerifier lambda always returns true",
                         asset_type="protocol")
                return
        for ancestor in ancestors:
            if ancestor.type == "method_invocation":
                _, mname = _method_parts(ancestor, self.source)
                if mname == "setHostnameVerifier":
                    self.add("tls-disabled", "TLS", 5, node,
                             "setHostnameVerifier with a lambda that "
                             "always returns true",
                             asset_type="protocol")
                    return


def scan_java(path: str, text: str) -> list[Finding]:
    """Scan one Java source file."""
    source = text.encode("utf-8")
    parser = Parser(_JAVA)
    tree = parser.parse(source)
    scanner = _Scanner(path, source)
    for node, ancestors in walk(tree.root_node):
        if node.type == "method_invocation":
            scanner._scan_method(node, ancestors)
        elif node.type == "object_creation_expression":
            scanner._scan_creation(node, ancestors)
        elif node.type == "method_declaration":
            scanner._scan_method_decl(node)
        elif node.type == "lambda_expression":
            scanner._scan_lambda(node, ancestors)
    return scanner.findings
