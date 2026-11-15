"""Shared tree-sitter helpers for the JS/TS and Go scanners.

Both scanners walk ``call_expression`` nodes and match on the
function's text, so the matching logic stays in plain Python and is
easy to test.
"""
from __future__ import annotations


def node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace")


def walk(node, ancestors=()):
    """Yield (node, ancestors) for every node in the tree. The
    ancestors are the same wrapper objects as the traversal, so
    climbing them is reliable: tree-sitter node objects are
    ephemeral, and id() is not stable across separate walks."""
    yield node, ancestors
    for child in node.children:
        yield from walk(child, ancestors + (node,))


def call_function_text(node, source: bytes) -> str | None:
    """The function text of a call_expression, e.g.
    ``crypto.createHash``."""
    if node.type != "call_expression":
        return None
    func = node.child_by_field_name("function")
    return node_text(func, source) if func is not None else None


def call_args(node, source: bytes) -> list:
    """The argument nodes of a call_expression."""
    args = node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def object_pairs(node, source: bytes) -> dict[str, str]:
    """key -> value text for an object / object literal node."""
    out: dict[str, str] = {}
    if node is None or node.type not in ("object", "object_literal",
                                        "object_pattern"):
        return out
    for child in node.named_children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
        if key is not None and value is not None:
            out[node_text(key, source).strip("\"'")] = \
                node_text(value, source)
    return out


def parent_map(root):
    """id(node) -> parent node. Prefer walk()'s ancestors: id() is
    not stable across separate walks."""
    out = {}
    for node, ancestors in walk(root):
        if ancestors:
            out[id(node)] = ancestors[-1]
    return out


def string_value(node, source: bytes) -> str | None:
    """The unquoted value of a string node, or None."""
    if node is None or node.type != "string":
        return None
    text = node_text(node, source)
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        return text[1:-1]
    return text
