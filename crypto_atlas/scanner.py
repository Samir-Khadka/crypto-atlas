"""Walk a target and scan every file the scanners understand.

Skips the directories that are never source: .git, virtual
environments, node_modules, caches, and build output. A single file
is scanned on its own.
"""
from __future__ import annotations

from pathlib import Path

from .findings import Finding
from .scanners.config_scanner import scan_config, scan_pem
from .scanners.go_scanner import scan_go
from .scanners.js_scanner import scan_js
from .scanners.python_scanner import scan_python

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules",
              ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
              ".next", "target", "vendor"}

_PY = {".py"}
_JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_GO = {".go"}
_CONF = {".conf", ".nginx"}
_PEM = {".pem", ".crt", ".cer", ".key"}


def _scan_file(path: Path, root: Path) -> list[Finding]:
    rel = str(path.relative_to(root)) if path.is_relative_to(root) \
        else str(path)
    suffix = path.suffix.lower()
    try:
        if suffix in _PY:
            return scan_python(rel, path.read_text(
                encoding="utf-8", errors="replace"))
        if suffix in _JS:
            return scan_js(rel, path.read_text(
                encoding="utf-8", errors="replace"))
        if suffix in _GO:
            return scan_go(rel, path.read_text(
                encoding="utf-8", errors="replace"))
        if suffix in _CONF or path.name in ("nginx.conf",
                                            "httpd.conf"):
            return scan_config(rel, path.read_text(
                encoding="utf-8", errors="replace"))
        if suffix in _PEM:
            return scan_pem(rel, path.read_bytes())
    except (OSError, UnicodeDecodeError):
        return []
    return []


def scan_target(target: str) -> tuple[list[Finding], int]:
    """Scan a file or a directory. Returns (findings, files_scanned)."""
    root = Path(target)
    if not root.exists():
        raise OSError(f"no such file or directory: {target}")
    findings: list[Finding] = []
    files = 0
    if root.is_file():
        findings += _scan_file(root, root.parent)
        return findings, 1
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in \
                (_PY | _JS | _GO | _CONF | _PEM) \
                and path.name not in ("nginx.conf", "httpd.conf"):
            continue
        files += 1
        findings += _scan_file(path, root)
    return findings, files
