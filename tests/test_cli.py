"""CLI: exit codes, output files, and the full scan end to end."""
from __future__ import annotations

from pathlib import Path

from crypto_atlas.cli import main

FIX = Path(__file__).parent / "fixtures"


def test_cli_clean_dir_exits_zero(tmp_path):
    target = tmp_path / "clean"
    target.mkdir()
    (target / "a.py").write_text(
        "import hashlib\n"
        "hashlib.sha256(b'x').hexdigest()\n", encoding="utf-8")
    assert main(["scan", str(target), "--output", str(tmp_path),
                 "--format", "cbom"]) == 0
    assert (tmp_path / "cbom.json").exists()


def test_cli_dirty_dir_exits_one(tmp_path):
    target = tmp_path / "dirty"
    target.mkdir()
    (target / "a.py").write_text(
        "import hashlib\n"
        "hashlib.md5(b'x').hexdigest()\n", encoding="utf-8")
    assert main(["scan", str(target), "--output", str(tmp_path)]) == 1
    assert (tmp_path / "cbom.json").exists()
    assert (tmp_path / "report.md").exists()


def test_cli_missing_path_exits_two(tmp_path):
    assert main(["scan", str(tmp_path / "nope"),
                 "--output", str(tmp_path)]) == 2


def test_cli_scans_the_fixture_dir(tmp_path):
    assert main(["scan", str(FIX), "--output", str(tmp_path),
                 "--format", "cbom"]) == 1
    import json
    document = json.loads((tmp_path / "cbom.json")
                          .read_text(encoding="utf-8"))
    assert document["specVersion"] == "1.7"
    assert len(document["components"]) >= 10
