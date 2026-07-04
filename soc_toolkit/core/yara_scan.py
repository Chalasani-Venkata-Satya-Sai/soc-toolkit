"""
YARA Scanning Engine
====================
Wraps yara-python to scan a single file or a whole directory tree against
a set of compiled detection rules — the same workflow a Tier-2/3 analyst
runs during endpoint triage of a suspected-compromised host.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yara

from soc_toolkit.config import RULES_DIR
from soc_toolkit.utils.logger import get_logger

log = get_logger(__name__)

# Skip huge files to keep scans fast; override with max_size_mb if needed.
DEFAULT_MAX_FILE_MB = 200


def load_rules(rules_path: str | Path | None = None) -> yara.Rules:
    """Compile YARA rules from a single .yar file or a directory of them."""
    rules_path = Path(rules_path) if rules_path else RULES_DIR

    if rules_path.is_file():
        return yara.compile(filepath=str(rules_path))

    if rules_path.is_dir():
        rule_files = {
            f.stem: str(f) for f in rules_path.glob("**/*.yar")
        }
        rule_files.update({
            f.stem: str(f) for f in rules_path.glob("**/*.yara")
        })
        if not rule_files:
            raise FileNotFoundError(f"No .yar/.yara rule files found in {rules_path}")
        return yara.compile(filepaths=rule_files)

    raise FileNotFoundError(f"Rules path not found: {rules_path}")


def scan_file(file_path: str | Path, rules: yara.Rules, max_size_mb: int = DEFAULT_MAX_FILE_MB) -> Dict[str, Any]:
    file_path = Path(file_path)
    size_mb = file_path.stat().st_size / (1024 * 1024)

    if size_mb > max_size_mb:
        return {"file": str(file_path), "status": "skipped", "reason": f"file > {max_size_mb}MB"}

    try:
        matches = rules.match(str(file_path))
        return {
            "file": str(file_path),
            "status": "clean" if not matches else "match",
            "matches": [
                {
                    "rule": m.rule,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                }
                for m in matches
            ],
        }
    except yara.Error as exc:
        return {"file": str(file_path), "status": "error", "reason": str(exc)}


def scan_directory(
    dir_path: str | Path,
    rules: yara.Rules,
    max_size_mb: int = DEFAULT_MAX_FILE_MB,
) -> List[Dict[str, Any]]:
    dir_path = Path(dir_path)
    results = []
    for file_path in dir_path.rglob("*"):
        if file_path.is_file():
            results.append(scan_file(file_path, rules, max_size_mb))
    return results


def scan(path: str | Path, rules_path: str | Path | None = None) -> Dict[str, Any]:
    """High-level entrypoint used by CLI/dashboard: handles file or dir."""
    path = Path(path)
    rules = load_rules(rules_path)

    if path.is_file():
        file_results = [scan_file(path, rules)]
    elif path.is_dir():
        file_results = scan_directory(path, rules)
    else:
        raise FileNotFoundError(f"Path not found: {path}")

    matched = [r for r in file_results if r.get("status") == "match"]
    log.info(f"YARA scan complete: {len(matched)} match(es) out of {len(file_results)} file(s) scanned")

    return {
        "scanned_path": str(path),
        "total_files": len(file_results),
        "matches_found": len(matched),
        "results": file_results,
    }
