"""
Report Generator
=================
Turns raw enrichment / phishing / YARA scan results into analyst-ready
artifacts: a JSON file for machine consumption (SIEM ingestion, tickets)
and a styled, self-contained HTML file for human review/sharing.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from soc_toolkit.config import REPORTS_DIR

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


def _timestamped_name(prefix: str, ext: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


def save_json(data: Dict[str, Any], prefix: str = "report", out_dir: Path | None = None) -> Path:
    out_dir = out_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _timestamped_name(prefix, "json")
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def save_html(data: Dict[str, Any], report_type: str, prefix: str = "report", out_dir: Path | None = None) -> Path:
    out_dir = out_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    template = _env.get_template("report.html")

    rendered = template.render(
        data=data,
        report_type=report_type,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    path = out_dir / _timestamped_name(prefix, "html")
    path.write_text(rendered)
    return path


def generate_report(data: Dict[str, Any], report_type: str, fmt: str = "html", prefix: str | None = None) -> Path:
    """Single entrypoint used by CLI/dashboard. fmt: 'json' | 'html' | 'both'."""
    prefix = prefix or report_type
    paths = []
    if fmt in ("json", "both"):
        paths.append(save_json(data, prefix))
    if fmt in ("html", "both"):
        paths.append(save_html(data, report_type, prefix))
    return paths[0] if len(paths) == 1 else paths
