from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .report import render_json, render_markdown


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"


def report_dir() -> Path:
    return Path(os.environ.get("MCP_GUARD_REPORT_DIR", DEFAULT_REPORT_DIR)).expanduser()


def save_report(report: dict[str, Any]) -> tuple[Path, Path]:
    directory = report_dir()
    directory.mkdir(parents=True, exist_ok=True)
    scan_id = report["scan_id"]
    json_path = directory / f"{scan_id}.json"
    markdown_path = directory / f"{scan_id}.md"
    report["artifacts"] = {
        "json_path": str(json_path),
        "markdown_path": str(markdown_path),
    }
    json_path.write_text(render_json(report), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def load_report(scan_id: str) -> dict[str, Any] | None:
    path = report_dir() / f"{scan_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
