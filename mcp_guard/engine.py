from __future__ import annotations

from uuid import uuid4

from .report import build_report
from .rules import evaluate_servers
from .scanner import parse_mcp_config
from .storage import save_report


def scan_content(content: str, source_name: str) -> dict:
    servers, raw_config = parse_mcp_config(content, source_name=source_name)
    findings = evaluate_servers(servers)
    scan_id = uuid4().hex[:12]
    report = build_report(scan_id, source_name, servers, findings, raw_config)
    save_report(report)
    return report


def scan_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    return scan_content(content, source_name=path)
