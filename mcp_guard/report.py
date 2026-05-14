from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .models import MCPServer, RiskFinding
from .scoring import score_findings, severity_label


def build_report(
    scan_id: str,
    source_name: str,
    servers: list[MCPServer],
    findings: list[RiskFinding],
    raw_config: dict[str, Any],
) -> dict[str, Any]:
    score = score_findings(findings)
    return {
        "scan_id": scan_id,
        "source_name": source_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            **score,
            "server_count": len(servers),
        },
        "servers": [server.as_dict() for server in servers],
        "findings": [finding.as_dict() for finding in findings],
        "raw_config": raw_config,
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# MCP-Guard 安全审计报告",
        "",
        f"- 扫描编号：`{report['scan_id']}`",
        f"- 配置来源：`{report['source_name']}`",
        f"- 生成时间：`{report['generated_at']}`",
        f"- MCP Server 数量：{summary['server_count']}",
        f"- 风险分数：{summary['score']} / 100",
        f"- 风险等级：{summary['level_label']}",
        f"- 高危及以上问题：{summary['high_or_above']}",
        "",
        "## MCP Server 概览",
        "",
    ]

    for server in report["servers"]:
        args = " ".join(server["args"]) if server["args"] else "-"
        lines.extend(
            [
                f"### {server['server_name']}",
                "",
                f"- command：`{server['command'] or '-'}`",
                f"- args：`{args}`",
                f"- cwd：`{server['cwd'] or '-'}`",
                f"- url：`{server['url'] or '-'}`",
                "",
            ]
        )

    lines.extend(["## 风险发现", ""])
    if not report["findings"]:
        lines.extend(["未发现明显风险。", ""])
        return "\n".join(lines)

    for finding in report["findings"]:
        lines.extend(
            [
                f"### [{severity_label(finding['severity'])}] {finding['title']}",
                "",
                f"- 规则编号：`{finding['rule_id']}`",
                f"- MCP Server：`{finding['server_name']}`",
                f"- 证据：`{finding['evidence']}`",
                f"- 风险说明：{finding['explanation']}",
                f"- 修复建议：{finding['recommendation']}",
                f"- 可能误报：{finding.get('false_positive_note') or '暂无。'}",
                "",
            ]
        )
    return "\n".join(lines)
