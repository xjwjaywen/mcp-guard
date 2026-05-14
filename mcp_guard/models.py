from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MCPServer:
    server_name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    url: str = ""
    description: str = ""
    raw_config: dict[str, Any] = field(default_factory=dict)

    def searchable_text(self) -> str:
        parts: list[str] = [
            self.server_name,
            self.command,
            " ".join(self.args),
            self.cwd,
            self.url,
            self.description,
            _flatten_text(self.env),
            _flatten_text(self.raw_config),
        ]
        return "\n".join(part for part in parts if part)

    def as_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "cwd": self.cwd,
            "url": self.url,
            "description": self.description,
            "raw_config": self.raw_config,
        }


@dataclass(frozen=True)
class RiskFinding:
    rule_id: str
    title: str
    severity: str
    server_name: str
    evidence: str
    explanation: str
    recommendation: str
    false_positive_note: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "server_name": self.server_name,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "false_positive_note": self.false_positive_note,
        }


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        chunks: list[str] = []
        for key, item in value.items():
            chunks.append(str(key))
            chunks.append(_flatten_text(item))
        return " ".join(chunk for chunk in chunks if chunk)
    if isinstance(value, list):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)
