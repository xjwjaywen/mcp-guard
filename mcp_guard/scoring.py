from __future__ import annotations

from .models import RiskFinding


SEVERITY_WEIGHTS = {
    "critical": 35,
    "high": 22,
    "medium": 10,
    "low": 4,
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}


def score_findings(findings: list[RiskFinding]) -> dict[str, object]:
    score = min(100, sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings))
    counts = {severity: 0 for severity in SEVERITY_WEIGHTS}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    level = _score_level(score)
    return {
        "score": score,
        "level": level,
        "level_label": _level_label(level),
        "severity_counts": counts,
        "high_or_above": counts["critical"] + counts["high"],
        "total_findings": len(findings),
    }


def severity_label(severity: str) -> str:
    return SEVERITY_LABELS.get(severity, severity)


def _score_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def _level_label(level: str) -> str:
    return {
        "critical": "严重风险",
        "high": "高风险",
        "medium": "中风险",
        "low": "低风险",
    }[level]

