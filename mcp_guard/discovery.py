from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


COMMON_CONFIG_PATHS = (
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/claude/claude_desktop_config.json",
    "~/.cursor/mcp.json",
    "~/.cursor/mcp_config.json",
    "~/Library/Application Support/Cursor/User/mcp.json",
    "~/.config/Cursor/User/mcp.json",
    "~/.vscode/mcp.json",
    "~/Library/Application Support/Code/User/mcp.json",
    "~/.codeium/windsurf/mcp_config.json",
    "~/.config/windsurf/mcp_config.json",
    "~/.config/mcp/mcp.json",
    "./mcp.json",
    "./.mcp.json",
    "./.cursor/mcp.json",
    "./claude_desktop_config.json",
)


@dataclass(frozen=True)
class DiscoveredConfig:
    path: Path
    label: str

    def as_dict(self) -> dict[str, str]:
        return {
            "path": str(self.path),
            "label": self.label,
        }


def discover_config_files(base_dir: str | Path = ".") -> list[DiscoveredConfig]:
    cwd = Path(base_dir).resolve()
    found: list[DiscoveredConfig] = []
    seen: set[Path] = set()

    for raw_path in COMMON_CONFIG_PATHS:
        path = _resolve_path(raw_path, cwd)
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            found.append(DiscoveredConfig(path=path, label=_label_for(raw_path)))

    return found


def _resolve_path(raw_path: str, cwd: Path) -> Path:
    expanded = Path(raw_path).expanduser()
    if expanded.is_absolute():
        return expanded.resolve()
    return (cwd / expanded).resolve()


def _label_for(raw_path: str) -> str:
    lowered = raw_path.lower()
    if "claude" in lowered:
        return "Claude Desktop"
    if "cursor" in lowered:
        return "Cursor"
    if "windsurf" in lowered or "codeium" in lowered:
        return "Windsurf"
    if "vscode" in lowered or "code/user" in lowered:
        return "VS Code"
    return "MCP"

