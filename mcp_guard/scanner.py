from __future__ import annotations

import json
import tomllib
from typing import Any

from .models import MCPServer

try:
    import yaml
except ImportError:  # pragma: no cover - exercised when optional dependency is absent
    yaml = None


class ConfigParseError(ValueError):
    """Raised when an uploaded MCP config cannot be parsed."""


def parse_mcp_config(content: str, source_name: str = "") -> tuple[list[MCPServer], dict[str, Any]]:
    """Parse common MCP JSON/YAML/TOML config shapes into normalized server records."""
    data = _load_config(content, source_name)

    if not isinstance(data, dict):
        raise ConfigParseError("配置文件顶层必须是对象结构。")

    servers = _extract_servers(data)
    if not servers:
        servers = [MCPServer(server_name="configuration", raw_config=data)]
    return servers, data


def _load_config(content: str, source_name: str) -> Any:
    suffix = source_name.rsplit(".", 1)[-1].lower() if "." in source_name else ""
    loaders = _loader_order(suffix)
    errors: list[str] = []

    for loader_name in loaders:
        try:
            if loader_name == "json":
                return json.loads(content)
            if loader_name == "yaml":
                if yaml is None:
                    raise ConfigParseError("当前环境缺少 PyYAML，无法解析 YAML 配置。")
                return yaml.safe_load(content)
            if loader_name == "toml":
                return tomllib.loads(content)
        except json.JSONDecodeError as exc:
            errors.append(f"JSON 第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}")
        except tomllib.TOMLDecodeError as exc:
            errors.append(f"TOML：{exc}")
        except ConfigParseError as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(f"{loader_name.upper()}：{exc}")

    hint = "；".join(errors) if errors else "未识别配置格式"
    raise ConfigParseError(f"配置解析失败：{hint}")


def _loader_order(suffix: str) -> list[str]:
    if suffix == "json":
        return ["json"]
    if suffix in {"yaml", "yml"}:
        return ["yaml"]
    if suffix == "toml":
        return ["toml"]
    return ["json", "yaml", "toml"]


def _extract_servers(data: dict[str, Any]) -> list[MCPServer]:
    for key in ("mcpServers", "McpServers", "mcp_servers", "servers"):
        if key in data:
            return _normalize_server_collection(data[key])

    if _looks_like_server(data):
        return [_normalize_server("default", data)]

    nested: list[MCPServer] = []
    for key, value in data.items():
        if isinstance(value, dict) and _looks_like_server(value):
            nested.append(_normalize_server(key, value))
    return nested


def _normalize_server_collection(collection: Any) -> list[MCPServer]:
    if isinstance(collection, dict):
        return [
            _normalize_server(name, config)
            for name, config in collection.items()
            if isinstance(config, dict)
        ]

    if isinstance(collection, list):
        servers: list[MCPServer] = []
        for index, item in enumerate(collection, start=1):
            if isinstance(item, dict):
                name = _as_text(item.get("name") or item.get("server_name") or f"server-{index}")
                servers.append(_normalize_server(name, item))
        return servers

    return []


def _normalize_server(name: str, config: dict[str, Any]) -> MCPServer:
    args = config.get("args", [])
    if isinstance(args, str):
        normalized_args = [args]
    elif isinstance(args, list):
        normalized_args = [_as_text(arg) for arg in args]
    else:
        normalized_args = [_as_text(args)] if args is not None else []

    env = config.get("env", {})
    normalized_env = {
        _as_text(key): _as_text(value)
        for key, value in env.items()
    } if isinstance(env, dict) else {}

    return MCPServer(
        server_name=_as_text(config.get("name") or config.get("server_name") or name),
        command=_as_text(config.get("command") or config.get("cmd") or config.get("executable")),
        args=normalized_args,
        env=normalized_env,
        cwd=_as_text(config.get("cwd") or config.get("workingDirectory") or config.get("working_directory")),
        url=_as_text(config.get("url") or config.get("endpoint") or config.get("baseUrl") or config.get("base_url")),
        description=_extract_description(config),
        raw_config=config,
    )


def _extract_description(config: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("description", "instructions", "systemPrompt", "system_prompt"):
        if key in config:
            chunks.append(_as_text(config[key]))

    tools = config.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict):
                chunks.append(_as_text(tool.get("name")))
                chunks.append(_as_text(tool.get("description")))
    return "\n".join(chunk for chunk in chunks if chunk)


def _looks_like_server(value: dict[str, Any]) -> bool:
    server_keys = {
        "command",
        "cmd",
        "executable",
        "args",
        "env",
        "cwd",
        "workingDirectory",
        "url",
        "endpoint",
        "baseUrl",
        "tools",
    }
    return any(key in value for key in server_keys)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
