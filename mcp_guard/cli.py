from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .discovery import discover_config_files
from .engine import scan_file
from .scanner import ConfigParseError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_guard", description="MCP 配置安全审计工具")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="扫描一个或多个 MCP 配置文件")
    scan_parser.add_argument("paths", nargs="+", help="JSON、YAML 或 TOML 配置文件路径")

    discover_parser = subparsers.add_parser("discover", help="扫描本机常见 MCP 配置路径")
    discover_parser.add_argument("--scan", action="store_true", help="发现文件后立即执行安全扫描")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan_paths(args.paths)
    if args.command == "discover":
        return _discover(scan=args.scan)
    return 1


def _scan_paths(paths: list[str]) -> int:
    exit_code = 0
    for path in paths:
        try:
            report = scan_file(path)
        except FileNotFoundError:
            print(f"[ERROR] 文件不存在：{path}", file=sys.stderr)
            exit_code = 2
            continue
        except ConfigParseError as exc:
            print(f"[ERROR] {path}: {exc}", file=sys.stderr)
            exit_code = 2
            continue

        _print_report_summary(report)
    return exit_code


def _discover(scan: bool) -> int:
    discovered = discover_config_files(Path.cwd())
    if not discovered:
        print("未发现常见 MCP 配置文件。")
        return 0

    print("发现以下 MCP 配置文件：")
    for item in discovered:
        print(f"- [{item.label}] {item.path}")

    if not scan:
        print("使用 `python -m mcp_guard discover --scan` 可直接扫描上述文件。")
        return 0

    print("")
    return _scan_paths([str(item.path) for item in discovered])


def _print_report_summary(report: dict) -> None:
    summary = report["summary"]
    artifacts = report.get("artifacts", {})
    print(f"[OK] {report['source_name']}")
    print(f"  scan_id: {report['scan_id']}")
    print(f"  risk: {summary['level_label']} ({summary['score']}/100)")
    print(f"  servers: {summary['server_count']}, findings: {summary['total_findings']}")
    print(f"  json: {artifacts.get('json_path', '-')}")
    print(f"  markdown: {artifacts.get('markdown_path', '-')}")


if __name__ == "__main__":
    raise SystemExit(main())

