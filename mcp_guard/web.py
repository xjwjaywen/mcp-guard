from __future__ import annotations

from flask import Flask, Response, abort, render_template, request

from .discovery import discover_config_files
from .engine import scan_content
from .examples import EXAMPLES, example_as_json, example_choices
from .report import render_json, render_markdown
from .scanner import ConfigParseError
from .scoring import severity_label
from .storage import load_report


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024

    @app.get("/")
    def index():
        return render_template("index.html", examples=example_choices())

    @app.post("/scan")
    def scan():
        source_name, content = _read_scan_input()
        if not content.strip():
            return render_template(
                "index.html",
                examples=example_choices(),
                error="请上传 JSON 配置文件、粘贴配置内容，或选择一个示例。",
            ), 400

        try:
            report = scan_content(content, source_name)
        except ConfigParseError as exc:
            return render_template(
                "index.html",
                examples=example_choices(),
                error=str(exc),
                previous_content=content,
            ), 400

        return render_template(
            "result.html",
            report=report,
            severity_label=severity_label,
        )

    @app.post("/scan/discover")
    def scan_discovered():
        discovered = discover_config_files()
        reports = []
        errors = []
        for item in discovered:
            try:
                reports.append(scan_content(item.path.read_text(encoding="utf-8"), str(item.path)))
            except (OSError, ConfigParseError) as exc:
                errors.append({"path": str(item.path), "error": str(exc)})

        return render_template(
            "discovery.html",
            discovered=[item.as_dict() for item in discovered],
            reports=reports,
            errors=errors,
            severity_label=severity_label,
        )

    @app.get("/examples")
    def examples():
        return render_template("examples.html", examples=example_choices())

    @app.get("/report/<scan_id>.json")
    def json_report(scan_id: str):
        report = load_report(scan_id)
        if not report:
            abort(404)
        return Response(
            render_json(report),
            mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=mcp-guard-{scan_id}.json"},
        )

    @app.get("/report/<scan_id>.md")
    def markdown_report(scan_id: str):
        report = load_report(scan_id)
        if not report:
            abort(404)
        return Response(
            render_markdown(report),
            mimetype="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=mcp-guard-{scan_id}.md"},
        )

    return app


def _read_scan_input() -> tuple[str, str]:
    example_id = request.form.get("example_id", "").strip()
    if example_id in EXAMPLES:
        return f"example:{example_id}", example_as_json(example_id)

    upload = request.files.get("config_file")
    if upload and upload.filename:
        raw = upload.read()
        return upload.filename, raw.decode("utf-8", errors="replace")

    content = request.form.get("config_text", "")
    return "pasted-config", content
