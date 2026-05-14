from __future__ import annotations

import os
import re
import shlex
from pathlib import PurePosixPath

from .models import MCPServer, RiskFinding


HIGH_RISK_COMMANDS = {
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "node",
    "powershell",
    "pwsh",
    "curl",
    "wget",
    "nmap",
    "sqlmap",
}

REMOTE_PACKAGE_COMMANDS = {"npx", "uvx", "pipx", "bunx", "pnpm", "yarn", "npm"}
WRITE_FLAGS = {
    "--write",
    "--read-write",
    "--allow-write",
    "--allow-write-path",
    "--dangerously-skip-permissions",
    "--unsafe",
    "--privileged",
}
DOCKER_SOCKET_PATTERNS = (
    "/var/run/docker.sock",
    "docker.sock",
)
SECRET_KEYWORDS = ("token", "key", "secret", "password", "credential", "apikey", "api_key")
PROMPT_INJECTION_PATTERNS = (
    "ignore previous instructions",
    "disregard previous instructions",
    "reveal system prompt",
    "leak system prompt",
    "print system prompt",
    "忽略之前指令",
    "忽略以上指令",
    "泄露系统提示词",
    "输出系统提示词",
)

SENSITIVE_PATH_PATTERNS = (
    (re.compile(r"(^|\s|=)(~?/)?\.ssh(/|\s|$)", re.IGNORECASE), "SSH 私钥目录"),
    (re.compile(r"(^|\s|=)/etc(/|\s|$)", re.IGNORECASE), "系统配置目录 /etc"),
    (re.compile(r"(^|\s|=)/var(/|\s|$)", re.IGNORECASE), "系统运行目录 /var"),
    (re.compile(r"(^|\s|=)(~?/)?Desktop(/|\s|$)", re.IGNORECASE), "桌面目录"),
    (re.compile(r"(^|\s|=)(~?/)?Downloads(/|\s|$)", re.IGNORECASE), "下载目录"),
    (re.compile(r"(^|\s|=)(~?/)?Documents(/|\s|$)", re.IGNORECASE), "文档目录"),
)

BROAD_PATH_OPTIONS = {
    "--allow-path",
    "--allow-dir",
    "--directory",
    "--root",
    "--workspace",
    "--mount",
    "--path",
    "-d",
}


def evaluate_servers(servers: list[MCPServer]) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for server in servers:
        findings.extend(_check_command(server))
        findings.extend(_check_shell_inline_execution(server))
        findings.extend(_check_remote_package_execution(server))
        findings.extend(_check_credentials(server))
        findings.extend(_check_sensitive_paths(server))
        findings.extend(_check_broad_file_access(server))
        findings.extend(_check_write_permissions(server))
        findings.extend(_check_container_escape_surface(server))
        findings.extend(_check_network_exposure(server))
        findings.extend(_check_prompt_injection(server))
    return _dedupe_findings(findings)


def _check_command(server: MCPServer) -> list[RiskFinding]:
    command_name = _command_basename(server.command)
    if command_name not in HIGH_RISK_COMMANDS:
        return []

    severity = "high"
    if command_name in {"bash", "sh", "zsh", "powershell", "pwsh"}:
        severity = "critical"

    return [
        RiskFinding(
            rule_id="HIGH_RISK_COMMAND",
            title="高风险启动命令",
            severity=severity,
            server_name=server.server_name,
            evidence=f"command={server.command}",
            explanation="该 MCP Server 使用了可执行脚本、Shell、扫描器或网络下载工具，工具调用被提示注入后可能扩大影响范围。",
            recommendation="尽量使用专用 MCP Server 可执行文件；如必须使用该命令，应限制参数、工作目录、网络访问和可读写路径。",
            false_positive_note="安全团队自研脚本或固定版本工具也可能被命中，需要结合启动参数和文件权限判断。",
        )
    ]


def _check_shell_inline_execution(server: MCPServer) -> list[RiskFinding]:
    command_name = _command_basename(server.command)
    if command_name not in {"bash", "sh", "zsh", "powershell", "pwsh"}:
        return []
    if not any(arg in {"-c", "/c", "-Command", "-EncodedCommand"} for arg in server.args):
        return []

    return [
        RiskFinding(
            rule_id="SHELL_INLINE_EXECUTION",
            title="Shell 内联命令执行",
            severity="critical",
            server_name=server.server_name,
            evidence=f"args={_format_args(server.args)}",
            explanation="配置通过 Shell 参数直接执行内联命令，若参数可被拼接或污染，容易形成任意命令执行风险。",
            recommendation="避免在 MCP 配置中使用 Shell 内联命令，改为固定入口程序，并对所有外部输入做白名单校验。",
            false_positive_note="一次性本地实验脚本可能是合法用途，但上线配置应改为固定可执行入口。",
        )
    ]


def _check_remote_package_execution(server: MCPServer) -> list[RiskFinding]:
    command_name = _command_basename(server.command)
    if command_name not in REMOTE_PACKAGE_COMMANDS:
        return []

    severity = "medium"
    evidence = f"command={server.command} args={_format_args(server.args)}"
    if any("@latest" in arg or arg.startswith("http://") or arg.startswith("https://") for arg in server.args):
        severity = "high"

    return [
        RiskFinding(
            rule_id="REMOTE_PACKAGE_EXECUTION",
            title="运行时拉取或执行包管理器命令",
            severity=severity,
            server_name=server.server_name,
            evidence=evidence,
            explanation="MCP Server 通过包管理器入口启动，可能在运行时拉取远程包或执行项目脚本，供应链和版本漂移风险更高。",
            recommendation="固定包版本和完整性校验，生产环境优先使用本地已安装的固定可执行文件。",
            false_positive_note="使用 `npx package@version` 等固定版本方式风险较低，但仍建议在报告中说明来源和版本。",
        )
    ]


def _check_credentials(server: MCPServer) -> list[RiskFinding]:
    findings: list[RiskFinding] = []

    for key, value in server.env.items():
        if _contains_secret_keyword(key):
            findings.append(
                RiskFinding(
                    rule_id="SECRET_IN_ENV",
                    title="环境变量包含疑似凭据",
                    severity="high",
                    server_name=server.server_name,
                    evidence=f"env.{key}={_mask_secret(value)}",
                    explanation="MCP 配置中明文保存 Token、Key 或密码，一旦配置文件被同步、截图或提交到仓库，会导致凭据泄露。",
                    recommendation="改用系统密钥管理器或运行时注入环境变量，避免将真实凭据写入配置文件。",
                    false_positive_note="示例值、占位符或测试 Token 可能被误报，正式审计时应确认值是否真实可用。",
                )
            )

    for arg in server.args:
        lowered = arg.lower()
        if any(keyword in lowered for keyword in SECRET_KEYWORDS):
            findings.append(
                RiskFinding(
                    rule_id="SECRET_IN_ARGS",
                    title="启动参数包含疑似凭据",
                    severity="high",
                    server_name=server.server_name,
                    evidence=f"arg={_mask_secret(arg)}",
                    explanation="命令行参数通常会出现在进程列表、日志或历史记录中，不适合传递敏感凭据。",
                    recommendation="将凭据迁移到受保护的环境变量或密钥管理服务，并避免在日志中输出。",
                    false_positive_note="参数名中包含 key 但语义不是密钥时可能误报，例如 keyboard 或 monkey。",
                )
            )

    return findings


def _check_sensitive_paths(server: MCPServer) -> list[RiskFinding]:
    text = _server_path_text(server)
    findings: list[RiskFinding] = []
    for pattern, label in SENSITIVE_PATH_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                RiskFinding(
                    rule_id="SENSITIVE_PATH_EXPOSURE",
                    title="敏感目录暴露",
                    severity="high",
                    server_name=server.server_name,
                    evidence=f"{label}: {match.group(0).strip()}",
                    explanation="MCP Server 被授予敏感目录访问能力，工具调用异常时可能读取私钥、系统配置或个人文件。",
                    recommendation="只暴露项目所需的最小目录，避免开放 SSH、系统目录、桌面、下载和文档目录。",
                    false_positive_note="只读审计工具可能需要读取部分系统目录，需检查是否明确限制为只读和最小子目录。",
                )
            )
    return findings


def _check_broad_file_access(server: MCPServer) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    home = os.path.expanduser("~")
    tokens = _split_args(server.args)

    for index, token in enumerate(tokens):
        if _is_broad_path(token, home):
            findings.append(_broad_access_finding(server, token))
        if token in BROAD_PATH_OPTIONS and index + 1 < len(tokens):
            next_token = tokens[index + 1]
            if _is_broad_path(next_token, home):
                findings.append(_broad_access_finding(server, f"{token} {next_token}"))

    if server.cwd and _is_broad_path(server.cwd, home):
        findings.append(_broad_access_finding(server, f"cwd={server.cwd}"))

    return findings


def _check_write_permissions(server: MCPServer) -> list[RiskFinding]:
    tokens = _split_args(server.args)
    hits = [token for token in tokens if token in WRITE_FLAGS or token.startswith("--allow-write=")]
    if not hits:
        return []

    return [
        RiskFinding(
            rule_id="WRITE_PERMISSION_ENABLED",
            title="启用了写入或危险权限",
            severity="medium",
            server_name=server.server_name,
            evidence=" ".join(hits),
            explanation="配置显式允许写入或跳过权限检查，工具调用异常时可能修改项目文件或用户文件。",
            recommendation="默认使用只读权限；必须写入时限定目录，并将写操作拆分为独立 MCP Server。",
            false_positive_note="代码生成类 MCP Server 需要写入项目目录，若目录受限且有人工确认，风险可降级。",
        )
    ]


def _check_container_escape_surface(server: MCPServer) -> list[RiskFinding]:
    text = server.searchable_text().lower()
    for pattern in DOCKER_SOCKET_PATTERNS:
        if pattern in text:
            return [
                RiskFinding(
                    rule_id="DOCKER_SOCKET_EXPOSURE",
                    title="Docker Socket 暴露",
                    severity="critical",
                    server_name=server.server_name,
                    evidence=pattern,
                    explanation="Docker Socket 通常等价于宿主机高权限控制面，暴露给 MCP Server 会显著扩大逃逸和持久化风险。",
                    recommendation="不要把 Docker Socket 直接挂载给 MCP Server；改用最小权限代理或只读镜像扫描接口。",
                    false_positive_note="部分容器安全扫描工具需要访问 Docker 元数据，仍应使用专门的只读代理而不是原始 Socket。",
                )
            ]
    return []


def _check_network_exposure(server: MCPServer) -> list[RiskFinding]:
    text = server.searchable_text().lower()
    findings: list[RiskFinding] = []

    if "0.0.0.0" in text:
        findings.append(
            RiskFinding(
                rule_id="PUBLIC_BIND_ADDRESS",
                title="服务绑定到所有网卡",
                severity="high",
                server_name=server.server_name,
                evidence="0.0.0.0",
                explanation="绑定 0.0.0.0 会让本地 MCP 相关服务可能被局域网或容器网络访问。",
                recommendation="本地审计和个人 Agent 工具默认绑定 127.0.0.1，并增加 Token 或来源校验。",
                false_positive_note="容器内部服务可能需要绑定 0.0.0.0，但宿主机端口映射仍应限制来源和鉴权。",
            )
        )

    if _uses_remote_http(server):
        findings.append(
            RiskFinding(
                rule_id="REMOTE_HTTP_ENDPOINT",
                title="远程 HTTP(S) MCP 入口",
                severity="medium",
                server_name=server.server_name,
                evidence=server.url or _first_http_url(text),
                explanation="MCP 配置指向非本机网络端点，工具调用结果和可用性依赖远程服务，存在信任边界和数据出境风险。",
                recommendation="确认远程服务归属、鉴权方式、日志策略和传输加密；敏感任务优先使用本地 Server。",
                false_positive_note="企业托管 MCP 网关是合理架构，但需要配套访问控制和审计日志。",
            )
        )

    if _uses_plain_http(server) and not _has_auth_hint(server):
        findings.append(
            RiskFinding(
                rule_id="UNAUTHENTICATED_HTTP",
                title="疑似无鉴权 HTTP 服务",
                severity="medium",
                server_name=server.server_name,
                evidence=server.url or _first_http_url(text),
                explanation="配置中出现明文 HTTP 入口，但未发现 Token、Authorization 或鉴权相关字段。",
                recommendation="优先使用本机回环地址和鉴权 Token；跨主机访问时使用 HTTPS 或受控代理。",
                false_positive_note="仅绑定 127.0.0.1 的临时调试服务风险较低，但仍建议增加随机 Token。",
            )
        )

    return findings


def _check_prompt_injection(server: MCPServer) -> list[RiskFinding]:
    text = server.searchable_text().lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.lower() in text:
            return [
                RiskFinding(
                    rule_id="PROMPT_INJECTION_TEXT",
                    title="工具描述存在提示注入语句",
                    severity="medium",
                    server_name=server.server_name,
                    evidence=pattern,
                    explanation="工具描述或配置文本中出现诱导模型忽略原有指令、泄露系统提示词的语句，可能污染 Agent 决策。",
                    recommendation="将工具描述改为客观能力说明，并在上线前审计第三方工具返回内容和元数据。",
                    false_positive_note="安全测试样本库中可能故意包含提示注入文本，应与真实工具描述区分存放。",
                )
            ]
    return []


def _broad_access_finding(server: MCPServer, evidence: str) -> RiskFinding:
    return RiskFinding(
        rule_id="BROAD_FILE_ACCESS",
        title="过宽文件访问范围",
        severity="high",
        server_name=server.server_name,
        evidence=evidence,
        explanation="配置授予了根目录、用户主目录或通配符路径访问权限，不符合最小权限原则。",
        recommendation="将访问范围缩小到单个项目目录，并按读写能力拆分权限。",
        false_positive_note="沙箱目录内的通配符可能是可接受的，但根目录和用户主目录不应作为默认授权。",
    )


def _server_path_text(server: MCPServer) -> str:
    return "\n".join([server.cwd, " ".join(server.args), str(server.env), str(server.raw_config)])


def _command_basename(command: str) -> str:
    if not command:
        return ""
    try:
        first = shlex.split(command)[0]
    except ValueError:
        first = command.split()[0]
    return PurePosixPath(first).name.lower()


def _split_args(args: list[str]) -> list[str]:
    tokens: list[str] = []
    for arg in args:
        try:
            tokens.extend(shlex.split(arg))
        except ValueError:
            tokens.append(arg)
    return tokens


def _format_args(args: list[str]) -> str:
    return " ".join(args)


def _contains_secret_keyword(value: str) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in SECRET_KEYWORDS)


def _mask_secret(value: str) -> str:
    if not value:
        return "<empty>"
    if len(value) <= 8:
        return "***"
    return f"{value[:3]}***{value[-3:]}"


def _is_broad_path(value: str, home: str) -> bool:
    normalized = value.strip().strip("'\"")
    if not normalized:
        return False
    if normalized in {"/", "~", "~/", "$HOME", "${HOME}"}:
        return True
    if normalized == home or normalized == f"{home}/":
        return True
    if normalized.endswith("/*") or normalized in {"./*", "../*"}:
        return True
    return False


def _uses_plain_http(server: MCPServer) -> bool:
    return server.url.lower().startswith("http://") or "http://" in server.searchable_text().lower()


def _uses_remote_http(server: MCPServer) -> bool:
    url = server.url.lower()
    if not (url.startswith("http://") or url.startswith("https://")):
        return False
    return not any(host in url for host in ("127.0.0.1", "localhost", "[::1]"))


def _has_auth_hint(server: MCPServer) -> bool:
    text = server.searchable_text().lower()
    return any(hint in text for hint in ("authorization", "bearer", "token", "api_key", "apikey", "auth"))


def _first_http_url(text: str) -> str:
    match = re.search(r"http://[^\s'\"}]+", text)
    return match.group(0) if match else "http://"


def _dedupe_findings(findings: list[RiskFinding]) -> list[RiskFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[RiskFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.server_name, finding.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
