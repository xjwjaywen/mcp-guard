# MCP-Guard

MCP-Guard 是一个本地运行的 MCP 工具调用安全审计仪表盘。它读取 MCP 配置文件或粘贴的 JSON/YAML/TOML 配置，静态分析 MCP Server 的启动命令、参数、环境变量、路径授权、网络入口和工具描述，并生成风险评分、问题证据、误报说明和修复建议。

项目定位是课程/实验室小项目：不执行配置里的命令，不连接外部目标，只做本地静态审计，便于教学演示、截图展示和开源说明。

## 项目声明

- **项目名称：** MCP-Guard
- **项目作者：** 待填写
- **作者单位：** 暨南大学网络空间安全学院

## 功能

- 上传或粘贴 `claude_desktop_config.json`、`mcp.json`、Cursor MCP 配置，以及 YAML/TOML 格式配置。
- 自动发现本机常见 MCP 配置路径，例如 Claude Desktop、Cursor、VS Code、Windsurf。
- 内置低风险、中风险、高风险三类示例。
- 检测高风险命令、Shell 内联执行、运行时包管理器启动、敏感路径暴露、明文凭据、公网绑定、远程 HTTP 入口、无鉴权 HTTP、Docker Socket 暴露、写入权限、过宽文件访问和提示注入文本。
- 在 Web 仪表盘显示风险分数、风险等级、Server 数量、高危问题数量和问题详情。
- 导出并保存 JSON 和 Markdown 审计报告到 `reports/` 目录。

## 快速开始

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

打开：

```text
http://127.0.0.1:5000
```

默认只监听 `127.0.0.1`，避免审计工具自身暴露到局域网。

## CLI 用法

扫描单个文件：

```bash
python -m mcp_guard scan examples/high-risk.json
```

扫描多个文件：

```bash
python -m mcp_guard scan examples/high-risk.json examples/high-risk.yaml examples/high-risk.toml
```

发现本机常见 MCP 配置路径：

```bash
python -m mcp_guard discover
```

发现后直接扫描：

```bash
python -m mcp_guard discover --scan
```

## 项目结构

```text
mcp_guard/
  scanner.py   # JSON 配置解析和 MCP Server 标准化
  rules.py     # 风险规则
  scoring.py   # 风险评分
  report.py    # JSON / Markdown 报告
  storage.py   # 报告落盘和读取
  discovery.py # 常见 MCP 配置路径发现
  cli.py       # 命令行入口
  web.py       # Flask 路由
templates/     # Web 页面
static/        # 样式
examples/      # 示例配置
tests/         # 单元测试
```

## 检测规则

| 规则 | 风险 |
|---|---|
| `HIGH_RISK_COMMAND` | 使用 `bash`、`python`、`node`、`curl`、`nmap`、`sqlmap` 等高风险命令 |
| `SHELL_INLINE_EXECUTION` | 通过 `bash -c`、PowerShell 等方式执行内联命令 |
| `REMOTE_PACKAGE_EXECUTION` | 使用 `npx`、`uvx`、`pipx` 等包管理器入口运行 MCP Server |
| `SECRET_IN_ENV` / `SECRET_IN_ARGS` | 环境变量或启动参数中包含疑似 Token、Key、Secret、Password |
| `SENSITIVE_PATH_EXPOSURE` | 暴露 `~/.ssh`、`/etc`、`Desktop`、`Downloads`、`Documents` 等敏感目录 |
| `PUBLIC_BIND_ADDRESS` | 服务绑定到 `0.0.0.0` |
| `REMOTE_HTTP_ENDPOINT` | 指向非本机 HTTP(S) MCP 服务 |
| `UNAUTHENTICATED_HTTP` | 出现明文 HTTP 入口且未发现鉴权线索 |
| `DOCKER_SOCKET_EXPOSURE` | 暴露 Docker Socket |
| `WRITE_PERMISSION_ENABLED` | 开启写入、跳过权限或特权参数 |
| `BROAD_FILE_ACCESS` | 授权根目录、用户主目录或通配符路径 |
| `PROMPT_INJECTION_TEXT` | 工具描述包含忽略原有指令、泄露系统提示词等提示注入文本 |

每条风险结果都包含 `false_positive_note` 字段，用于说明可能误报的合理场景，便于人工复核。

## 测试

```bash
python -m unittest
```

测试覆盖：

- Claude/Cursor 常见 MCP 配置结构解析。
- JSON、YAML、TOML 格式解析。
- 配置格式错误提示。
- 本机路径自动发现。
- 明文凭据检测。
- Shell 内联执行检测。
- 敏感路径检测。
- `0.0.0.0` 和无鉴权 HTTP 检测。
- Docker Socket、包管理器启动、写入权限检测。
- 风险评分上限。

## 示例配置

仓库内置了三个配置：

- `examples/low-risk.json`
- `examples/medium-risk.json`
- `examples/high-risk.json`
- `examples/high-risk.yaml`
- `examples/high-risk.toml`

Web 首页也可以直接点击示例扫描，适合课堂或项目汇报演示。

## 安全边界

MCP-Guard 只做静态审计：

- 不执行 MCP Server 的 `command`。
- 不主动扫描网络目标。
- 不验证凭据有效性。
- 不读取配置中授权路径里的文件。

因此它适合作为 MCP 配置上线前检查工具或 AI Agent 工具调用安全教学样例。
