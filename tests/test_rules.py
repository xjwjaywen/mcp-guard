import json
import unittest

from mcp_guard.rules import evaluate_servers
from mcp_guard.scanner import parse_mcp_config
from mcp_guard.scoring import score_findings


def scan(config):
    servers, _ = parse_mcp_config(json.dumps(config))
    return evaluate_servers(servers)


class RulesTest(unittest.TestCase):
    def test_low_risk_config_has_no_findings(self):
        findings = scan(
            {
                "mcpServers": {
                    "notes": {
                        "command": "mcp-notes-server",
                        "args": ["--readonly", "./notes"],
                    }
                }
            }
        )

        self.assertEqual(findings, [])

    def test_secret_env_is_high_risk(self):
        findings = scan(
            {
                "mcpServers": {
                    "api": {
                        "command": "mcp-api-server",
                        "env": {"API_TOKEN": "abc123456789"},
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "SECRET_IN_ENV" for f in findings))

    def test_shell_inline_execution_is_critical(self):
        findings = scan(
            {
                "mcpServers": {
                    "runner": {
                        "command": "bash",
                        "args": ["-c", "python3 server.py"],
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "SHELL_INLINE_EXECUTION" for f in findings))
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_sensitive_path_is_high_risk(self):
        findings = scan(
            {
                "mcpServers": {
                    "files": {
                        "command": "mcp-files",
                        "args": ["--allow-path", "~/.ssh"],
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "SENSITIVE_PATH_EXPOSURE" for f in findings))

    def test_public_bind_and_http_are_detected(self):
        findings = scan(
            {
                "mcpServers": {
                    "remote": {
                        "url": "http://0.0.0.0:9000/mcp",
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "PUBLIC_BIND_ADDRESS" for f in findings))
        self.assertTrue(any(f.rule_id == "UNAUTHENTICATED_HTTP" for f in findings))

    def test_scoring_caps_at_100(self):
        findings = scan(
            {
                "mcpServers": {
                    "danger": {
                        "command": "bash",
                        "args": ["-c", "python3 app.py --host 0.0.0.0 --root /"],
                        "env": {"SECRET_KEY": "abcdef123456"},
                        "cwd": "/",
                    }
                }
            }
        )

        score = score_findings(findings)

        self.assertLessEqual(score["score"], 100)
        self.assertGreaterEqual(score["score"], 70)

    def test_remote_package_execution_is_detected(self):
        findings = scan(
            {
                "mcpServers": {
                    "remote-package": {
                        "command": "npx",
                        "args": ["some-mcp-server@latest"],
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "REMOTE_PACKAGE_EXECUTION" for f in findings))

    def test_docker_socket_is_critical(self):
        findings = scan(
            {
                "mcpServers": {
                    "docker": {
                        "command": "mcp-docker",
                        "args": ["--mount", "/var/run/docker.sock"],
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "DOCKER_SOCKET_EXPOSURE" for f in findings))

    def test_write_permission_flag_is_detected(self):
        findings = scan(
            {
                "mcpServers": {
                    "writer": {
                        "command": "mcp-files",
                        "args": ["--allow-write", "./workspace"],
                    }
                }
            }
        )

        self.assertTrue(any(f.rule_id == "WRITE_PERMISSION_ENABLED" for f in findings))

    def test_finding_has_false_positive_note(self):
        findings = scan(
            {
                "mcpServers": {
                    "runner": {
                        "command": "bash",
                        "args": ["-c", "echo hello"],
                    }
                }
            }
        )

        self.assertTrue(any(f.false_positive_note for f in findings))


if __name__ == "__main__":
    unittest.main()
