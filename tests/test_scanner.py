import json
import unittest

from mcp_guard.scanner import ConfigParseError, parse_mcp_config


class ScannerTest(unittest.TestCase):
    def test_parse_claude_style_config(self):
        content = json.dumps(
            {
                "mcpServers": {
                    "notes": {
                        "command": "mcp-notes-server",
                        "args": ["--readonly", "./notes"],
                        "env": {"MODE": "readonly"},
                    }
                }
            }
        )

        servers, raw_config = parse_mcp_config(content)

        self.assertEqual(raw_config["mcpServers"]["notes"]["command"], "mcp-notes-server")
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].server_name, "notes")
        self.assertEqual(servers[0].args, ["--readonly", "./notes"])

    def test_parse_list_style_config(self):
        content = json.dumps(
            {
                "servers": [
                    {
                        "name": "remote",
                        "url": "http://127.0.0.1:8080/mcp",
                    }
                ]
            }
        )

        servers, _ = parse_mcp_config(content)

        self.assertEqual(servers[0].server_name, "remote")
        self.assertEqual(servers[0].url, "http://127.0.0.1:8080/mcp")

    def test_invalid_json_has_friendly_error(self):
        with self.assertRaises(ConfigParseError) as context:
            parse_mcp_config("{bad json")

        self.assertIn("配置解析失败", str(context.exception))

    def test_parse_yaml_config(self):
        content = """
mcpServers:
  yaml-server:
    command: mcp-yaml-server
    args:
      - --readonly
      - ./data
"""

        servers, _ = parse_mcp_config(content, source_name="mcp.yaml")

        self.assertEqual(servers[0].server_name, "yaml-server")
        self.assertEqual(servers[0].command, "mcp-yaml-server")

    def test_parse_toml_config(self):
        content = """
[mcpServers.toml-server]
command = "mcp-toml-server"
args = ["--readonly", "./data"]
"""

        servers, _ = parse_mcp_config(content, source_name="mcp.toml")

        self.assertEqual(servers[0].server_name, "toml-server")
        self.assertEqual(servers[0].args, ["--readonly", "./data"])


if __name__ == "__main__":
    unittest.main()
