import tempfile
import unittest
from pathlib import Path

from mcp_guard.discovery import discover_config_files


class DiscoveryTest(unittest.TestCase):
    def test_discovers_workspace_mcp_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            path.write_text('{"mcpServers": {}}', encoding="utf-8")

            discovered = discover_config_files(tmp)

            self.assertTrue(any(item.path == path.resolve() for item in discovered))


if __name__ == "__main__":
    unittest.main()
