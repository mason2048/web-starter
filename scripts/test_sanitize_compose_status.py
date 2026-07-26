from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import sanitize_compose_status as status


class SanitizeComposeStatusTest(unittest.TestCase):
    def test_writes_only_allowlisted_service_state_and_health(self) -> None:
        document = status.sanitize(
            "redis|running|healthy\n"
            "app|exited|unhealthy\n"
            "mcp-public-nginx|restarting|starting\n"
        )

        self.assertEqual(1, document["schemaVersion"])
        self.assertEqual(
            ["app", "mcp-public-nginx", "redis"],
            [service["service"] for service in document["services"]],
        )
        self.assertEqual(
            {"service", "state", "health"}, set(document["services"][0])
        )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime-compose-ps.json"
            status.write_private(output, document)
            self.assertEqual(document, json.loads(output.read_text(encoding="utf-8")))
            if os.name == "posix":
                self.assertEqual(0, stat.S_IMODE(output.stat().st_mode) & 0o077)
            with self.assertRaises(FileExistsError):
                status.write_private(output, document)

    def test_rejects_command_password_unknown_fields_and_duplicates(self) -> None:
        invalid = (
            'redis|running|healthy|redis-server --requirepass "actual-secret"',
            "redis|running|actual-secret",
            "unknown|running|healthy",
            "redis|running|healthy\nredis|running|healthy",
            '{"Service":"redis","Command":"--requirepass actual-secret"}',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(status.ComposeStatusError):
                status.sanitize(raw)


if __name__ == "__main__":
    unittest.main()
