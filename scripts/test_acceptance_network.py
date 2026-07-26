from __future__ import annotations

import os
import unittest
from unittest import mock

from scripts.acceptance_network import is_isolated_acceptance_host


class AcceptanceNetworkTest(unittest.TestCase):
    def test_only_ip_literals_or_explicit_reserved_aliases_are_loopback(self) -> None:
        with mock.patch.dict(os.environ, {
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS": "mcp.acceptance.webstarter.test",
            "WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS": "127.0.0.1",
        }, clear=False):
            self.assertTrue(is_isolated_acceptance_host("127.0.0.1"))
            self.assertTrue(is_isolated_acceptance_host("127.42.0.9"))
            self.assertTrue(is_isolated_acceptance_host("::1"))
            self.assertTrue(is_isolated_acceptance_host("localhost"))
            self.assertTrue(is_isolated_acceptance_host("mcp.acceptance.webstarter.test"))
            self.assertFalse(is_isolated_acceptance_host("127.attacker.example"))
            self.assertFalse(is_isolated_acceptance_host("127.0.0.1.attacker.example"))
            self.assertFalse(is_isolated_acceptance_host("mcp.external.example"))


if __name__ == "__main__":
    unittest.main()
