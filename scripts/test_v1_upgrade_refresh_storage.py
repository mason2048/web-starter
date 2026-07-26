from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import scripts.rehearse_v1_to_v2_upgrade as upgrade


RUN_ID = "2468ace01357"


class V1UpgradeRefreshStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-refresh-storage-")
        root = Path(self.temporary.name)
        runtime_root = root / "runtime"
        runtime_root.mkdir(mode=0o700)
        self.runtime = upgrade.RuntimeContext(
            root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(38080, 38443, 38081),
            upgrade.EvidenceState(),
        )
        self.runtime.environment["WEB_STARTER_TOKEN_PEPPER"] = "p" * 48
        self.old_refresh = "old-refresh-" + "a" * 64
        self.new_refresh = "new-refresh-" + "b" * 64
        self.authorization_id = "authorization-1234"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def query_side_effect(self, outputs: list[bytes], sql_seen: list[str]):
        def query(_runtime, _runner, sql, **_kwargs):
            sql_seen.append(sql)
            return outputs.pop(0)

        return query

    def test_v1_refresh_storage_matches_the_private_raw_token_hmac(self) -> None:
        token_hash = upgrade._token_hmac(self.runtime, self.old_refresh)
        outputs = [
            f"{self.authorization_id}\thmac${token_hash}\t7200\n".encode("ascii"),
            f"{self.authorization_id}\t{token_hash}\t0\t1\t7200\n".encode("ascii"),
            f"{token_hash}\t0\t0\t1\t7200\n".encode("ascii"),
        ]
        sql_seen: list[str] = []
        with patch.object(
            upgrade, "_mysql_query", side_effect=self.query_side_effect(outputs, sql_seen)
        ):
            observed = upgrade._validate_refresh_storage_before_upgrade(
                self.runtime, object(), self.old_refresh  # type: ignore[arg-type]
            )
        self.assertEqual(self.authorization_id, observed)
        self.assertTrue(all(self.old_refresh not in sql for sql in sql_seen))
        self.assertFalse(outputs)

    def test_rotation_requires_generation_history_and_latest_only_access_registry(self) -> None:
        old_hash = upgrade._token_hmac(self.runtime, self.old_refresh)
        new_hash = upgrade._token_hmac(self.runtime, self.new_refresh)
        outputs = [
            f"hmac${new_hash}\t7200\n".encode("ascii"),
            f"{new_hash}\t1\t1\n".encode("ascii"),
            (
                f"0\t{old_hash}\t1\t1\n"
                f"1\t{new_hash}\t0\t1\n"
            ).encode("ascii"),
            b"2\t1\n",
        ]
        sql_seen: list[str] = []
        with patch.object(
            upgrade, "_mysql_query", side_effect=self.query_side_effect(outputs, sql_seen)
        ):
            upgrade._validate_refresh_storage_after_rotation(
                self.runtime,
                object(),  # type: ignore[arg-type]
                self.authorization_id,
                self.old_refresh,
                self.new_refresh,
            )
        self.assertTrue(all(self.old_refresh not in sql and self.new_refresh not in sql for sql in sql_seen))
        self.assertFalse(outputs)

    def test_replay_requires_authorization_removal_family_history_and_access_revocation(self) -> None:
        outputs = [
            b"0\n",
            b"1\t1\tREFRESH_TOKEN_REUSE\n",
            b"0\t1\tREFRESH_TOKEN_REUSE\n1\t1\tREFRESH_TOKEN_REUSE\n",
            b"2\t0\n",
        ]
        with patch.object(
            upgrade, "_mysql_query", side_effect=self.query_side_effect(outputs, [])
        ):
            upgrade._validate_refresh_storage_after_reuse(
                self.runtime, object(), self.authorization_id  # type: ignore[arg-type]
            )
        self.assertFalse(outputs)

    def test_wrong_generation_or_active_access_token_fails_closed(self) -> None:
        new_hash = upgrade._token_hmac(self.runtime, self.new_refresh)
        outputs = [
            f"hmac${new_hash}\t7200\n".encode("ascii"),
            f"{new_hash}\t2\t1\n".encode("ascii"),
            b"",
            b"",
        ]
        with patch.object(
            upgrade, "_mysql_query", side_effect=self.query_side_effect(outputs, [])
        ), self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "family"):
            upgrade._validate_refresh_storage_after_rotation(
                self.runtime,
                object(),  # type: ignore[arg-type]
                self.authorization_id,
                self.old_refresh,
                self.new_refresh,
            )


if __name__ == "__main__":
    unittest.main()
