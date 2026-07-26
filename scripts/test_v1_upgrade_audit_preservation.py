from __future__ import annotations

import unittest
from unittest.mock import patch

import scripts.rehearse_v1_to_v2_upgrade as upgrade


HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


class V1UpgradeAuditPreservationTest(unittest.TestCase):
    def test_projection_hashes_frame_every_v1_column_and_return_one_digest_per_row(self) -> None:
        captured: list[str] = []

        def query(_runtime, _runner, sql, *, database, label):
            self.assertEqual("ws_v1_test", database)
            self.assertEqual("projection-ws_v1_test-sys_user", label)
            captured.append(sql)
            return f"{HASH_B}\n{HASH_A}\n".encode("ascii")

        profile = {
            "sys_user": {
                "columns": ("id", "nullable_value", "binary_value"),
                "order": ("id",),
            }
        }
        with patch.object(upgrade, "_mysql_query", side_effect=query):
            result = upgrade._projection_hashes(object(), object(), "ws_v1_test", profile)

        self.assertEqual((HASH_A, HASH_B), result["sys_user"])
        self.assertEqual(1, len(captured))
        sql = captured[0]
        for column in profile["sys_user"]["columns"]:
            self.assertIn(
                f"CASE WHEN `{column}` IS NULL THEN UNHEX('00')",
                sql,
            )
            self.assertIn(
                f"OCTET_LENGTH(CAST(`{column}` AS BINARY))",
                sql,
            )
            self.assertIn(f"CAST(`{column}` AS BINARY)", sql)
        self.assertEqual(3, sql.count("UNHEX('01')"))
        self.assertEqual(3, sql.count("LPAD(HEX(OCTET_LENGTH("))
        self.assertIn("SELECT LOWER(SHA2(CONCAT(", sql)
        self.assertIn("ORDER BY `row_sha256`", sql)

    def test_null_empty_and_column_boundaries_have_distinct_prefix_free_frames(self) -> None:
        expression = upgrade._framed_column_expression("payload")
        self.assertIn("IS NULL THEN UNHEX('00')", expression)
        self.assertIn("ELSE CONCAT(UNHEX('01')", expression)
        self.assertIn("LPAD(HEX(OCTET_LENGTH(CAST(`payload` AS BINARY))),16,'0')", expression)
        self.assertIn("CAST(`payload` AS BINARY)", expression)

    def test_unsafe_identifiers_are_rejected_before_any_database_query(self) -> None:
        with patch.object(upgrade, "_mysql_query") as query:
            with self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade._projection_profile(
                    object(), object(), "ws_v1_test", ("sys_user` UNION SELECT secret",)
                )
            query.assert_not_called()

        with patch.object(upgrade, "_mysql_query") as query:
            with self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade._projection_hashes(
                    object(),
                    object(),
                    "ws_v1_test",
                    {
                        "sys_user": {
                            "columns": ("id", "unsafe-name"),
                            "order": ("id",),
                        }
                    },
                )
            query.assert_not_called()

    def test_profile_rejects_duplicate_or_non_column_primary_identifiers(self) -> None:
        responses = iter((b"id\nid\n", b"id\n"))
        with patch.object(upgrade, "_mysql_query", side_effect=lambda *_args, **_kwargs: next(responses)):
            with self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade._projection_profile(object(), object(), "ws_v1_test", ("sys_user",))

        responses = iter((b"id\nname\n", b"missing_id\n"))
        with patch.object(upgrade, "_mysql_query", side_effect=lambda *_args, **_kwargs: next(responses)):
            with self.assertRaises(upgrade.UpgradeRehearsalError):
                upgrade._projection_profile(object(), object(), "ws_v1_test", ("sys_user",))

    def test_non_audit_tables_require_exact_row_digest_multiset(self) -> None:
        before = {"sys_user": (HASH_A, HASH_B)}
        after = {"sys_user": (HASH_B, HASH_A)}
        counts = {"sys_user": 2}
        upgrade._assert_v1_projection_preserved(before, after, counts, counts)

        with self.assertRaises(upgrade.UpgradeRehearsalError) as changed:
            upgrade._assert_v1_projection_preserved(
                before,
                {"sys_user": (HASH_A, HASH_C)},
                counts,
                counts,
            )
        self.assertNotIn(HASH_A, str(changed.exception))
        self.assertNotIn(HASH_B, str(changed.exception))
        self.assertNotIn(HASH_C, str(changed.exception))

        with self.assertRaises(upgrade.UpgradeRehearsalError):
            upgrade._assert_v1_projection_preserved(
                before,
                {"sys_user": (HASH_A, HASH_B, HASH_C)},
                counts,
                {"sys_user": 3},
            )

    def test_all_three_audit_tables_allow_new_rows_but_preserve_every_old_digest(self) -> None:
        before = {table: (HASH_A,) for table in upgrade.AUDIT_TABLES}
        after = {table: (HASH_A, HASH_B) for table in upgrade.AUDIT_TABLES}
        before_counts = {table: 1 for table in upgrade.AUDIT_TABLES}
        after_counts = {table: 2 for table in upgrade.AUDIT_TABLES}
        upgrade._assert_v1_projection_preserved(before, after, before_counts, after_counts)

    def test_audit_comparison_is_not_a_row_count_only_check(self) -> None:
        table = "sys_operation_log"
        with self.assertRaises(upgrade.UpgradeRehearsalError) as changed:
            upgrade._assert_v1_projection_preserved(
                {table: (HASH_A,)},
                {table: (HASH_B,)},
                {table: 1},
                {table: 1},
            )
        self.assertEqual("V1_AUDIT_PROJECTION", changed.exception.code)
        self.assertNotIn(HASH_A, str(changed.exception))
        self.assertNotIn(HASH_B, str(changed.exception))

    def test_audit_comparison_preserves_duplicate_digest_multiplicity(self) -> None:
        table = "sys_mcp_call_log"
        with self.assertRaises(upgrade.UpgradeRehearsalError):
            upgrade._assert_v1_projection_preserved(
                {table: (HASH_A, HASH_A)},
                {table: (HASH_A, HASH_B)},
                {table: 2},
                {table: 2},
            )

    def test_invalid_digest_or_cardinality_fails_closed_without_exposing_values(self) -> None:
        with self.assertRaises(upgrade.UpgradeRehearsalError) as invalid:
            upgrade._assert_v1_projection_preserved(
                {"sys_user": ("not-a-digest",)},
                {"sys_user": (HASH_A,)},
                {"sys_user": 1},
                {"sys_user": 1},
            )
        self.assertNotIn("not-a-digest", str(invalid.exception))

        with self.assertRaises(upgrade.UpgradeRehearsalError):
            upgrade._assert_v1_projection_preserved(
                {"sys_user": (HASH_A,)},
                {"sys_user": (HASH_A,)},
                {"sys_user": 2},
                {"sys_user": 1},
            )


if __name__ == "__main__":
    unittest.main()
