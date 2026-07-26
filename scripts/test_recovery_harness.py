from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.recovery_common import (
    CRITICAL_TABLES,
    MANIFEST_VERSION,
    REPO_ROOT,
    RecoveryError,
    STABLE_DOMAIN_TABLES,
    collect_table_counts,
    ensure_table_inventory_matches,
    ensure_audit_not_lost,
    ensure_external_output_directory,
    generated_restore_target,
    list_database_tables,
    prepare_external_report_file,
    required_tables_for_schema_version,
    row_counts_tsv,
    sha256_file,
    validate_ac40_project,
    validate_ac41_project,
    validate_backup_package,
    validate_restore_target,
    write_private_json,
    write_private_text,
)


class RecoveryHarnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-recovery-test-")
        self.root = Path(self.temporary.name)
        self.package_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_refresh_family_fingerprints_use_real_primary_keys(self) -> None:
        credential_tables = dict(STABLE_DOMAIN_TABLES["credential_hashes"])
        self.assertEqual("authorization_id", credential_tables["sec_oauth_refresh_family"])
        self.assertEqual("authorization_id, generation", credential_tables["sec_oauth_refresh_history"])

    def package(self) -> Path:
        package = self.root / "package"
        package.mkdir(mode=0o700)
        sql = package / "database.sql"
        flyway = package / "flyway-history.tsv"
        counts = package / "critical-row-counts.tsv"
        write_private_text(sql, "CREATE TABLE example (id BIGINT PRIMARY KEY);\n")
        write_private_text(
            flyway,
            "installed_rank\tversion\tdescription\ttype\tscript\tchecksum\tinstalled_by\t"
            "installed_on_utc\texecution_time_ms\tsuccess\n",
        )
        table_counts = {table: index for index, table in enumerate(CRITICAL_TABLES)}
        write_private_text(counts, row_counts_tsv(table_counts))
        write_private_text(package / "database.sql.sha256", f"{sha256_file(sql)}  database.sql\n")
        manifest = {
            "manifestVersion": MANIFEST_VERSION,
            "application": {"version": "2.0.0-test"},
            "source": {"composeProject": "web-starter-ac40-test", "database": "web_starter"},
            "consistency": {"applicationStopped": True, "ac40Eligible": True},
            "artifacts": {
                "sql": {"file": sql.name, "sha256": sha256_file(sql), "bytes": sql.stat().st_size},
                "flywayHistory": {"file": flyway.name, "sha256": sha256_file(flyway), "rows": 0},
                "criticalRowCounts": {
                    "file": counts.name,
                    "sha256": sha256_file(counts),
                    "tables": table_counts,
                },
            },
        }
        manifest_path = package / "manifest.json"
        write_private_json(manifest_path, manifest)
        write_private_text(
            package / "manifest.json.sha256", f"{sha256_file(manifest_path)}  manifest.json\n"
        )
        return package

    def versioned_package(
        self,
        version: int,
        *,
        counted_tables: tuple[str, ...] | None = None,
        declared_required_tables: tuple[str, ...] | None = None,
    ) -> Path:
        self.package_index += 1
        package = self.root / f"versioned-package-{self.package_index}"
        package.mkdir(mode=0o700)
        sql = package / "database.sql"
        flyway = package / "flyway-history.tsv"
        counts = package / "critical-row-counts.tsv"
        write_private_text(sql, "CREATE TABLE example (id BIGINT PRIMARY KEY);\n")
        flyway_header = (
            "installed_rank\tversion\tdescription\ttype\tscript\tchecksum\tinstalled_by\t"
            "installed_on_utc\texecution_time_ms\tsuccess\n"
        )
        flyway_body = "".join(
            f"{item}\t{item}\tmigration {item}\tSQL\tV{item}__migration.sql\t{item}\ttest\t"
            f"2026-07-19T00:00:0{item}.000000Z\t1\t1\n"
            for item in range(1, version + 1)
        )
        write_private_text(flyway, flyway_header + flyway_body)
        required = required_tables_for_schema_version(version)
        actual = counted_tables if counted_tables is not None else required
        table_counts = {table: index for index, table in enumerate(sorted(actual))}
        write_private_text(counts, row_counts_tsv(table_counts))
        write_private_text(package / "database.sql.sha256", f"{sha256_file(sql)}  database.sql\n")
        manifest = {
            "manifestVersion": MANIFEST_VERSION,
            "application": {"version": "1.0.0-test"},
            "source": {"composeProject": "web-starter-ac40-test", "database": "web_starter"},
            "consistency": {"applicationStopped": True, "ac40Eligible": True},
            "databaseSchema": {
                "profile": f"web-starter-flyway-v{version}",
                "flywayVersion": str(version),
                "requiredTables": list(
                    declared_required_tables
                    if declared_required_tables is not None
                    else required
                ),
                "countedTables": sorted(actual),
            },
            "artifacts": {
                "sql": {"file": sql.name, "sha256": sha256_file(sql), "bytes": sql.stat().st_size},
                "flywayHistory": {
                    "file": flyway.name,
                    "sha256": sha256_file(flyway),
                    "rows": version,
                },
                "criticalRowCounts": {
                    "file": counts.name,
                    "sha256": sha256_file(counts),
                    "tables": table_counts,
                },
            },
        }
        manifest_path = package / "manifest.json"
        write_private_json(manifest_path, manifest)
        write_private_text(
            package / "manifest.json.sha256", f"{sha256_file(manifest_path)}  manifest.json\n"
        )
        return package

    def test_valid_package_covers_all_critical_tables(self) -> None:
        _, counts = validate_backup_package(self.package())
        self.assertEqual(set(CRITICAL_TABLES), set(counts))

    def test_v3_profile_does_not_require_v5_idempotency_table(self) -> None:
        required = required_tables_for_schema_version(3)
        self.assertIn("sec_oauth_refresh_family", required)
        self.assertNotIn("mcp_idempotency_record", required)

    def test_v7_profile_requires_idempotency_table(self) -> None:
        self.assertIn("mcp_idempotency_record", required_tables_for_schema_version(7))

    def test_v3_versioned_package_is_accepted_without_v5_table(self) -> None:
        manifest, counts = validate_backup_package(self.versioned_package(3))
        self.assertEqual("3", manifest["databaseSchema"]["flywayVersion"])
        self.assertNotIn("mcp_idempotency_record", counts)

    def test_versioned_package_counts_generated_tables_beyond_core_profile(self) -> None:
        actual = (*required_tables_for_schema_version(3), "generated_example")
        _, counts = validate_backup_package(self.versioned_package(3, counted_tables=actual))
        self.assertIn("generated_example", counts)

    def test_versioned_package_cannot_silently_omit_a_required_table(self) -> None:
        required = required_tables_for_schema_version(3)
        incomplete = tuple(table for table in required if table != "sys_config")
        package = self.versioned_package(
            3,
            counted_tables=incomplete,
            declared_required_tables=incomplete,
        )
        with self.assertRaisesRegex(RecoveryError, "required table set"):
            validate_backup_package(package)

    def test_v7_versioned_package_cannot_omit_idempotency_table(self) -> None:
        required = required_tables_for_schema_version(7)
        incomplete = tuple(table for table in required if table != "mcp_idempotency_record")
        package = self.versioned_package(7, counted_tables=incomplete)
        with self.assertRaisesRegex(RecoveryError, "required tables"):
            validate_backup_package(package)

    def test_future_schema_version_is_rejected_until_inventory_profile_is_updated(self) -> None:
        with self.assertRaisesRegex(RecoveryError, "newer than this recovery tool"):
            required_tables_for_schema_version(8)

    def test_restore_inventory_must_exactly_match_manifest(self) -> None:
        expected = required_tables_for_schema_version(3)
        ensure_table_inventory_matches(expected, reversed(expected))
        with self.assertRaisesRegex(RecoveryError, "unexpected tables"):
            ensure_table_inventory_matches(expected, (*expected, "generated_example"))
        with self.assertRaisesRegex(RecoveryError, "missing tables"):
            ensure_table_inventory_matches(expected, expected[:-1])

    def test_v3_inventory_collection_never_queries_v5_only_table(self) -> None:
        required = required_tables_for_schema_version(3)

        class RecordingContext:
            def __init__(self) -> None:
                self.queries: list[str] = []

            def mysql_query(self, sql: str, **_: object) -> bytes:
                self.queries.append(sql)
                if "information_schema.tables" in sql:
                    return ("\n".join(sorted(required)) + "\n").encode("ascii")
                return b"0\n"

        context = RecordingContext()
        tables = list_database_tables(context)  # type: ignore[arg-type]
        counts = collect_table_counts(context, tables)  # type: ignore[arg-type]
        self.assertEqual(set(required), set(counts))
        self.assertFalse(any("mcp_idempotency_record" in query for query in context.queries))

    def test_sql_tampering_is_rejected(self) -> None:
        package = self.package()
        with (package / "database.sql").open("a", encoding="utf-8") as stream:
            stream.write("DROP TABLE example;\n")
        with self.assertRaisesRegex(RecoveryError, "checksum mismatch"):
            validate_backup_package(package)

    def test_symlink_artifact_is_rejected(self) -> None:
        package = self.package()
        sql = package / "database.sql"
        external = self.root / "external.sql"
        external.write_text(sql.read_text(encoding="utf-8"), encoding="utf-8")
        sql.unlink()
        sql.symlink_to(external)
        with self.assertRaisesRegex(RecoveryError, "not a regular file"):
            validate_backup_package(package)

    def test_restore_target_is_always_new_and_prefixed(self) -> None:
        target = generated_restore_target("web_starter", suffix="20260719T010203")
        self.assertEqual("web_starter_restore_20260719T010203", target)
        self.assertEqual(target, validate_restore_target("web_starter", target))
        for unsafe in ("web_starter", "production_restore_test", "web_starter_restore_x;DROP"):
            with self.subTest(unsafe=unsafe), self.assertRaises(RecoveryError):
                validate_restore_target("web_starter", unsafe)

    def test_redis_rehearsal_project_must_use_isolated_prefix(self) -> None:
        self.assertEqual(
            "web-starter-ac41-test1", validate_ac41_project("web-starter-ac41-test1")
        )
        for unsafe in ("web-starter", "production", "web-starter-ac40-test"):
            with self.subTest(unsafe=unsafe), self.assertRaises(RecoveryError):
                validate_ac41_project(unsafe)

    def test_restore_rehearsal_project_must_use_isolated_prefix(self) -> None:
        self.assertEqual(
            "web-starter-ac40-test1", validate_ac40_project("web-starter-ac40-test1")
        )
        for unsafe in ("web-starter", "production", "web-starter-ac41-test"):
            with self.subTest(unsafe=unsafe), self.assertRaises(RecoveryError):
                validate_ac40_project(unsafe)

    def test_backup_output_inside_repository_is_rejected(self) -> None:
        candidate = REPO_ROOT / ".recovery-test-output-must-not-exist"
        self.assertFalse(candidate.exists())
        with self.assertRaisesRegex(RecoveryError, "outside the Git working tree"):
            ensure_external_output_directory(candidate)
        self.assertFalse(candidate.exists())

    def test_formal_report_directory_is_external_private_and_dedicated(self) -> None:
        directory = self.root / "formal-evidence"
        report, checksum = prepare_external_report_file(directory / "v2-ac41.json")
        self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        self.assertEqual(directory.resolve() / "v2-ac41.json", report)
        self.assertEqual(directory.resolve() / "v2-ac41.json.sha256", checksum)

        attachment_directory = self.root / "formal-evidence-with-attachment"
        attachment_directory.mkdir(mode=0o700)
        (attachment_directory / "notes.txt").write_text("attachment\n", encoding="utf-8")
        with self.assertRaisesRegex(RecoveryError, "dedicated and empty"):
            prepare_external_report_file(attachment_directory / "v2-ac41.json")

    def test_audit_counts_cannot_decrease_and_login_must_append(self) -> None:
        before = {
            "sys_login_log": 3,
            "sys_operation_log": 7,
            "sys_mcp_call_log": 2,
        }
        ensure_audit_not_lost(before, {**before, "sys_login_log": 4})
        with self.assertRaisesRegex(RecoveryError, "did not append"):
            ensure_audit_not_lost(before, before)
        with self.assertRaisesRegex(RecoveryError, "decreased"):
            ensure_audit_not_lost(before, {**before, "sys_login_log": 4, "sys_mcp_call_log": 1})

    def test_operational_scripts_have_help_without_docker(self) -> None:
        environment = {**os.environ, "PYTHONPYCACHEPREFIX": str(self.root / "pycache")}
        for name in (
            "recovery_backup.py",
            "recovery_restore.py",
            "rehearse_redis_loss.py",
        ):
            with self.subTest(script=name):
                result = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "scripts" / name), "--help"],
                    cwd=REPO_ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_scripts_do_not_contain_broad_volume_or_database_deletion(self) -> None:
        combined = "\n".join(
            (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
            for name in (
                "recovery_common.py",
                "recovery_backup.py",
                "recovery_restore.py",
                "rehearse_redis_loss.py",
            )
        ).lower()
        self.assertNotIn("docker compose down", combined)
        self.assertNotIn("docker volume rm", combined)
        self.assertNotIn('"flushall"', combined)
        self.assertNotIn("drop database", combined)
        self.assertNotIn("shell=true", combined)

    def test_restore_plan_performs_no_docker_call(self) -> None:
        package = self.package()
        report = self.root / "unused.json"
        environment = {**os.environ, "PYTHONPYCACHEPREFIX": str(self.root / "pycache")}
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "recovery_restore.py"),
                "--package",
                str(package),
                "--compose-project",
                "web-starter-ac40-test",
                "--confirm-project",
                "web-starter-ac40-test",
                "--target-database",
                "web_starter_restore_plan1",
                "--report-file",
                str(report),
                "--plan",
            ],
            cwd=REPO_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("PLAN", payload["status"])
        self.assertFalse(report.exists())

    def test_restore_plan_rejects_nonisolated_project_before_docker(self) -> None:
        package = self.package()
        environment = {**os.environ, "PYTHONPYCACHEPREFIX": str(self.root / "pycache")}
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "recovery_restore.py"),
                "--package",
                str(package),
                "--compose-project",
                "web-starter",
                "--confirm-project",
                "web-starter",
                "--target-database",
                "web_starter_restore_plan1",
                "--plan",
            ],
            cwd=REPO_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("web-starter-ac40-", result.stderr)

    def test_backup_requires_explicit_consistency_mode_before_docker(self) -> None:
        environment = {**os.environ, "PYTHONPYCACHEPREFIX": str(self.root / "pycache")}
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "recovery_backup.py"),
                "--compose-project",
                "web-starter-ac40-test",
                "--expected-database",
                "web_starter",
                "--release-version",
                "2.0.0-test",
                "--output-dir",
                str(self.root / "backups"),
            ],
            cwd=REPO_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("one of the arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
