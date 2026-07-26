#!/usr/bin/env python3
"""Restore a verified Web Starter package into a newly created MySQL database."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.recovery_common import (  # noqa: E402
    ComposeContext,
    RecoveryError,
    collect_table_counts,
    ensure_table_inventory_matches,
    flyway_history_tsv,
    generated_restore_target,
    list_database_tables,
    safe_package_artifact,
    utc_now,
    validate_ac40_project,
    validate_backup_package,
    validate_database_identifier,
    validate_restore_target,
    write_private_json,
    write_private_text,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify and restore an AC-40 package. Existing databases are never overwritten or dropped."
        )
    )
    result.add_argument("--package", required=True, type=Path, help="backup package directory")
    result.add_argument("--compose-project", required=True, help="exact Docker Compose project name")
    result.add_argument("--confirm-project", required=True, help="must exactly match --compose-project")
    result.add_argument(
        "--compose-file",
        action="append",
        type=Path,
        default=[],
        help="Compose file; may be repeated (defaults to compose.yaml)",
    )
    result.add_argument(
        "--target-database",
        help="new <source>_restore_<suffix> database; generated when omitted",
    )
    result.add_argument(
        "--report-file",
        type=Path,
        help="new JSON evidence file; required for a real restore",
    )
    result.add_argument(
        "--runtime-override-file",
        type=Path,
        help="optional new Compose override that points app at the restored database",
    )
    result.add_argument(
        "--plan",
        action="store_true",
        help="validate the package and target name without connecting to Docker or creating a database",
    )
    return result


def _database_exists(context: ComposeContext, target: str) -> bool:
    output = context.mysql_query(
        f"SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = '{target}';\n",
        root=True,
    ).decode("ascii").strip()
    return output != "0"


def _create_database(context: ComposeContext, target: str) -> None:
    context.mysql_query(
        f"CREATE DATABASE `{target}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\n",
        root=True,
    )


def _create_scoped_restore_user(context: ComposeContext, target: str) -> tuple[str, str]:
    username = "ws_restore_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(32)
    option_path = f"/tmp/{username}.cnf"
    created = False
    try:
        context.mysql_query(
            f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{password}';\n", root=True
        )
        created = True
        context.mysql_query(
            f"GRANT ALL PRIVILEGES ON `{target}`.* TO '{username}'@'localhost';\n", root=True
        )
    except Exception:
        if created:
            context.mysql_query(f"DROP USER IF EXISTS '{username}'@'localhost';\n", root=True)
        raise
    option_content = f"[client]\nuser={username}\npassword={password}\nhost=localhost\n"
    try:
        context.exec(
            "mysql",
            [
                "sh",
                "-ec",
                'umask 077; test ! -e "$1"; cat > "$1"; chmod 600 "$1"',
                "web-starter-restore-option",
                option_path,
            ],
            input_bytes=option_content.encode("utf-8"),
        )
    except Exception:
        context.mysql_query(f"DROP USER IF EXISTS '{username}'@'localhost';\n", root=True)
        raise
    return username, option_path


def _cleanup_scoped_restore_user(
    context: ComposeContext, username: str, option_path: str
) -> None:
    option_error: Exception | None = None
    try:
        context.exec(
            "mysql",
            [
                "sh",
                "-ec",
                'case "$1" in /tmp/ws_restore_*.cnf) rm -f -- "$1";; *) exit 64;; esac',
                "web-starter-restore-cleanup",
                option_path,
            ],
        )
    except Exception as error:  # continue so the database account is still removed
        option_error = error
    context.mysql_query(f"DROP USER IF EXISTS '{username}'@'localhost';\n", root=True)
    if option_error is not None:
        raise RecoveryError("temporary restore option file could not be removed") from option_error


def _import_sql(context: ComposeContext, target: str, sql_path: Path, option_path: str) -> None:
    command = [
        *context.prefix,
        "exec",
        "-T",
        "mysql",
        "sh",
        "-ec",
        'exec mysql --defaults-extra-file="$1" "$2"',
        "web-starter-restore",
        option_path,
        target,
    ]
    try:
        with sql_path.open("rb") as stream:
            subprocess.run(
                command,
                stdin=stream,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
            )
    except FileNotFoundError as error:
        raise RecoveryError("docker command was not found") from error
    except subprocess.CalledProcessError as error:
        raise RecoveryError(
            "SQL import failed; the newly created target database was left in place for "
            "authorized inspection (raw SQL diagnostics were not echoed to avoid data disclosure)"
        ) from error


def _grant_app_access_to_rehearsal_database(context: ComposeContext, target: str) -> None:
    username = context.exec("mysql", ["printenv", "MYSQL_USER"]).decode("utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", username):
        raise RecoveryError("container MYSQL_USER cannot be safely granted restore-database access")
    hosts = context.mysql_query(
        f"SELECT host FROM mysql.user WHERE user = '{username}' ORDER BY host;\n", root=True
    ).decode("utf-8").splitlines()
    if not hosts:
        raise RecoveryError("container MYSQL_USER account was not found")
    for host in hosts:
        if not re.fullmatch(r"[A-Za-z0-9_.:%-]{1,255}", host):
            raise RecoveryError("MYSQL_USER host contains unsupported characters")
        context.mysql_query(
            f"GRANT ALL PRIVILEGES ON `{target}`.* TO '{username}'@'{host}';\n", root=True
        )


def _write_runtime_override(path: Path, target: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    jdbc = (
        f"jdbc:mysql://mysql:3306/{target}?useUnicode=true&characterEncoding=utf8&"
        "preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true&"
        "allowPublicKeyRetrieval=true&useSSL=false"
    )
    content = (
        "# Generated by scripts/recovery_restore.py for an isolated recovery drill.\n"
        "# Remove this override from the Compose command to point app back at its source database.\n"
        "services:\n"
        "  app:\n"
        "    environment:\n"
        f"      WEB_STARTER_DB_URL: \"{jdbc}\"\n"
    )
    write_private_text(path, content)


def _validate_output_path(path: Path, package: Path, *, label: str) -> Path:
    resolved = path.expanduser().resolve()
    package = package.resolve()
    if resolved == package or package in resolved.parents:
        raise RecoveryError(f"{label} must not modify the immutable backup package")
    return resolved


def _container_database(context: ComposeContext) -> str:
    value = context.exec("mysql", ["printenv", "MYSQL_DATABASE"]).decode("utf-8").strip()
    return validate_database_identifier(value, field="container MYSQL_DATABASE")


def restore(args: argparse.Namespace) -> dict[str, object]:
    manifest, expected_counts = validate_backup_package(args.package)
    source = manifest["source"]["database"]
    target = args.target_database or generated_restore_target(source)
    target = validate_restore_target(source, target)
    project = validate_ac40_project(args.compose_project)
    if args.confirm_project != project:
        raise RecoveryError("--confirm-project must exactly match --compose-project")

    plan = {
        "status": "PLAN" if args.plan else "RESTORED_DATABASE_VERIFIED",
        "sourceDatabase": source,
        "targetDatabase": target,
        "composeProject": project,
        "package": str(args.package.resolve()),
        "applicationVersion": manifest["application"]["version"],
        "backupConsistency": manifest.get("consistency"),
        "existingDatabaseOverwriteAllowed": False,
        "runtimeAcceptance": "NOT_RUN",
    }
    if args.plan:
        return plan
    if args.report_file is None:
        raise RecoveryError("--report-file is required for a real restore")
    package = args.package.resolve()
    report_file = _validate_output_path(args.report_file, package, label="report file")
    runtime_override_file = (
        _validate_output_path(args.runtime_override_file, package, label="runtime override file")
        if args.runtime_override_file is not None
        else None
    )
    if report_file.exists():
        raise RecoveryError("report file already exists")
    if runtime_override_file is not None and runtime_override_file.exists():
        raise RecoveryError("runtime override file already exists")
    if runtime_override_file is not None and runtime_override_file == report_file:
        raise RecoveryError("report and runtime override files must be different")

    context = ComposeContext.create(project, args.compose_file)
    context.require_container("mysql")
    mysql_volume = context.assert_isolated_named_volume("mysql", "/var/lib/mysql")
    container_database = _container_database(context)
    if container_database != source:
        raise RecoveryError(
            f"isolated target stack uses {container_database}, but package source is {source}"
        )
    if _database_exists(context, target):
        raise RecoveryError(f"target database already exists; refusing to overwrite: {target}")
    _create_database(context, target)
    restore_user, option_path = _create_scoped_restore_user(context, target)
    import_error: Exception | None = None
    try:
        _import_sql(context, target, safe_package_artifact(package, "database.sql"), option_path)
    except Exception as error:
        import_error = error
    cleanup_error: Exception | None = None
    try:
        _cleanup_scoped_restore_user(context, restore_user, option_path)
    except Exception as error:
        cleanup_error = error
    if import_error is not None:
        if cleanup_error is not None:
            raise RecoveryError(
                "SQL import failed and temporary restore credential cleanup also failed; "
                "the isolated target stack requires operator inspection"
            ) from import_error
        raise import_error
    if cleanup_error is not None:
        raise cleanup_error

    restored_tables = list_database_tables(context, root=True, database=target)
    ensure_table_inventory_matches(expected_counts, restored_tables)
    restored_counts = collect_table_counts(
        context, expected_counts, root=True, database=target
    )
    if restored_counts != expected_counts:
        raise RecoveryError(
            "restored critical row counts do not match the package; target database was left for inspection"
        )
    expected_flyway = safe_package_artifact(
        package, "flyway-history.tsv"
    ).read_text(encoding="utf-8")
    restored_flyway = flyway_history_tsv(context, root=True, database=target)
    if restored_flyway != expected_flyway:
        raise RecoveryError(
            "restored Flyway history does not match the package; target database was left for inspection"
        )

    plan.update(
        {
            "verifiedAtUtc": utc_now(),
            "criticalRowCounts": restored_counts,
            "flywayHistory": "MATCH",
            "sqlChecksum": manifest["artifacts"]["sql"]["sha256"],
            "isolation": {
                "mysqlNamedVolume": mysql_volume,
                "volumeDeletionPerformed": False,
            },
            "nextRequiredEvidence": [
                "real Web login against restored database",
                "Project CRUD transaction and persisted audit",
                "permission-denied HTTP 403",
                "OAuth token flow",
                "official MCP SDK tool call",
            ],
        }
    )
    if runtime_override_file is not None:
        _grant_app_access_to_rehearsal_database(context, target)
        _write_runtime_override(runtime_override_file, target)
        plan["runtimeOverrideFile"] = str(runtime_override_file)
    report_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_private_json(report_file, plan)
    return plan


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = restore(args)
    except RecoveryError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
