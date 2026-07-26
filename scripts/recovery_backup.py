#!/usr/bin/env python3
"""Create a self-verifying Web Starter MySQL recovery package."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.recovery_common import (  # noqa: E402
    ComposeContext,
    MANIFEST_VERSION,
    REPO_ROOT,
    RecoveryError,
    collect_table_counts,
    ensure_required_schema_tables,
    ensure_external_output_directory,
    flyway_history_tsv,
    list_database_tables,
    required_tables_for_schema_version,
    row_counts_tsv,
    schema_version_from_flyway_history,
    sha256_file,
    utc_now,
    validate_database_identifier,
    write_private_json,
    write_private_text,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Create an AC-40 logical MySQL backup package. The application must be stopped "
            "unless --allow-live-source is explicitly supplied."
        )
    )
    result.add_argument("--compose-project", required=True, help="exact Docker Compose project name")
    result.add_argument(
        "--compose-file",
        action="append",
        type=Path,
        default=[],
        help="Compose file; may be repeated (defaults to compose.yaml)",
    )
    result.add_argument("--expected-database", required=True, help="database expected in MYSQL_DATABASE")
    result.add_argument("--release-version", required=True, help="immutable application/release version")
    result.add_argument("--output-dir", required=True, type=Path, help="directory outside the Git worktree")
    consistency = result.add_mutually_exclusive_group(required=True)
    consistency.add_argument(
        "--confirm-no-external-writers",
        action="store_true",
        help="confirm that every writer, not only this Compose project's app service, is stopped",
    )
    consistency.add_argument(
        "--allow-live-source",
        action="store_true",
        help=(
            "allow backup while app is running; row-count consistency becomes best effort and "
            "is not sufficient for the AC-40 drill"
        ),
    )
    return result


def _repository_state() -> tuple[str | None, bool | None]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True,
            ).stdout.strip()
        )
        return commit, dirty
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None, None


def _app_image(context: ComposeContext) -> dict[str, str | None]:
    identifier = context.container_id("app", include_stopped=True)
    if not identifier:
        return {"configuredReference": None, "imageId": None}
    payload = context.inspect_container("app", include_stopped=True)
    return {
        "configuredReference": payload.get("Config", {}).get("Image"),
        "imageId": payload.get("Image"),
    }


def _source_database(context: ComposeContext) -> str:
    value = context.exec("mysql", ["printenv", "MYSQL_DATABASE"]).decode("utf-8").strip()
    return validate_database_identifier(value, field="container MYSQL_DATABASE")


def _dump_database(context: ComposeContext, destination: Path) -> None:
    arguments = [
        "exec",
        "-T",
        "mysql",
        "sh",
        "-ec",
        'exec mysqldump -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" '
        "--single-transaction --quick --hex-blob --default-character-set=utf8mb4 "
        "--routines --events --triggers --no-tablespaces --set-gtid-purged=OFF --skip-comments",
    ]
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        context.run(arguments, stdout=stream)
    if destination.stat().st_size < 1:
        raise RecoveryError("mysqldump produced an empty SQL file")


def create_backup(args: argparse.Namespace) -> Path:
    expected_database = validate_database_identifier(args.expected_database, field="expected database")
    release_version = args.release_version.strip()
    if not release_version or any(character in release_version for character in "\r\n\t"):
        raise RecoveryError("release version must be a non-empty single-line value")
    context = ComposeContext.create(args.compose_project, args.compose_file)
    context.require_container("mysql")
    actual_database = _source_database(context)
    if actual_database != expected_database:
        raise RecoveryError(
            f"refusing backup: expected database {expected_database}, container uses {actual_database}"
        )
    app_running = context.container_id("app") is not None
    if app_running and not args.allow_live_source:
        raise RecoveryError(
            "app container is running; stop application writers before an AC-40 consistent backup, "
            "or explicitly use --allow-live-source for a best-effort operational backup"
        )

    output_directory = ensure_external_output_directory(args.output_dir)
    created_at = utc_now()
    timestamp = created_at.replace("-", "").replace(":", "").replace("Z", "Z")
    package_name = f"web-starter-backup-{timestamp}-{os.urandom(3).hex()}"
    final_package = output_directory / package_name
    if final_package.exists():
        raise RecoveryError("generated backup package path already exists")

    temporary = Path(tempfile.mkdtemp(prefix=".web-starter-backup-", dir=output_directory))
    os.chmod(temporary, 0o700)
    try:
        sql_path = temporary / "database.sql"
        _dump_database(context, sql_path)
        flyway_path = temporary / "flyway-history.tsv"
        flyway_history = flyway_history_tsv(context)
        flyway_rows = flyway_history.splitlines()[1:]
        if not flyway_rows:
            raise RecoveryError("Flyway history is empty; refusing an unverifiable backup")
        if any(row.rsplit("\t", 1)[-1] != "1" for row in flyway_rows):
            raise RecoveryError("Flyway history contains an unsuccessful migration")
        write_private_text(flyway_path, flyway_history)
        schema_version = schema_version_from_flyway_history(flyway_history)
        required_tables = required_tables_for_schema_version(schema_version)
        database_tables = ensure_required_schema_tables(
            schema_version, list_database_tables(context)
        )
        counts = collect_table_counts(context, database_tables)
        counts_path = temporary / "critical-row-counts.tsv"
        write_private_text(counts_path, row_counts_tsv(counts))

        sql_hash = sha256_file(sql_path)
        flyway_hash = sha256_file(flyway_path)
        counts_hash = sha256_file(counts_path)
        write_private_text(temporary / "database.sql.sha256", f"{sql_hash}  database.sql\n")

        git_commit, repository_dirty = _repository_state()
        manifest = {
            "manifestVersion": MANIFEST_VERSION,
            "createdAtUtc": created_at,
            "application": {
                "version": release_version,
                "image": _app_image(context),
                "repositoryCommit": git_commit,
                "repositoryDirty": repository_dirty,
            },
            "source": {
                "composeProject": context.project,
                "database": actual_database,
            },
            "databaseSchema": {
                "profile": f"web-starter-flyway-v{schema_version}",
                "flywayVersion": str(schema_version),
                "requiredTables": list(required_tables),
                "countedTables": list(database_tables),
            },
            "consistency": {
                "composeApplicationStopped": not app_running,
                "noExternalWritersConfirmed": bool(args.confirm_no_external_writers),
                "mode": (
                    "confirmed-no-writers"
                    if args.confirm_no_external_writers and not app_running
                    else "best-effort-live-source"
                ),
                "ac40Eligible": bool(args.confirm_no_external_writers and not app_running),
            },
            "artifacts": {
                "sql": {
                    "file": "database.sql",
                    "sha256": sql_hash,
                    "bytes": sql_path.stat().st_size,
                },
                "flywayHistory": {
                    "file": "flyway-history.tsv",
                    "sha256": flyway_hash,
                    "rows": len(flyway_rows),
                },
                "criticalRowCounts": {
                    "file": "critical-row-counts.tsv",
                    "sha256": counts_hash,
                    "tables": counts,
                },
            },
        }
        manifest_path = temporary / "manifest.json"
        write_private_json(manifest_path, manifest)
        write_private_text(
            temporary / "manifest.json.sha256",
            f"{sha256_file(manifest_path)}  manifest.json\n",
        )
        temporary.replace(final_package)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return final_package


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        package = create_backup(args)
    except RecoveryError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "CREATED", "package": str(package)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
