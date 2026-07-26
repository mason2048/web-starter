#!/usr/bin/env python3
"""Shared, safety-focused primitives for recovery acceptance tooling.

The helpers deliberately avoid a shell on the host.  The only shell snippets
run inside the repository's MySQL/Redis containers so credentials can be read
from container environment variables instead of appearing in host process
arguments or generated files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_VERSION = 1

CRITICAL_TABLES: tuple[str, ...] = (
    "sys_user",
    "sys_role",
    "sys_permission",
    "sys_menu",
    "sys_config",
    "sys_user_role",
    "sys_role_permission",
    "sys_role_menu",
    "biz_project",
    "sec_service_account",
    "sec_access_credential",
    "sec_oauth_client",
    "sec_oauth_token_registry",
    "sec_oauth_refresh_family",
    "sec_oauth_refresh_history",
    "oauth2_authorization",
    "oauth2_authorization_consent",
    "mcp_idempotency_record",
    "sys_login_log",
    "sys_operation_log",
    "sys_mcp_call_log",
)

# Keep this map in step with append-only Flyway migrations.  A recovery tool
# built for an older schema must fail closed on a newer migration instead of
# silently producing an incomplete inventory.
TABLE_INTRODUCED_IN_SCHEMA_VERSION: Mapping[str, int] = {
    **{table: 1 for table in CRITICAL_TABLES},
    "sec_oauth_refresh_family": 3,
    "sec_oauth_refresh_history": 3,
    "mcp_idempotency_record": 5,
}
LATEST_SUPPORTED_SCHEMA_VERSION = 7
SCHEMA_PROFILE_PREFIX = "web-starter-flyway-v"

AUDIT_TABLES: tuple[str, ...] = (
    "sys_login_log",
    "sys_operation_log",
    "sys_mcp_call_log",
)

STABLE_DOMAIN_TABLES: Mapping[str, tuple[tuple[str, str], ...]] = {
    "business": (
        ("biz_project", "id"),
        ("sys_config", "id"),
    ),
    "rbac": (
        ("sys_user", "id"),
        ("sys_role", "id"),
        ("sys_permission", "id"),
        ("sys_menu", "id"),
        ("sys_user_role", "user_id, role_id"),
        ("sys_role_permission", "role_id, permission_id"),
        ("sys_role_menu", "role_id, menu_id"),
    ),
    "credential_hashes": (
        ("sec_service_account", "id"),
        ("sec_access_credential", "id"),
        ("sec_oauth_client", "id"),
        ("sec_oauth_token_registry", "id"),
        ("sec_oauth_refresh_family", "authorization_id"),
        ("sec_oauth_refresh_history", "authorization_id, generation"),
        ("oauth2_authorization", "id"),
        ("oauth2_authorization_consent", "registered_client_id, principal_name"),
    ),
}

_DATABASE_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
_AC40_PROJECT = re.compile(r"^web-starter-ac40-[a-z0-9][a-z0-9-]{0,39}$")
_AC41_PROJECT = re.compile(r"^web-starter-ac41-[a-z0-9][a-z0-9-]{0,39}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TABLE_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

_FLYWAY_HISTORY_HEADER = (
    "installed_rank\tversion\tdescription\ttype\tscript\tchecksum\tinstalled_by\t"
    "installed_on_utc\texecution_time_ms\tsuccess"
)


class RecoveryError(RuntimeError):
    """Expected validation or command failure without secret-bearing output."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_database_identifier(value: str, *, field: str = "database") -> str:
    if not _DATABASE_IDENTIFIER.fullmatch(value):
        raise RecoveryError(
            f"{field} must be a 1-64 character MySQL identifier using only letters, digits, and underscore"
        )
    return value


def validate_compose_project(value: str) -> str:
    if not _COMPOSE_PROJECT.fullmatch(value):
        raise RecoveryError("compose project name contains unsupported characters")
    return value


def validate_ac41_project(value: str) -> str:
    validate_compose_project(value)
    if not _AC41_PROJECT.fullmatch(value):
        raise RecoveryError(
            "Redis-loss rehearsal requires an isolated project named web-starter-ac41-<suffix>"
        )
    return value


def validate_ac40_project(value: str) -> str:
    validate_compose_project(value)
    if not _AC40_PROJECT.fullmatch(value):
        raise RecoveryError(
            "restore rehearsal requires an isolated project named web-starter-ac40-<suffix>"
        )
    return value


def validate_restore_target(source_database: str, target_database: str) -> str:
    source = validate_database_identifier(source_database, field="source database")
    target = validate_database_identifier(target_database, field="target database")
    expected_prefix = f"{source}_restore_"
    if target == source or not target.startswith(expected_prefix):
        raise RecoveryError(
            f"restore target must be a new database whose name starts with {expected_prefix}"
        )
    return target


def generated_restore_target(source_database: str, *, suffix: str | None = None) -> str:
    source = validate_database_identifier(source_database, field="source database")
    if suffix is None:
        suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + os.urandom(3).hex()
    if not re.fullmatch(r"[A-Za-z0-9_]+", suffix):
        raise RecoveryError("restore target suffix contains unsupported characters")
    maximum_suffix = 64 - len(source) - len("_restore_")
    if maximum_suffix < 1:
        raise RecoveryError("source database name is too long to derive a safe restore target")
    return validate_restore_target(source, f"{source}_restore_{suffix[:maximum_suffix]}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_private_text(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def write_private_json(path: Path, value: object) -> None:
    write_private_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def prepare_external_report_file(path: Path) -> tuple[Path, Path]:
    """Resolve one new external 0600 report and its new sibling checksum path."""
    expanded = path.expanduser().absolute()
    if expanded.is_symlink() or expanded.name in {"", ".", ".."}:
        raise RecoveryError("report file must be a new regular non-symbolic-link path")
    parent = expanded.parent
    if parent.is_symlink():
        raise RecoveryError("report directory must not be a symbolic link")
    resolved_parent = parent.resolve()
    repository = REPO_ROOT.resolve()
    if resolved_parent == repository or repository in resolved_parent.parents \
            or resolved_parent in repository.parents:
        raise RecoveryError("formal report directory must stay outside the Git working tree")
    if parent.exists():
        if not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
            raise RecoveryError("formal report directory must be a real 0700 directory")
        if any(parent.iterdir()):
            raise RecoveryError(
                "formal report directory must be dedicated and empty before the rehearsal"
            )
    else:
        parent.mkdir(mode=0o700, parents=True)
        parent.chmod(0o700)
    report = resolved_parent / expanded.name
    checksum = Path(str(report) + ".sha256")
    if report.exists() or report.is_symlink() or checksum.exists() or checksum.is_symlink():
        raise RecoveryError("report file or sibling checksum already exists")
    return report, checksum


def write_private_json_with_checksum(path: Path, value: object) -> tuple[Path, Path]:
    report, checksum = prepare_external_report_file(path)
    write_private_json(report, value)
    write_private_text(checksum, f"{sha256_file(report)}  {report.name}\n")
    return report, checksum


def ensure_external_output_directory(path: Path) -> Path:
    # Resolve before creating anything so a rejected path cannot leave files or
    # directories in the repository.
    resolved = path.expanduser().resolve()
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        raise RecoveryError("backup packages must be written outside the Git working tree")
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise RecoveryError("backup output path is not a directory")
    return resolved


def parse_checksum_file(path: Path, expected_name: str) -> str:
    parts = path.read_text(encoding="utf-8").strip().split()
    if len(parts) != 2 or parts[1].lstrip("*") != expected_name or not _SHA256.fullmatch(parts[0]):
        raise RecoveryError(f"invalid checksum file: {path.name}")
    return parts[0]


def safe_package_artifact(package: Path, name: object) -> Path:
    if not isinstance(name, str) or Path(name).name != name or name in {"", ".", ".."}:
        raise RecoveryError("backup manifest contains an unsafe artifact path")
    path = package / name
    if path.is_symlink() or not path.is_file():
        raise RecoveryError(f"backup artifact is missing or is not a regular file: {name}")
    if path.resolve().parent != package.resolve():
        raise RecoveryError("backup artifact resolves outside the package")
    return path


def _validated_table_names(values: Iterable[str], *, field: str) -> tuple[str, ...]:
    names = tuple(values)
    if not names:
        raise RecoveryError(f"{field} is empty")
    if len(names) != len(set(names)):
        raise RecoveryError(f"{field} contains duplicate tables")
    for name in names:
        if not isinstance(name, str) or not _TABLE_IDENTIFIER.fullmatch(name):
            raise RecoveryError(f"{field} contains an unsafe table identifier")
        if name == "flyway_schema_history":
            raise RecoveryError(f"{field} must not include Flyway history")
    return tuple(sorted(names))


def required_tables_for_schema_version(version: int) -> tuple[str, ...]:
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RecoveryError("Flyway schema version must be a positive integer")
    if version > LATEST_SUPPORTED_SCHEMA_VERSION:
        raise RecoveryError(
            f"Flyway schema version {version} is newer than this recovery tool; "
            "update its table inventory profile before taking a backup"
        )
    return tuple(
        table
        for table in CRITICAL_TABLES
        if TABLE_INTRODUCED_IN_SCHEMA_VERSION[table] <= version
    )


def schema_version_from_flyway_history(history: str) -> int:
    lines = history.splitlines()
    if not lines or lines[0] != _FLYWAY_HISTORY_HEADER:
        raise RecoveryError("flyway-history.tsv has an invalid header")
    versions: list[int] = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 10:
            raise RecoveryError("flyway-history.tsv contains an invalid row")
        if fields[-1] != "1":
            raise RecoveryError("Flyway history contains an unsuccessful migration")
        version = fields[1]
        if not version:
            continue
        if not re.fullmatch(r"[1-9][0-9]*", version):
            raise RecoveryError("Flyway history contains an unsupported schema version")
        versions.append(int(version))
    if not versions:
        raise RecoveryError("Flyway history is empty; refusing an unverifiable backup")
    latest = max(versions)
    required_tables_for_schema_version(latest)
    return latest


def parse_row_counts(path: Path) -> dict[str, int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "table_name\trow_count":
        raise RecoveryError("critical-row-counts.tsv has an invalid header")
    counts: dict[str, int] = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if (
            len(fields) != 2
            or fields[0] in counts
            or not _TABLE_IDENTIFIER.fullmatch(fields[0])
            or fields[0] == "flyway_schema_history"
        ):
            raise RecoveryError("critical-row-counts.tsv contains an invalid row")
        try:
            count = int(fields[1])
        except ValueError as error:
            raise RecoveryError("critical-row-counts.tsv contains a non-integer count") from error
        if count < 0:
            raise RecoveryError("critical-row-counts.tsv contains a negative count")
        counts[fields[0]] = count
    if not counts:
        raise RecoveryError("critical-row-counts.tsv is empty")
    return counts


def validate_backup_package(package: Path) -> tuple[dict[str, object], dict[str, int]]:
    package = package.resolve()
    if not package.is_dir():
        raise RecoveryError("backup package directory does not exist")
    manifest_path = safe_package_artifact(package, "manifest.json")
    manifest_checksum_path = safe_package_artifact(package, "manifest.json.sha256")
    declared_manifest_hash = parse_checksum_file(manifest_checksum_path, "manifest.json")
    if sha256_file(manifest_path) != declared_manifest_hash:
        raise RecoveryError("manifest.json checksum mismatch")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RecoveryError("manifest.json is not valid UTF-8 JSON") from error
    if not isinstance(manifest, dict) or manifest.get("manifestVersion") != MANIFEST_VERSION:
        raise RecoveryError("unsupported backup manifest version")
    application = manifest.get("application")
    source = manifest.get("source")
    artifacts = manifest.get("artifacts")
    if not isinstance(application, dict) or not isinstance(application.get("version"), str):
        raise RecoveryError("backup manifest has no application version")
    if not application["version"].strip():
        raise RecoveryError("backup manifest application version is empty")
    if not isinstance(source, dict) or not isinstance(source.get("database"), str):
        raise RecoveryError("backup manifest has no source database")
    validate_database_identifier(source["database"], field="manifest source database")
    if not isinstance(artifacts, dict):
        raise RecoveryError("backup manifest has no artifact catalog")
    required = {
        "sql": ("database.sql", "database.sql.sha256"),
        "flywayHistory": ("flyway-history.tsv", None),
        "criticalRowCounts": ("critical-row-counts.tsv", None),
    }
    resolved: dict[str, Path] = {}
    for key, (expected_file, checksum_file) in required.items():
        entry = artifacts.get(key)
        if not isinstance(entry, dict) or entry.get("file") != expected_file:
            raise RecoveryError(f"backup manifest has an invalid {key} artifact")
        declared_hash = entry.get("sha256")
        if not isinstance(declared_hash, str) or not _SHA256.fullmatch(declared_hash):
            raise RecoveryError(f"backup manifest has an invalid {key} checksum")
        artifact_path = safe_package_artifact(package, expected_file)
        if sha256_file(artifact_path) != declared_hash:
            raise RecoveryError(f"{expected_file} checksum mismatch")
        resolved[key] = artifact_path
        if checksum_file:
            checksum_path = safe_package_artifact(package, checksum_file)
            if parse_checksum_file(checksum_path, expected_file) != declared_hash:
                raise RecoveryError(f"{checksum_file} does not match manifest")
    if resolved["sql"].stat().st_size < 1:
        raise RecoveryError("database.sql is empty")
    if artifacts["sql"].get("bytes") != resolved["sql"].stat().st_size:
        raise RecoveryError("database.sql size does not match manifest")
    counts = parse_row_counts(resolved["criticalRowCounts"])
    if artifacts["criticalRowCounts"].get("tables") != counts:
        raise RecoveryError("critical row counts do not match manifest")
    flyway_history = resolved["flywayHistory"].read_text(encoding="utf-8")
    flyway_rows = max(0, len(flyway_history.splitlines()) - 1)
    if artifacts["flywayHistory"].get("rows") != flyway_rows:
        raise RecoveryError("Flyway row count does not match manifest")
    database_schema = manifest.get("databaseSchema")
    if database_schema is None:
        # Compatibility for packages created before schema-aware inventories.
        # Those packages were defined against the then-current complete set.
        if set(counts) != set(CRITICAL_TABLES):
            raise RecoveryError("critical-row-counts.tsv does not cover the required table set")
        return manifest, counts
    if not isinstance(database_schema, dict):
        raise RecoveryError("backup manifest has an invalid database schema inventory")
    schema_version = schema_version_from_flyway_history(flyway_history)
    expected_required = required_tables_for_schema_version(schema_version)
    if database_schema.get("flywayVersion") != str(schema_version):
        raise RecoveryError("database schema version does not match Flyway history")
    if database_schema.get("profile") != f"{SCHEMA_PROFILE_PREFIX}{schema_version}":
        raise RecoveryError("database schema profile does not match Flyway history")
    if database_schema.get("requiredTables") != list(expected_required):
        raise RecoveryError("database schema required table set does not match the Flyway profile")
    counted_tables = database_schema.get("countedTables")
    if not isinstance(counted_tables, list) or counted_tables != sorted(counts):
        raise RecoveryError("database schema counted table set does not match row counts")
    missing_required = sorted(set(expected_required) - set(counts))
    if missing_required:
        raise RecoveryError(
            "database schema inventory does not cover required tables: " + ", ".join(missing_required)
        )
    return manifest, counts


@dataclass(frozen=True)
class ComposeContext:
    project: str
    files: tuple[Path, ...]
    env_file: Path | None = None

    @classmethod
    def create(
        cls,
        project: str,
        files: Iterable[Path],
        *,
        env_file: Path | None = None,
    ) -> "ComposeContext":
        validate_compose_project(project)
        resolved_files = tuple(Path(item).resolve() for item in files)
        if not resolved_files:
            resolved_files = (REPO_ROOT / "compose.yaml",)
        for path in resolved_files:
            if not path.is_file():
                raise RecoveryError(f"Compose file does not exist: {path}")
        resolved_env_file: Path | None = None
        if env_file is not None:
            candidate = env_file.expanduser().absolute()
            try:
                metadata = candidate.lstat()
                resolved_env_file = candidate.resolve(strict=True)
            except OSError as error:
                raise RecoveryError("Compose env file does not exist") from error
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise RecoveryError("Compose env file must be a real 0600 regular file")
        return cls(project=project, files=resolved_files, env_file=resolved_env_file)

    @property
    def prefix(self) -> list[str]:
        command = ["docker", "compose"]
        if self.env_file is not None:
            command.extend(("--env-file", str(self.env_file)))
        command.extend(("--project-name", self.project))
        for path in self.files:
            command.extend(("-f", str(path)))
        return command

    def run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        stdout: BinaryIO | int | None = subprocess.PIPE,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                [*self.prefix, *arguments],
                input=input_bytes,
                stdout=stdout,
                stderr=subprocess.PIPE,
                check=True,
            )
        except FileNotFoundError as error:
            raise RecoveryError("docker command was not found") from error
        except subprocess.CalledProcessError as error:
            detail = error.stderr.decode("utf-8", errors="replace").strip()
            if len(detail) > 1000:
                detail = detail[-1000:]
            raise RecoveryError(f"Docker Compose command failed: {detail or 'no diagnostic output'}") from error

    def container_id(self, service: str, *, include_stopped: bool = False) -> str | None:
        arguments = ["ps"]
        if include_stopped:
            arguments.append("--all")
        arguments.extend(("--quiet", service))
        output = self.run(arguments).stdout.decode("utf-8").strip().splitlines()
        identifiers = [item.strip() for item in output if item.strip()]
        if len(identifiers) > 1:
            raise RecoveryError(f"expected one {service} container, found {len(identifiers)}")
        return identifiers[0] if identifiers else None

    def require_container(self, service: str, *, include_stopped: bool = False) -> str:
        identifier = self.container_id(service, include_stopped=include_stopped)
        if not identifier:
            state = "created" if include_stopped else "running"
            raise RecoveryError(f"Compose project {self.project} has no {state} {service} container")
        try:
            inspected = subprocess.run(
                ["docker", "inspect", identifier],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as error:
            raise RecoveryError(f"cannot inspect Compose {service} container") from error
        payload = json.loads(inspected.stdout)[0]
        labels = payload.get("Config", {}).get("Labels", {}) or {}
        if labels.get("com.docker.compose.project") != self.project:
            raise RecoveryError(f"{service} container does not belong to the requested Compose project")
        if labels.get("com.docker.compose.service") != service:
            raise RecoveryError(f"container label does not identify Compose service {service}")
        return identifier

    def inspect_container(self, service: str, *, include_stopped: bool = False) -> dict[str, object]:
        identifier = self.require_container(service, include_stopped=include_stopped)
        try:
            output = subprocess.run(
                ["docker", "inspect", identifier],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
        except (FileNotFoundError, subprocess.CalledProcessError) as error:
            raise RecoveryError(f"cannot inspect Compose {service} container") from error
        return json.loads(output)[0]

    def exec(self, service: str, arguments: Sequence[str], *, input_bytes: bytes | None = None) -> bytes:
        return self.run(["exec", "-T", service, *arguments], input_bytes=input_bytes).stdout

    def assert_isolated_named_volume(self, service: str, destination: str) -> str:
        return self.isolated_named_volume_evidence(service, destination)["name"]

    def isolated_named_volume_evidence(
        self,
        service: str,
        destination: str,
        *,
        expected_compose_volume: str | None = None,
    ) -> dict[str, object]:
        payload = self.inspect_container(service)
        mounts = [item for item in payload.get("Mounts", []) if item.get("Destination") == destination]
        if len(mounts) != 1 or mounts[0].get("Type") != "volume":
            raise RecoveryError(
                f"AC-41 requires {service} {destination} to use one project-owned named volume"
            )
        name = mounts[0].get("Name")
        if not isinstance(name, str) or not name:
            raise RecoveryError(f"cannot resolve {service} volume name")
        try:
            output = subprocess.run(
                ["docker", "volume", "inspect", name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
        except (FileNotFoundError, subprocess.CalledProcessError) as error:
            raise RecoveryError(f"cannot inspect {service} volume") from error
        volume = json.loads(output)[0]
        labels = volume.get("Labels", {}) or {}
        if labels.get("com.docker.compose.project") != self.project:
            raise RecoveryError(f"{service} volume is not owned by isolated project {self.project}")
        compose_volume = labels.get("com.docker.compose.volume")
        if not isinstance(compose_volume, str) or not compose_volume:
            raise RecoveryError(f"{service} volume has no Compose volume ownership label")
        if expected_compose_volume is not None and compose_volume != expected_compose_volume:
            raise RecoveryError(
                f"{service} volume does not match the resolved Compose volume configuration"
            )
        driver = volume.get("Driver")
        if not isinstance(driver, str) or not driver:
            raise RecoveryError(f"{service} volume has no storage driver identity")
        return {
            "name": name,
            "destination": destination,
            "projectLabel": self.project,
            "composeVolumeLabel": compose_volume,
            "driver": driver,
            "external": False,
        }

    def mysql_query(self, sql: str, *, root: bool = False, database: str | None = None) -> bytes:
        if root:
            arguments = [
                "sh",
                "-ec",
                'if [ "$#" -eq 1 ]; then exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$1" '
                '--batch --raw --binary-as-hex --skip-column-names; '
                'else exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" --batch --raw --binary-as-hex '
                '--skip-column-names; fi',
                "web-starter-mysql",
            ]
            if database is not None:
                validate_database_identifier(database)
                arguments.append(database)
        else:
            if database is not None:
                raise RecoveryError("application database queries use the container MYSQL_DATABASE")
            arguments = [
                "sh",
                "-ec",
                'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" '
                "--batch --raw --binary-as-hex --skip-column-names",
            ]
        return self.exec("mysql", arguments, input_bytes=sql.encode("utf-8"))

    def mysql_query_digest(self, sql: str) -> str:
        command = [
            *self.prefix,
            "exec",
            "-T",
            "mysql",
            "sh",
            "-ec",
            'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" '
            "--batch --raw --binary-as-hex --skip-column-names",
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as error:
            raise RecoveryError("docker command was not found") from error
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(sql.encode("utf-8"))
        process.stdin.close()
        digest = hashlib.sha256()
        for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
            digest.update(chunk)
        stderr = process.stderr.read() if process.stderr is not None else b""
        return_code = process.wait()
        if return_code != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            raise RecoveryError(f"MySQL fingerprint query failed: {detail[-1000:]}")
        return digest.hexdigest()


def flyway_history_tsv(context: ComposeContext, *, root: bool = False, database: str | None = None) -> str:
    header = _FLYWAY_HISTORY_HEADER + "\n"
    query = """
SELECT installed_rank,
       COALESCE(version, ''),
       description,
       type,
       script,
       COALESCE(CAST(checksum AS CHAR), ''),
       installed_by,
       DATE_FORMAT(CONVERT_TZ(installed_on, @@session.time_zone, '+00:00'), '%Y-%m-%dT%H:%i:%s.%fZ'),
       execution_time,
       success
  FROM flyway_schema_history
 ORDER BY installed_rank;
"""
    body = context.mysql_query(query, root=root, database=database).decode("utf-8")
    return header + body


def list_database_tables(
    context: ComposeContext, *, root: bool = False, database: str | None = None
) -> tuple[str, ...]:
    query = """
SELECT table_name
  FROM information_schema.tables
 WHERE table_schema = DATABASE()
   AND table_type = 'BASE TABLE'
   AND table_name <> 'flyway_schema_history'
 ORDER BY table_name;
"""
    body = context.mysql_query(query, root=root, database=database).decode("utf-8")
    return _validated_table_names(body.splitlines(), field="database table inventory")


def ensure_required_schema_tables(version: int, actual_tables: Iterable[str]) -> tuple[str, ...]:
    actual = _validated_table_names(actual_tables, field="database table inventory")
    missing = sorted(set(required_tables_for_schema_version(version)) - set(actual))
    if missing:
        raise RecoveryError(
            f"Flyway v{version} database is missing required tables: " + ", ".join(missing)
        )
    return actual


def ensure_table_inventory_matches(
    expected_tables: Iterable[str], actual_tables: Iterable[str]
) -> None:
    expected = _validated_table_names(expected_tables, field="manifest table inventory")
    actual = _validated_table_names(actual_tables, field="restored database table inventory")
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing:
        raise RecoveryError("restored database is missing tables from the manifest: " + ", ".join(missing))
    if unexpected:
        raise RecoveryError(
            "restored database contains unexpected tables absent from the manifest: "
            + ", ".join(unexpected)
        )


def collect_table_counts(
    context: ComposeContext,
    tables: Iterable[str],
    *,
    root: bool = False,
    database: str | None = None,
) -> dict[str, int]:
    names = _validated_table_names(tables, field="row-count table inventory")
    counts: dict[str, int] = {}
    for table in names:
        output = context.mysql_query(
            f"SELECT COUNT(*) FROM `{table}`;\n", root=root, database=database
        ).decode("ascii").strip()
        try:
            counts[table] = int(output)
        except ValueError as error:
            raise RecoveryError(f"could not read row count for {table}") from error
        if counts[table] < 0:
            raise RecoveryError(f"could not read row count for {table}")
    return counts


def collect_critical_counts(
    context: ComposeContext, *, root: bool = False, database: str | None = None
) -> dict[str, int]:
    """Legacy helper retained for callers that explicitly need the V7 core set."""

    return collect_table_counts(context, CRITICAL_TABLES, root=root, database=database)


def row_counts_tsv(counts: Mapping[str, int]) -> str:
    tables = _validated_table_names(counts, field="row-count table inventory")
    for table in tables:
        count = counts[table]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise RecoveryError(f"row count for {table} is invalid")
    return "table_name\trow_count\n" + "".join(
        f"{table}\t{counts[table]}\n" for table in tables
    )


def audit_counts(context: ComposeContext) -> dict[str, int]:
    result: dict[str, int] = {}
    for table in AUDIT_TABLES:
        output = context.mysql_query(f"SELECT COUNT(*) FROM `{table}`;\n").decode("ascii").strip()
        result[table] = int(output)
    return result


def stable_domain_fingerprints(context: ComposeContext) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    for domain, tables in STABLE_DOMAIN_TABLES.items():
        statements: list[str] = []
        for table, order_by in tables:
            statements.append(f"SELECT 'TABLE:{table}';")
            statements.append(f"SELECT * FROM `{table}` ORDER BY {order_by};")
        fingerprints[domain] = context.mysql_query_digest("\n".join(statements) + "\n")
    return fingerprints


def ensure_audit_not_lost(before: Mapping[str, int], after: Mapping[str, int]) -> None:
    for table in AUDIT_TABLES:
        if after.get(table, -1) < before.get(table, 0):
            raise RecoveryError(f"audit row count decreased for {table}")
    if after.get("sys_login_log", 0) <= before.get("sys_login_log", 0):
        raise RecoveryError("re-login did not append a login audit row")
