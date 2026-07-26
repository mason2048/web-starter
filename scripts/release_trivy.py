#!/usr/bin/env python3
"""Run a release Trivy scan without trusting repository-local auto configuration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


IMAGE_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


class ReleaseTrivyError(RuntimeError):
    """A release scan precondition or output validation failed."""


def _regular_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file():
        raise ReleaseTrivyError(f"{label} must be a regular non-symlink file")
    return resolved


def _directory(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_dir():
        raise ReleaseTrivyError(f"{label} must be a non-symlink directory")
    return resolved


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def run_scan(
    *,
    trivy: Path,
    repository_root: Path,
    config: Path,
    secret_config: Path,
    ignore_file: Path,
    work_root: Path,
    docker_config: Path,
    scanner: str,
    reference: str,
    output: Path,
) -> None:
    executable = _regular_file(trivy, "Trivy executable")
    repository = _directory(repository_root, "repository root")
    controlled_config = _regular_file(config, "release Trivy config")
    controlled_secret_config = _regular_file(secret_config, "release Trivy secret config")
    controlled_ignore = _regular_file(ignore_file, "release Trivy ignore file")
    temporary_root = _directory(work_root, "release Trivy work root")
    docker_credentials = _directory(docker_config, "Docker config directory")

    for path, label in (
        (controlled_config, "release Trivy config"),
        (controlled_secret_config, "release Trivy secret config"),
        (controlled_ignore, "release Trivy ignore file"),
    ):
        if not _inside(path, repository):
            raise ReleaseTrivyError(f"{label} must be tracked under the repository root")

    if _inside(temporary_root, repository):
        raise ReleaseTrivyError("release Trivy work root must be outside the repository")
    if scanner not in {"vuln", "secret"}:
        raise ReleaseTrivyError("scanner must be vuln or secret")
    if IMAGE_REFERENCE.fullmatch(reference) is None:
        raise ReleaseTrivyError("release image reference must be digest-bound")

    output_parent = _directory(output.parent, "scan output directory")
    resolved_output = output_parent / output.name
    if output.is_symlink() or resolved_output.exists():
        raise ReleaseTrivyError("scan output must not already exist")

    with tempfile.TemporaryDirectory(prefix="web-starter-trivy-", dir=temporary_root) as directory:
        isolated = Path(directory).resolve()
        isolated_home = isolated / "home"
        isolated_cache = isolated / "cache"
        isolated_home.mkdir(mode=0o700)
        isolated_cache.mkdir(mode=0o700)

        command = [
            str(executable),
            "--config",
            str(controlled_config),
            "--cache-dir",
            str(isolated_cache),
            "image",
            "--quiet",
            "--image-src",
            "remote",
            "--ignorefile",
            str(controlled_ignore),
            "--scanners",
            scanner,
            "--format",
            "json",
            "--output",
            str(resolved_output),
        ]
        if scanner == "secret":
            command.extend(
                [
                    "--secret-config",
                    str(controlled_secret_config),
                    "--image-config-scanners",
                    "secret",
                ]
            )
        command.append(reference)

        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("TRIVY_")
        }
        environment["HOME"] = str(isolated_home)
        environment["DOCKER_CONFIG"] = str(docker_credentials)

        completed = subprocess.run(command, cwd=isolated, env=environment, check=False)
        if completed.returncode != 0:
            raise ReleaseTrivyError(f"Trivy {scanner} scan failed with exit code {completed.returncode}")

    if resolved_output.is_symlink() or not resolved_output.is_file():
        raise ReleaseTrivyError("Trivy did not create a regular JSON report")
    try:
        document = json.loads(resolved_output.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ReleaseTrivyError("Trivy created an invalid JSON report") from exception
    if not isinstance(document, dict):
        raise ReleaseTrivyError("Trivy report root must be a JSON object")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--secret-config", required=True, type=Path)
    parser.add_argument("--ignore-file", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--docker-config", required=True, type=Path)
    parser.add_argument("--scanner", required=True, choices=("vuln", "secret"))
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        run_scan(
            trivy=args.trivy,
            repository_root=args.repository_root,
            config=args.config,
            secret_config=args.secret_config,
            ignore_file=args.ignore_file,
            work_root=args.work_root,
            docker_config=args.docker_config,
            scanner=args.scanner,
            reference=args.reference,
            output=args.output,
        )
    except ReleaseTrivyError as exception:
        print(f"FAIL release-trivy: {exception}", file=sys.stderr)
        return 1
    print(f"PASS release-trivy: isolated digest-bound {args.scanner} report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
