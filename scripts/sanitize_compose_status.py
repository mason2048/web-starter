#!/usr/bin/env python3
"""Write a credential-free Compose service status artifact.

Docker Compose's JSON ps output includes each container command. Production
commands can contain expanded database or Redis passwords, so release evidence
must consume only the explicit Service/State/Health template used by the
runtime runner.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


class ComposeStatusError(ValueError):
    """The input is not the fixed, credential-free Compose status format."""


ALLOWED_SERVICES = {"mysql", "redis", "app", "nginx", "mcp-public-nginx"}
ALLOWED_STATES = {"created", "dead", "exited", "paused", "removing", "restarting", "running"}
ALLOWED_HEALTH = {"", "healthy", "starting", "unhealthy"}


def sanitize(raw: str) -> dict[str, Any]:
    services: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_line in raw.splitlines():
        values = raw_line.split("|")
        if len(values) != 3:
            raise ComposeStatusError("Compose status output is not the fixed three-field format")
        service, state, health = (value.strip() for value in values)
        if (
            service not in ALLOWED_SERVICES
            or service in seen
            or state not in ALLOWED_STATES
            or health not in ALLOWED_HEALTH
            or re.search(r"[\x00-\x1f\x7f]", service + state + health)
        ):
            raise ComposeStatusError("Compose status output contains an unknown or unsafe value")
        seen.add(service)
        services.append({"service": service, "state": state, "health": health})
    return {"schemaVersion": 1, "services": sorted(services, key=lambda item: item["service"])}


def write_private(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sanitize Docker Compose release status")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        document = sanitize(args.input.read_text(encoding="utf-8"))
        write_private(args.output, document)
    except (ComposeStatusError, FileExistsError, OSError, UnicodeDecodeError) as error:
        print(f"FAIL sanitize-compose-status: {error}", file=sys.stderr)
        return 1
    print("PASS sanitize-compose-status: service, state and health only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
