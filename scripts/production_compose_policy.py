#!/usr/bin/env python3
"""Fail-closed policy checks for the standalone production Compose model.

The script consumes JSON emitted by ``docker compose config --format json`` so
it evaluates the fully interpolated deployment model, not only YAML text. It
uses the standard library and never starts or mutates a container stack.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import posixpath
import re
import sys
from typing import Any


IMMUTABLE_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
MANAGEMENT_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
REQUIRED_SERVICES = {"mysql", "redis", "app", "nginx", "mcp-public-nginx"}
HARDENED_SERVICES = ("app", "nginx", "mcp-public-nginx")
ALLOWED_TOP_LEVEL_KEYS = {"name", "services", "networks", "volumes"}
ALLOWED_SERVICE_KEYS = {
    "mysql": {
        "command", "entrypoint", "environment", "healthcheck", "image", "networks",
        "restart", "security_opt", "volumes",
    },
    "redis": {
        "command", "entrypoint", "environment", "healthcheck", "image", "networks",
        "restart", "security_opt", "volumes",
    },
    "app": {
        "cap_drop", "command", "depends_on", "deploy", "entrypoint", "environment",
        "expose", "healthcheck", "image", "init", "networks", "read_only", "restart",
        "security_opt", "stop_grace_period", "tmpfs", "user",
    },
    "nginx": {
        "cap_drop", "command", "depends_on", "deploy", "entrypoint", "healthcheck",
        "image", "init", "networks", "ports", "read_only", "restart", "security_opt",
        "tmpfs", "user",
    },
    "mcp-public-nginx": {
        "cap_drop", "command", "depends_on", "deploy", "entrypoint", "healthcheck",
        "image", "init", "networks", "ports", "read_only", "restart", "security_opt",
        "tmpfs", "user", "volumes",
    },
}
ALLOWED_ENVIRONMENT_KEYS = {
    "mysql": {"MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD", "TZ"},
    "redis": {"WEB_STARTER_REDIS_PASSWORD", "REDISCLI_AUTH", "TZ"},
    "app": {
        "WEB_STARTER_RUNTIME_MODE", "WEB_STARTER_DB_URL", "WEB_STARTER_DB_USERNAME",
        "WEB_STARTER_DB_PASSWORD", "WEB_STARTER_DB_POOL_MAX_SIZE",
        "WEB_STARTER_DB_POOL_MIN_IDLE", "WEB_STARTER_DB_CONNECTION_TIMEOUT_MS",
        "WEB_STARTER_DB_VALIDATION_TIMEOUT_MS", "WEB_STARTER_REDIS_HOST",
        "WEB_STARTER_REDIS_PORT", "WEB_STARTER_REDIS_PASSWORD",
        "WEB_STARTER_REDIS_DATABASE", "WEB_STARTER_SESSION_TIMEOUT",
        "WEB_STARTER_SHUTDOWN_PHASE_TIMEOUT",
        "WEB_STARTER_TOKEN_PEPPER", "WEB_STARTER_CREDENTIAL_PEPPER",
        "WEB_STARTER_CREDENTIAL_PEPPER_ACTIVE_VERSION",
        "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING",
        "WEB_STARTER_CREDENTIAL_PEPPER_RETIRING_VERSION",
        "WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME", "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD",
        "WEB_STARTER_BOOTSTRAP_ADMIN_DISPLAY_NAME", "WEB_STARTER_OAUTH_ISSUER",
        "WEB_STARTER_OAUTH_RESOURCE_AUDIENCE", "WEB_STARTER_OAUTH_ACCESS_TOKEN_TTL",
        "WEB_STARTER_OAUTH_REFRESH_TOKEN_TTL", "WEB_STARTER_OAUTH_CLIENT_SECRET_OVERLAP",
        "WEB_STARTER_OAUTH_CLIENT_SECRET_MAX_OVERLAP",
        "WEB_STARTER_OAUTH_DEVELOPMENT_KEYS_ALLOWED", "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY",
        "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY", "WEB_STARTER_OAUTH_RSA_JWK_SET",
        "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID", "WEB_STARTER_INTERNAL_TOKENS_ENABLED",
        "WEB_STARTER_COOKIE_SECURE", "WEB_STARTER_LOGIN_RATE_LIMIT_ENABLED",
        "WEB_STARTER_LOGIN_RATE_LIMIT_MAX_FAILURES_PER_IDENTITY",
        "WEB_STARTER_LOGIN_RATE_LIMIT_MAX_FAILURES_PER_PAIR",
        "WEB_STARTER_LOGIN_RATE_LIMIT_WINDOW", "WEB_STARTER_LOGIN_RATE_LIMIT_INITIAL_BACKOFF",
        "WEB_STARTER_LOGIN_RATE_LIMIT_MAX_BACKOFF", "WEB_STARTER_MCP_ALLOWED_HOSTS",
        "WEB_STARTER_MCP_ALLOWED_ORIGINS", "WEB_STARTER_MCP_IDEMPOTENCY_TTL",
        "WEB_STARTER_MCP_IDEMPOTENCY_CLEANUP_INTERVAL", "WEB_STARTER_MCP_SESSION_ENABLED",
        "WEB_STARTER_MCP_SESSION_IDLE_TTL", "WEB_STARTER_MCP_SESSION_ABSOLUTE_TTL",
        "WEB_STARTER_MCP_SESSION_MAX_PER_SUBJECT",
        "WEB_STARTER_MCP_SESSION_RESERVATION_TTL", "WEB_STARTER_MCP_RATE_LIMIT_ENABLED",
        "WEB_STARTER_MCP_RATE_LIMIT_WINDOW", "WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_SUBJECT",
        "WEB_STARTER_MCP_RATE_LIMIT_MAX_PER_CLIENT", "WEB_STARTER_MCP_RATE_LIMIT_MAX_READ",
        "WEB_STARTER_MCP_RATE_LIMIT_MAX_WRITE", "WEB_STARTER_MCP_RATE_LIMIT_MAX_DESTRUCTIVE",
        "WEB_STARTER_MCP_RATE_LIMIT_MAX_PROTOCOL", "WEB_STARTER_SERVER_PORT",
        "WEB_STARTER_MANAGEMENT_PORT", "WEB_STARTER_MANAGEMENT_BIND_ADDRESS",
        "WEB_STARTER_MANAGEMENT_USERNAME", "WEB_STARTER_MANAGEMENT_PASSWORD",
        "WEB_STARTER_LOG_FORMAT", "WEB_STARTER_LOG_LEVEL", "WEB_STARTER_GIT_COMMIT", "TZ",
    },
}
ALLOWED_SECURITY_OPTIONS = {"no-new-privileges:true"}
EXPECTED_SERVICE_NETWORKS = {
    "mysql": {"data"},
    "redis": {"data"},
    "app": {"app", "data"},
    "nginx": {"app"},
    "mcp-public-nginx": {"app"},
}
ALLOWED_MOUNTS = {
    "mysql": {
        "/var/lib/mysql": {
            "type": "volume",
            "source": "mysql-data",
            "read_only": False,
        },
    },
    "redis": {
        "/data": {
            "type": "volume",
            "source": "redis-data",
            "read_only": False,
        },
    },
    "mcp-public-nginx": {
        "/etc/nginx/tls/fullchain.pem": {"type": "bind", "read_only": True},
        "/etc/nginx/tls/privkey.pem": {"type": "bind", "read_only": True},
    },
}
EXPECTED_COMMANDS = {
    "mysql": [
        "--character-set-server=utf8mb4",
        "--collation-server=utf8mb4_0900_ai_ci",
        "--default-time-zone=+08:00",
    ],
    "app": None,
    "nginx": None,
    "mcp-public-nginx": [
        "nginx",
        "-c",
        "/etc/nginx/nginx-public.conf",
        "-g",
        "daemon off;",
    ],
}
EXPECTED_HEALTHCHECK_TESTS = {
    "mysql": [
        "CMD-SHELL",
        'mysqladmin ping -h 127.0.0.1 -uroot --password="$${MYSQL_ROOT_PASSWORD}" --silent',
    ],
    "redis": ["CMD", "redis-cli", "ping"],
    "app": [
        "CMD",
        "curl",
        "-fsS",
        "http://127.0.0.1:8081/actuator/health/readiness",
    ],
    "nginx": [
        "CMD",
        "wget",
        "-q",
        "-O",
        "/dev/null",
        "http://127.0.0.1:8080/actuator/health/readiness",
    ],
    "mcp-public-nginx": [
        "CMD",
        "wget",
        "-q",
        "-O",
        "/dev/null",
        "http://127.0.0.1:8081/healthz",
    ],
}
EXPECTED_APP_HEALTHCHECK_TIMING = {
    "interval": "20s",
    "timeout": "5s",
    "retries": 5,
    "start_period": "40s",
    "start_interval": "2s",
}
EXPECTED_APP_SHUTDOWN_PHASE_TIMEOUT = "10s"
SHELL_EXECUTABLES = {"sh", "/bin/sh", "ash", "/bin/ash", "bash", "/bin/bash", "dash", "/bin/dash"}
NAMESPACE_KEYS = (
    "network_mode",
    "ipc",
    "pid",
    "userns_mode",
    "userns",
    "cgroup",
    "cgroup_parent",
    "uts",
)


def _positive(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def _tmpfs_entries(service: dict[str, Any]) -> tuple[list[tuple[str, str]], bool]:
    entries: list[tuple[str, str]] = []
    raw = service.get("tmpfs", [])
    if raw is None:
        return entries, True
    if not isinstance(raw, list):
        return entries, False
    valid = True
    for entry in raw:
        if isinstance(entry, str):
            target, _, options = entry.partition(":")
            entries.append((target, options))
        else:
            valid = False
    return entries, valid


def _volume_is_read_only(volume: Any) -> bool:
    if isinstance(volume, str):
        return volume.endswith(":ro") or ":ro," in volume
    if isinstance(volume, dict):
        return volume.get("read_only") is True
    return False


def _volume_details(volume: Any) -> tuple[str, str, str, bool]:
    if isinstance(volume, dict):
        return (
            str(volume.get("type", "")),
            str(volume.get("source", "")),
            str(volume.get("target", "")),
            _volume_is_read_only(volume),
        )
    if isinstance(volume, str):
        parts = volume.split(":")
        if len(parts) == 1:
            return ("volume", "", parts[0], False)
        source, target = parts[:2]
        mount_type = "bind" if source.startswith(("/", ".")) else "volume"
        return (mount_type, source, target, _volume_is_read_only(volume))
    return ("", "", "", False)


def _list_or_empty(value: Any) -> tuple[list[Any], bool]:
    if value is None:
        return [], True
    if isinstance(value, list):
        return value, True
    return [], False


def _network_names(service: dict[str, Any]) -> tuple[set[str], bool]:
    raw = service.get("networks")
    if not isinstance(raw, dict):
        return set(), False
    valid = all(value is None or value == {} for value in raw.values())
    return {str(name) for name in raw}, valid


def _valid_published_port(value: Any) -> bool:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def _valid_public_bind(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    except ValueError:
        return False
    return True


def _positive_size(value: str) -> bool:
    match = re.fullmatch(r"([0-9]+)([bkmgtep]?)", value.strip().lower())
    return bool(match and int(match.group(1)) > 0)


def _tmpfs_options(options: str) -> tuple[dict[str, str | None], bool]:
    parsed: dict[str, str | None] = {}
    valid = True
    for raw_option in options.split(","):
        option = raw_option.strip().lower()
        if not option:
            valid = False
            continue
        key, separator, value = option.partition("=")
        if key in parsed:
            valid = False
        parsed[key] = value if separator else None
    return parsed, valid


def _normalized_security_options(service: dict[str, Any]) -> tuple[set[str], bool]:
    raw = service.get("security_opt", [])
    if not isinstance(raw, list):
        return set(), False
    normalized: set[str] = set()
    valid = True
    for option in raw:
        if not isinstance(option, str):
            valid = False
            continue
        normalized.add(option.strip().lower().replace("=", ":"))
    return normalized, valid


def _private_bind_host(port: Any) -> str:
    if isinstance(port, dict):
        return str(port.get("host_ip", "")).strip()
    if not isinstance(port, str):
        return ""
    value = port.strip()
    if value.startswith("["):
        closing = value.find("]")
        return value[1:closing].strip() if closing >= 0 else ""
    parts = value.split(":")
    return parts[0].strip() if len(parts) >= 3 else ""


def _is_controlled_private_bind(host: str) -> bool:
    if not host or host in {"0.0.0.0", "::", "[::]", "*"}:
        return False
    try:
        address = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    except ValueError:
        return False
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        return False
    if address.is_loopback:
        return True
    if isinstance(address, ipaddress.IPv4Address):
        return address in ipaddress.ip_network("10.0.0.0/8") \
            or address in ipaddress.ip_network("172.16.0.0/12") \
            or address in ipaddress.ip_network("192.168.0.0/16")
    return address in ipaddress.ip_network("fc00::/7")


def validate_compose(model: dict[str, Any]) -> list[str]:
    if not isinstance(model, dict):
        return ["compose model must be a JSON object"]
    errors: list[str] = []
    unexpected_top_level = sorted(set(model) - ALLOWED_TOP_LEVEL_KEYS)
    if unexpected_top_level:
        errors.append(
            "unsupported top-level Compose settings are forbidden: "
            + ",".join(unexpected_top_level)
        )
    services = model.get("services")
    if not isinstance(services, dict):
        return ["compose model must contain a services object"]

    service_names = {str(name) for name in services}
    missing_services = sorted(REQUIRED_SERVICES - service_names)
    extra_services = sorted(service_names - REQUIRED_SERVICES)
    if missing_services:
        errors.append("required services are missing: " + ",".join(missing_services))
    if extra_services:
        errors.append("unexpected production services are forbidden: " + ",".join(extra_services))

    networks = model.get("networks")
    if not isinstance(networks, dict):
        errors.append("top-level networks must contain exactly app and data")
    else:
        network_names = {str(name) for name in networks}
        if network_names != {"app", "data"}:
            errors.append("top-level networks must contain exactly app and data")
        for network_name in ("app", "data"):
            config = networks.get(network_name)
            if not isinstance(config, dict):
                errors.append(f"network {network_name}: definition must be an object")
                continue
            unexpected_keys = sorted(set(config) - {"name", "ipam", "internal"})
            if unexpected_keys:
                errors.append(
                    f"network {network_name}: unsupported settings are forbidden: "
                    + ",".join(unexpected_keys)
                )
            if config.get("ipam", {}) != {}:
                errors.append(f"network {network_name}: custom IPAM is forbidden")
        data_network = networks.get("data")
        if isinstance(data_network, dict) and data_network.get("internal") is not True:
            errors.append("network data: internal:true is required")
        app_network = networks.get("app")
        if isinstance(app_network, dict) and app_network.get("internal") is True:
            errors.append("network app: must remain the ingress-facing application network")

    volumes = model.get("volumes")
    if not isinstance(volumes, dict) or set(volumes) != {"mysql-data", "redis-data"}:
        errors.append("top-level volumes must contain exactly mysql-data and redis-data")
    else:
        for volume_name, config in volumes.items():
            if not isinstance(config, dict) or set(config) - {"name"}:
                errors.append(f"volume {volume_name}: only the Compose-generated name is allowed")
    if model.get("configs"):
        errors.append("top-level configs are forbidden in the immutable production model")
    if model.get("secrets"):
        errors.append("top-level Compose secrets are forbidden; use the approved external secret injection boundary")

    for name, service in sorted(services.items()):
        if not isinstance(service, dict):
            errors.append(f"{name}: service definition must be an object")
            continue
        allowed_service_keys = ALLOWED_SERVICE_KEYS.get(name, set())
        unexpected_service_keys = sorted(set(service) - allowed_service_keys)
        if unexpected_service_keys:
            errors.append(
                f"{name}: unsupported service settings are forbidden: "
                + ",".join(unexpected_service_keys)
            )
        if service.get("build") is not None:
            errors.append(f"{name}: production compose must not contain build")
        image = str(service.get("image", ""))
        if not IMMUTABLE_IMAGE.fullmatch(image):
            errors.append(f"{name}: image must be an immutable repository@sha256 reference")
        if service.get("privileged") is True:
            errors.append(f"{name}: privileged containers are forbidden")
        for namespace_key in NAMESPACE_KEYS:
            if service.get(namespace_key) not in (None, ""):
                errors.append(f"{name}: namespace override {namespace_key} is forbidden")
        if service.get("devices"):
            errors.append(f"{name}: device mappings are forbidden")
        if service.get("device_cgroup_rules"):
            errors.append(f"{name}: device cgroup rules are forbidden")
        if service.get("device_requests"):
            errors.append(f"{name}: device requests are forbidden")
        if service.get("gpus"):
            errors.append(f"{name}: GPU access is forbidden")
        if service.get("runtime"):
            errors.append(f"{name}: alternate container runtimes are forbidden")
        if service.get("volumes_from"):
            errors.append(f"{name}: volumes_from is forbidden")
        if service.get("use_api_socket"):
            errors.append(f"{name}: container engine API socket access is forbidden")
        if service.get("develop"):
            errors.append(f"{name}: Compose development sync/watch is forbidden")
        if service.get("profiles"):
            errors.append(f"{name}: conditional Compose profiles are forbidden")
        if service.get("scale") is not None:
            errors.append(f"{name}: service scale overrides are forbidden")
        if name not in HARDENED_SERVICES and service.get("deploy") is not None:
            errors.append(f"{name}: deploy overrides are forbidden for data services")
        if service.get("configs"):
            errors.append(f"{name}: Compose config mounts are forbidden")
        if service.get("secrets"):
            errors.append(f"{name}: Compose secret mounts are forbidden")
        if service.get("post_start") or service.get("pre_stop"):
            errors.append(f"{name}: lifecycle command hooks are forbidden")
        if service.get("sysctls"):
            errors.append(f"{name}: sysctl overrides are forbidden")
        if service.get("shm_size"):
            errors.append(f"{name}: implicit /dev/shm tmpfs overrides are forbidden")
        for network_override in ("extra_hosts", "links", "external_links", "dns", "dns_search"):
            if service.get(network_override):
                errors.append(f"{name}: network override {network_override} is forbidden")
        if service.get("cap_add"):
            errors.append(f"{name}: no Linux capability may be added")
        if service.get("group_add"):
            errors.append(f"{name}: supplemental groups are forbidden")
        if service.get("entrypoint") not in (None, []):
            errors.append(f"{name}: entrypoint overrides are forbidden")

        environment = service.get("environment")
        if isinstance(environment, dict):
            unexpected_environment = sorted(
                set(environment) - ALLOWED_ENVIRONMENT_KEYS.get(name, set())
            )
            if unexpected_environment:
                errors.append(
                    f"{name}: unsupported environment variables are forbidden: "
                    + ",".join(unexpected_environment)
                )
        if name == "app":
            if not isinstance(environment, dict):
                errors.append("app: normalized environment object is required")
            else:
                operational_username = str(
                    environment.get("WEB_STARTER_MANAGEMENT_USERNAME", "")
                )
                operational_password = str(
                    environment.get("WEB_STARTER_MANAGEMENT_PASSWORD", "")
                )
                if not MANAGEMENT_USERNAME.fullmatch(operational_username):
                    errors.append(
                        "app: dedicated operational management username is required"
                    )
                if len(operational_password.strip()) < 32:
                    errors.append(
                        "app: dedicated operational management password must contain at least 32 characters"
                    )
                if environment.get("WEB_STARTER_SHUTDOWN_PHASE_TIMEOUT") \
                        != EXPECTED_APP_SHUTDOWN_PHASE_TIMEOUT:
                    errors.append(
                        "app: graceful shutdown phase timeout must be exactly 10s "
                        "to preserve the 40s governance restart evidence window"
                    )
        elif isinstance(environment, dict) and (
            "WEB_STARTER_MANAGEMENT_USERNAME" in environment
            or "WEB_STARTER_MANAGEMENT_PASSWORD" in environment
        ):
            errors.append(
                f"{name}: operational management credentials belong only to app"
            )

        expected_user = {
            "app": "10001:10001",
            "nginx": "101:101",
            "mcp-public-nginx": "101:101",
        }.get(name)
        actual_user = service.get("user")
        if expected_user is None:
            if actual_user not in (None, ""):
                errors.append(f"{name}: user override is forbidden")
        elif str(actual_user) != expected_user:
            errors.append(f"{name}: user must be exactly {expected_user}")

        security_options, valid_security_options = _normalized_security_options(service)
        if not valid_security_options:
            errors.append(f"{name}: security_opt must contain only string options")
        raw_security_options = service.get("security_opt")
        if security_options != ALLOWED_SECURITY_OPTIONS or not isinstance(raw_security_options, list) or len(raw_security_options) != 1:
            errors.append(f"{name}: security_opt must be exactly no-new-privileges:true")

        network_names, valid_network_config = _network_names(service)
        expected_networks = EXPECTED_SERVICE_NETWORKS.get(name, set())
        if network_names != expected_networks:
            errors.append(
                f"{name}: networks must be exactly "
                + ",".join(sorted(expected_networks))
            )
        if not valid_network_config:
            errors.append(f"{name}: per-service network aliases and address overrides are forbidden")

        tmpfs_entries, valid_tmpfs = _tmpfs_entries(service)
        if not valid_tmpfs:
            errors.append(f"{name}: tmpfs must use normalized string entries")
        if name in HARDENED_SERVICES:
            if len(tmpfs_entries) != 1 or tmpfs_entries[0][0] != "/tmp":
                errors.append(f"{name}: exactly one /tmp tmpfs is required")
            elif tmpfs_entries:
                options, options_valid = _tmpfs_options(tmpfs_entries[0][1])
                if not options_valid:
                    errors.append(f"{name}: /tmp tmpfs options must not be empty or duplicated")
                required_flags = {"rw", "noexec", "nosuid", "nodev"}
                missing_flags = sorted(flag for flag in required_flags if options.get(flag, "missing") is not None)
                if missing_flags:
                    errors.append(f"{name}: /tmp tmpfs lacks {','.join(missing_flags)}")
                conflicts = sorted({"ro", "exec", "suid", "dev"} & set(options))
                if conflicts:
                    errors.append(f"{name}: /tmp tmpfs has conflicting options {','.join(conflicts)}")
                unsupported = sorted(set(options) - {"rw", "noexec", "nosuid", "nodev", "size", "mode", "uid", "gid"})
                if unsupported:
                    errors.append(f"{name}: /tmp tmpfs has unsupported options {','.join(unsupported)}")
                size = options.get("size")
                if not isinstance(size, str) or not _positive_size(size):
                    errors.append(f"{name}: /tmp tmpfs requires a positive size")
        elif tmpfs_entries:
            errors.append(f"{name}: tmpfs is not allowed for this service")

        allowed_mounts = ALLOWED_MOUNTS.get(name, {})
        service_volumes, volumes_are_list = _list_or_empty(service.get("volumes"))
        if not volumes_are_list:
            errors.append(f"{name}: volumes must be a normalized list")
        targets: list[str] = []
        tls_sources: list[str] = []
        for volume in service_volumes:
            mount_type, source, target, read_only = _volume_details(volume)
            targets.append(target)
            if "docker.sock" in source.lower() or "docker.sock" in target.lower():
                errors.append(f"{name}: Docker socket mounts are forbidden")
                continue
            allowed = allowed_mounts.get(target)
            if not allowed:
                errors.append(f"{name}: mount target {target or '<empty>'} is not allowlisted")
                continue
            if mount_type != allowed["type"]:
                errors.append(f"{name}: mount target {target} has forbidden type {mount_type or '<empty>'}")
            if read_only is not allowed["read_only"]:
                expected = "read-only" if allowed["read_only"] else "writable"
                errors.append(f"{name}: mount target {target} must be {expected}")
            if "source" in allowed and source != allowed["source"]:
                errors.append(f"{name}: mount target {target} must use volume {allowed['source']}")
            if not isinstance(volume, dict):
                errors.append(f"{name}: mounts must use normalized long syntax")
                continue
            allowed_keys = {"type", "source", "target", "read_only", "volume"} if mount_type == "volume" else {"type", "source", "target", "read_only", "bind"}
            unexpected_mount_keys = sorted(set(volume) - allowed_keys)
            if unexpected_mount_keys:
                errors.append(f"{name}: mount target {target} has unsupported settings")
            if mount_type == "volume" and volume.get("volume", {}) != {}:
                errors.append(f"{name}: mount target {target} has forbidden volume options")
            if mount_type == "bind":
                if not Path(source).is_absolute():
                    errors.append(f"{name}: TLS bind source for {target} must be absolute")
                if volume.get("bind") != {"create_host_path": False}:
                    errors.append(f"{name}: TLS bind {target} must set bind.create_host_path:false")
                tls_sources.append(source)
        if len(targets) != len(set(targets)):
            errors.append(f"{name}: duplicate mount targets are forbidden")
        if set(targets) != set(allowed_mounts) or len(targets) != len(allowed_mounts):
            expected_targets = ",".join(sorted(allowed_mounts)) or "none"
            errors.append(f"{name}: mount targets must be exactly {expected_targets}")
        if name == "mcp-public-nginx" and len(set(tls_sources)) != 2:
            errors.append("mcp-public-nginx: TLS certificate and key must use distinct bind sources")

        command = service.get("command")
        if isinstance(command, str) or (
            isinstance(command, list)
            and command
            and str(command[0]).strip().lower() in SHELL_EXECUTABLES
        ):
            errors.append(f"{name}: shell-form commands are forbidden")
        if name == "redis":
            if not (
                isinstance(command, list)
                and len(command) == 5
                and command[:4] == ["redis-server", "--appendonly", "yes", "--requirepass"]
                and isinstance(command[4], str)
                and bool(command[4])
            ):
                errors.append("redis: command must be the approved exec-form redis-server invocation")
        elif name in EXPECTED_COMMANDS and command != EXPECTED_COMMANDS[name]:
            errors.append(f"{name}: command must match the approved production invocation")

        healthcheck = service.get("healthcheck")
        healthcheck_test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
        expected_healthcheck = EXPECTED_HEALTHCHECK_TESTS.get(name)
        if healthcheck_test != expected_healthcheck:
            errors.append(f"{name}: healthcheck command must match the approved production probe")
        if name == "app" and isinstance(healthcheck, dict):
            actual_timing = {
                key: healthcheck.get(key)
                for key in EXPECTED_APP_HEALTHCHECK_TIMING
            }
            if actual_timing != EXPECTED_APP_HEALTHCHECK_TIMING:
                errors.append(
                    "app: healthcheck timing must preserve the 2s startup probe interval "
                    "required by the 40s governance restart evidence window"
                )

        ports, ports_are_list = _list_or_empty(service.get("ports"))
        if not ports_are_list:
            errors.append(f"{name}: ports must be a normalized list")
        expected_target = {"nginx": 8080, "mcp-public-nginx": 8443}.get(name)
        if expected_target is None:
            if ports:
                errors.append(f"{name}: published ports are forbidden")
        elif len(ports) != 1:
            errors.append(f"{name}: exactly one published port targeting {expected_target} is required")
        if expected_target is not None:
            for port in ports:
                if not isinstance(port, dict):
                    errors.append(f"{name}: ports must use normalized long syntax")
                    continue
                if set(port) - {"mode", "host_ip", "target", "published", "protocol"}:
                    errors.append(f"{name}: published port has unsupported settings")
                if port.get("target") != expected_target:
                    errors.append(f"{name}: published port must target {expected_target}")
                if port.get("protocol", "tcp") != "tcp" or port.get("mode", "ingress") != "ingress":
                    errors.append(f"{name}: published port must use tcp ingress mode")
                if not _valid_published_port(port.get("published")):
                    errors.append(f"{name}: published host port must be a single valid port")
                host = str(port.get("host_ip", "")).strip()
                if name == "nginx" and not _is_controlled_private_bind(host):
                    errors.append(
                        "nginx: private port host_ip must be an explicit loopback, RFC1918, or IPv6 ULA address"
                    )
                if name == "mcp-public-nginx" and not _valid_public_bind(host):
                    errors.append("mcp-public-nginx: public port host_ip must be an explicit IP address")

        expose, expose_is_list = _list_or_empty(service.get("expose"))
        if not expose_is_list:
            errors.append(f"{name}: expose must be a normalized list")
        expected_expose = {"8080", "8081"} if name == "app" else set()
        if {str(value) for value in expose} != expected_expose or len(expose) != len(expected_expose):
            expected_text = ",".join(sorted(expected_expose)) or "none"
            errors.append(f"{name}: exposed ports must be exactly {expected_text}")

    for name in HARDENED_SERVICES:
        service = services.get(name)
        if not isinstance(service, dict):
            errors.append(f"{name}: required hardened service is missing")
            continue

        if service.get("read_only") is not True:
            errors.append(f"{name}: root filesystem must be read-only")
        if service.get("init") is not True:
            errors.append(f"{name}: init:true is required")

        dropped = {str(capability).upper() for capability in service.get("cap_drop", [])}
        if dropped != {"ALL"} or len(service.get("cap_drop", [])) != 1:
            errors.append(f"{name}: cap_drop must be exactly ALL")

        deploy = service.get("deploy", {})
        if (
            not isinstance(deploy, dict)
            or "resources" not in deploy
            or set(deploy) - {"resources", "placement"}
            or deploy.get("placement", {}) != {}
        ):
            errors.append(f"{name}: deploy must contain only resource budgets")
            deploy = {}
        resources = deploy.get("resources", {})
        if not isinstance(resources, dict) or set(resources) != {"limits", "reservations"}:
            errors.append(f"{name}: deploy resources must contain exactly limits and reservations")
            resources = {}
        limits = resources.get("limits", {})
        reservations = resources.get("reservations", {})
        if not isinstance(limits, dict) or set(limits) != {"cpus", "memory", "pids"}:
            errors.append(f"{name}: resource limits must contain exactly CPU, memory, and PID")
        if not isinstance(reservations, dict) or set(reservations) != {"cpus", "memory"}:
            errors.append(f"{name}: resource reservations must contain exactly CPU and memory")
        if not isinstance(limits, dict) or not _positive(limits.get("cpus")):
            errors.append(f"{name}: positive CPU limit is required")
        if not isinstance(limits, dict) or not _positive(limits.get("memory")):
            errors.append(f"{name}: positive memory limit is required")
        if not isinstance(limits, dict) or not _positive(limits.get("pids")):
            errors.append(f"{name}: positive PID limit is required")

    return errors


def _final_stage(text: str) -> str:
    starts = list(re.finditer(r"(?im)^FROM\s+", text))
    return text[starts[-1].start() :] if starts else text


def _dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    instructions: list[tuple[str, str]] = []
    logical_line = ""
    for physical_line in _final_stage(text).splitlines():
        stripped = physical_line.strip()
        if not logical_line and (not stripped or stripped.startswith("#")):
            continue
        continued = physical_line.rstrip().endswith("\\")
        fragment = physical_line.rstrip()
        if continued:
            fragment = fragment[:-1]
        logical_line = f"{logical_line} {fragment.strip()}".strip()
        if continued:
            continue
        match = re.match(r"^([A-Za-z]+)\s+(.*)$", logical_line)
        if match:
            instructions.append((match.group(1).upper(), match.group(2).strip()))
        logical_line = ""
    return instructions


def _active_nginx_directives(text: str, directive: str) -> list[str]:
    values: list[str] = []
    pattern = re.compile(rf"^{re.escape(directive)}\s+([^;]+);$")
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        match = pattern.fullmatch(active)
        if match:
            values.append(match.group(1).strip())
    return values


def _exposes_privileged_port(argument: str) -> bool:
    for token in argument.split():
        port_spec = token.split("/", 1)[0]
        start_text, separator, end_text = port_spec.partition("-")
        try:
            start = int(start_text)
            end = int(end_text) if separator else start
        except ValueError:
            return True
        if start > end or start < 1 or end > 65535:
            return True
        if start <= 80 <= end or start <= 443 <= end:
            return True
    return False


def validate_dockerfiles(repository_root: Path) -> list[str]:
    errors: list[str] = []
    app_path = repository_root / "Dockerfile"
    nginx_path = repository_root / "deploy/nginx/Dockerfile"
    try:
        app_stage = _final_stage(app_path.read_text(encoding="utf-8"))
        nginx_stage = _final_stage(nginx_path.read_text(encoding="utf-8"))
    except OSError as exception:
        return [f"unable to read final-image Dockerfiles: {exception.filename}"]

    app_instructions = _dockerfile_instructions(app_stage)
    nginx_instructions = _dockerfile_instructions(nginx_stage)
    app_users = [argument for instruction, argument in app_instructions if instruction == "USER"]
    nginx_users = [argument for instruction, argument in nginx_instructions if instruction == "USER"]

    if not app_users or app_users[-1] != "10001:10001":
        errors.append("Dockerfile: final app stage must run as 10001:10001")
    if not nginx_users or nginx_users[-1] != "101:101":
        errors.append("deploy/nginx/Dockerfile: final stage must run as 101:101")
    for instruction, argument in nginx_instructions:
        if instruction != "EXPOSE":
            continue
        if _exposes_privileged_port(argument):
            errors.append("deploy/nginx/Dockerfile: privileged listener ports are forbidden")
            break

    for relative in ("deploy/nginx/nginx.conf", "deploy/nginx/nginx-public.conf"):
        try:
            configuration = (repository_root / relative).read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{relative}: checked-in runtime configuration is missing")
            continue
        if _active_nginx_directives(configuration, "pid") != ["/tmp/nginx.pid"]:
            errors.append(f"{relative}: PID file must live on controlled tmpfs")
        for directive in (
            "client_body_temp_path",
            "proxy_temp_path",
            "fastcgi_temp_path",
            "uwsgi_temp_path",
            "scgi_temp_path",
        ):
            values = _active_nginx_directives(configuration, directive)
            normalized = posixpath.normpath(values[0]) if len(values) == 1 else ""
            if len(values) != 1 or values[0] != normalized or not normalized.startswith("/tmp/"):
                errors.append(f"{relative}: {directive} must live on controlled tmpfs")

    return errors


def _write_summary(
    output: Path,
    compose_source: Path | str | None,
    errors: list[str],
) -> None:
    if isinstance(compose_source, Path):
        try:
            compose_sha256 = hashlib.sha256(compose_source.read_bytes()).hexdigest()
        except OSError:
            compose_sha256 = None
    else:
        compose_sha256 = compose_source
    summary = {
        "schemaVersion": 1,
        "status": "PASS" if not errors else "FAIL",
        "composeSha256": compose_sha256,
        "errors": errors,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-json", required=True, type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    compose_sha256: str | None = None
    try:
        compose_bytes = args.compose_json.read_bytes()
        compose_sha256 = hashlib.sha256(compose_bytes).hexdigest()
        model = json.loads(compose_bytes)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exception:
        errors = [f"invalid Compose JSON ({exception.__class__.__name__})"]
        if args.output is not None:
            _write_summary(args.output.resolve(), compose_sha256, errors)
        print(f"FAIL production-compose-policy: {errors[0]}")
        return 1

    errors = validate_compose(model) + validate_dockerfiles(args.repository_root.resolve())
    if args.output is not None:
        _write_summary(args.output.resolve(), compose_sha256, errors)
    if errors:
        for error in errors:
            print(f"FAIL production-compose-policy: {error}")
        return 1
    print("PASS production-compose-policy: immutable images and exact hardened production topology")
    return 0


if __name__ == "__main__":
    sys.exit(main())
