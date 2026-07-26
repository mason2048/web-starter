#!/usr/bin/env python3
"""Create isolated API-issued credentials for MCP governance runtime acceptance.

The fixture builder uses only the product's management and OAuth endpoints.
Every bearer is written once to a caller-owned directory outside the Git
workspace, is never printed, and is intentionally scoped to one observation.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import sys
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    ProxyHandler,
    build_opener,
)

from acceptance_network import (
    RejectRedirectHandler,
    is_isolated_acceptance_host,
    isolated_loopback_resolution,
    reject_tls_key_logging,
)
import prepare_release_runtime_acceptance as release_prepare
import v1_upgrade_refresh as pkce


EXPECTED_FILES = frozenset({
    "sdk.json",
    "session.json",
    "delete.json",
    "ttl.json",
    "rate-subject-a.json",
    "rate-subject-b.json",
    "rate-client-a.json",
    "rate-client-b.json",
    "rate-risk.json",
    "audit.json",
})

PAT_PLAN: dict[str, tuple[str, tuple[str, ...]]] = {
    "sdk.json": ("sdk", ("system:info",)),
    "session.json": ("session", ("system:info",)),
    "delete.json": ("delete", ("system:info",)),
    "ttl.json": ("ttl", ("system:info",)),
    "rate-subject-a.json": ("rate-subject", ("system:info",)),
    "rate-subject-b.json": ("rate-subject", ("system:info",)),
    "rate-risk.json": ("rate-risk", ("project:remove",)),
    "audit.json": ("audit", ("audit:list",)),
}

OAUTH_USERS = ("rate-client-a", "rate-client-b")
OAUTH_SCOPES = ("system:info", "project:create")
MAX_PRIVATE_JSON_BYTES = 64 * 1024
# The public ingress deliberately limits login attempts to 10 requests/minute.
# Governance creates ten independent browser principals through that same
# production route, so start them slightly slower than one request per six
# seconds instead of weakening or bypassing the ingress policy.
PUBLIC_LOGIN_MIN_INTERVAL_SECONDS = 6.25


class GovernanceFixtureError(RuntimeError):
    """Raised when isolated governance fixtures cannot be created safely."""


FIXTURE_STAGES = frozenset({
    "output-initialization",
    "configuration",
    "admin-authentication",
    "account-creation",
    "account-authentication",
    "pat-issuance",
    "oauth-client-creation",
    "oauth-token-issuance",
    "private-inventory",
})


class GovernanceFixtureStageError(GovernanceFixtureError):
    """Expose only a fixed, non-secret fixture stage to the release runner."""

    def __init__(self, stage: str):
        if stage not in FIXTURE_STAGES:
            raise ValueError("governance fixture stage is not allowed")
        self.stage = stage
        super().__init__(f"governance fixture stage failed: {stage}")


class PublicLoginPacer:
    """Pace fixture logins against the production public-ingress limit."""

    def __init__(
        self,
        interval_seconds: float = PUBLIC_LOGIN_MIN_INTERVAL_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if interval_seconds < PUBLIC_LOGIN_MIN_INTERVAL_SECONDS:
            raise ValueError("governance login interval is below the public ingress limit")
        self._interval_seconds = interval_seconds
        self._clock = clock
        self._sleeper = sleeper
        self._last_started: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last_started is not None:
            earliest = self._last_started + self._interval_seconds
            while now < earliest:
                self._sleeper(earliest - now)
                now = self._clock()
        self._last_started = now


@contextmanager
def _fixture_stage(stage: str) -> Iterator[None]:
    if stage not in FIXTURE_STAGES:
        raise ValueError("governance fixture stage is not allowed")
    try:
        yield
    except GovernanceFixtureStageError:
        raise
    except (
        GovernanceFixtureError,
        release_prepare.AcceptanceSetupError,
        pkce.PkceRefreshError,
        OSError,
        ValueError,
    ) as exception:
        raise GovernanceFixtureStageError(stage) from exception


@dataclass(frozen=True)
class AuthenticatedUser:
    subject_id: str
    cookies: CookieJar
    write_headers: dict[str, str]


@dataclass(frozen=True)
class PrivateOutputDirectory:
    path: Path
    descriptor: int
    device: int
    inode: int


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise GovernanceFixtureError(f"{name} is required")
    if any(character in value for character in "\r\n\0"):
        raise GovernanceFixtureError(f"{name} contains a forbidden control character")
    return value


def _base_url(name: str, *, https: bool) -> str:
    value = _required(name).rstrip("/")
    parsed = urlparse(value)
    expected = "https" if https else "http"
    if parsed.scheme != expected or not parsed.hostname \
            or parsed.username or parsed.password or parsed.path not in {"", "/"} \
            or parsed.query or parsed.fragment:
        raise GovernanceFixtureError(f"{name} must be an exact {expected.upper()} origin")
    if not https and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise GovernanceFixtureError("private governance HTTP ingress must be loopback-only")
    if https:
        try:
            isolated = is_isolated_acceptance_host(parsed.hostname)
        except ValueError as exception:
            raise GovernanceFixtureError(str(exception)) from exception
        if not isolated:
            raise GovernanceFixtureError(
                "public governance HTTPS ingress must be an explicit loopback alias"
            )
    return value


def _tls_context(public_url: str) -> ssl.SSLContext:
    try:
        reject_tls_key_logging()
    except ValueError as exception:
        raise GovernanceFixtureError(str(exception)) from exception
    if os.environ.get("WEB_STARTER_ACCEPTANCE_INSECURE_TLS", "false") != "true":
        return ssl.create_default_context()
    hostname = (urlparse(public_url).hostname or "").lower()
    allowed = {
        item.strip().lower()
        for item in os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS", "").split(",")
        if item.strip()
    }
    if hostname not in allowed:
        raise GovernanceFixtureError(
            "insecure governance TLS requires an explicitly isolated loopback hostname"
        )
    return ssl._create_unverified_context()  # noqa: SLF001 - isolated self-signed CI TLS only


def _strict_opener(cookies: CookieJar, context: ssl.SSLContext) -> Any:
    return build_opener(
        ProxyHandler({}),
        RejectRedirectHandler(),
        HTTPCookieProcessor(cookies),
        HTTPSHandler(context=context),
    )


def _oauth_opener(cookies: CookieJar, context: ssl.SSLContext) -> Any:
    # v1_upgrade_refresh installs and verifies its own no-redirect handler.
    return build_opener(
        ProxyHandler({}),
        HTTPCookieProcessor(cookies),
        HTTPSHandler(context=context),
    )


def _token_opener(context: ssl.SSLContext) -> Any:
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context))


def _authenticate(
    public_url: str,
    username: str,
    password: str,
    context: ssl.SSLContext,
    login_pacer: PublicLoginPacer,
) -> AuthenticatedUser:
    cookies = CookieJar()
    opener = _strict_opener(cookies, context)
    csrf_header, csrf_token = release_prepare._csrf(opener, public_url)
    login_pacer.wait()
    caller = release_prepare._api_data(
        opener,
        "POST",
        f"{public_url}/api/auth/login",
        {"username": username, "password": password},
        {csrf_header: csrf_token},
    )
    subject_id = str(caller.get("subjectId", "")) if isinstance(caller, dict) else ""
    if not subject_id.isdigit():
        raise GovernanceFixtureError("governance login did not return a numeric subject")
    cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in cookies)
    if "WEB_STARTER_SESSION=" not in cookie_header:
        raise GovernanceFixtureError("governance login did not establish a Web Session")
    return AuthenticatedUser(
        subject_id,
        cookies,
        {csrf_header: csrf_token, "Cookie": cookie_header},
    )


def _create_user(
    opener: Any,
    private_url: str,
    headers: dict[str, str],
    label: str,
    suffix: str,
) -> tuple[str, str, str]:
    username = f"governance_{label.replace('-', '_')}_{suffix.lower()}"
    password = secrets.token_urlsafe(36)
    response = release_prepare._api_data(
        opener,
        "POST",
        f"{private_url}/api/users",
        {
            "username": username,
            "displayName": f"MCP governance {label}",
            "password": password,
            "status": "ENABLED",
            "roleIds": [1],
        },
        headers,
    )
    identifier = str(response.get("id", "")) if isinstance(response, dict) else ""
    if not identifier.isdigit():
        raise GovernanceFixtureError(f"governance user {label} was not created")
    return identifier, username, password


def _create_pat(
    opener: Any,
    private_url: str,
    headers: dict[str, str],
    filename: str,
    scopes: tuple[str, ...],
    suffix: str,
) -> str:
    response = release_prepare._api_data(
        opener,
        "POST",
        f"{private_url}/api/security/personal-tokens",
        {
            "name": f"governance-{filename.removesuffix('.json')}-{suffix.lower()}",
            "scopes": list(scopes),
            "allowedIpCidrs": [],
            "expiresAt": None,
        },
        headers,
    )
    token = response.get("token") if isinstance(response, dict) else None
    if not isinstance(token, str) or len(token) < 20:
        raise GovernanceFixtureError(f"{filename} PAT did not return a one-time token")
    return token


def _assert_output_directory(output: PrivateOutputDirectory) -> None:
    try:
        path_metadata = os.lstat(output.path)
        opened_metadata = os.fstat(output.descriptor)
    except OSError as exception:
        raise GovernanceFixtureError(
            "governance credential directory identity is unavailable"
        ) from exception
    expected = (output.device, output.inode)
    if not stat.S_ISDIR(path_metadata.st_mode) \
            or not stat.S_ISDIR(opened_metadata.st_mode) \
            or (path_metadata.st_dev, path_metadata.st_ino) != expected \
            or (opened_metadata.st_dev, opened_metadata.st_ino) != expected \
            or stat.S_IMODE(opened_metadata.st_mode) != 0o700 \
            or opened_metadata.st_uid != os.geteuid():
        raise GovernanceFixtureError("governance credential directory identity changed")


def _write_private_json(
    output: PrivateOutputDirectory,
    filename: str,
    document: dict[str, str],
) -> None:
    if filename not in EXPECTED_FILES or "/" in filename or "\0" in filename:
        raise GovernanceFixtureError("governance credential filename is not allowed")
    payload = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if not payload or len(payload) > MAX_PRIVATE_JSON_BYTES:
        raise GovernanceFixtureError("governance credential response is outside its size bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    _assert_output_directory(output)
    descriptor: int | None = os.open(
        filename, flags, 0o600, dir_fd=output.descriptor
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GovernanceFixtureError("governance credential write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(
            filename, dir_fd=output.descriptor, follow_symlinks=False
        )
        if not stat.S_ISREG(metadata.st_mode) \
                or stat.S_IMODE(metadata.st_mode) != 0o600 \
                or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 \
                or metadata.st_size != len(payload) \
                or (path_metadata.st_dev, path_metadata.st_ino) \
                    != (metadata.st_dev, metadata.st_ino):
            raise GovernanceFixtureError("governance credential file is not private")
        os.close(descriptor)
        descriptor = None
        os.fsync(output.descriptor)
        _assert_output_directory(output)
    except BaseException:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                os.unlink(filename, dir_fd=output.descriptor)
            except FileNotFoundError:
                pass
        raise


def _open_output_directory(path: Path, repository: Path) -> PrivateOutputDirectory:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or requested.parent.is_symlink():
        raise GovernanceFixtureError("governance credential directory must not use symlinks")
    parent = requested.parent.resolve(strict=True)
    parent_metadata = parent.stat()
    if not stat.S_ISDIR(parent_metadata.st_mode) \
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700 \
            or parent_metadata.st_uid != os.geteuid():
        raise GovernanceFixtureError(
            "governance credential parent must be an owned mode 0700 directory"
        )
    if requested.exists():
        before = requested.lstat()
        if not stat.S_ISDIR(before.st_mode) \
                or stat.S_IMODE(before.st_mode) != 0o700 \
                or before.st_uid != os.geteuid() \
                or any(requested.iterdir()):
            raise GovernanceFixtureError(
                "governance credential directory must be absent or empty owned mode 0700"
            )
    else:
        requested.mkdir(mode=0o700)
    resolved = requested.resolve(strict=True)
    metadata = resolved.stat()
    if resolved.parent != parent or resolved == repository \
            or repository in resolved.parents or resolved in repository.parents \
            or not stat.S_ISDIR(metadata.st_mode) \
            or metadata.st_uid != os.geteuid():
        raise GovernanceFixtureError("governance credential directory boundary is invalid")
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise GovernanceFixtureError("governance credential directory must be mode 0700")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.lstat(resolved)
        descriptor = os.open(resolved, flags)
        opened = os.fstat(descriptor)
        after = os.lstat(resolved)
    except OSError as exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise GovernanceFixtureError(
            "cannot open governance credential directory safely"
        ) from exception
    identities = {
        (item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode), item.st_uid)
        for item in (before, opened, after)
    }
    if len(identities) != 1 or not stat.S_ISDIR(opened.st_mode) \
            or stat.S_IMODE(opened.st_mode) != 0o700 \
            or opened.st_uid != os.geteuid():
        os.close(descriptor)
        raise GovernanceFixtureError("governance credential directory changed while opened")
    return PrivateOutputDirectory(resolved, descriptor, opened.st_dev, opened.st_ino)


def _require_exact_private_inventory(output: PrivateOutputDirectory) -> None:
    _assert_output_directory(output)
    if set(os.listdir(output.descriptor)) != EXPECTED_FILES:
        raise GovernanceFixtureError("governance credential directory is not the exact fixture set")
    for name in EXPECTED_FILES:
        metadata = os.stat(name, dir_fd=output.descriptor, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) \
                or stat.S_IMODE(metadata.st_mode) != 0o600 \
                or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 \
                or metadata.st_size <= 0 or metadata.st_size > MAX_PRIVATE_JSON_BYTES:
            raise GovernanceFixtureError("governance credential inventory contains an unsafe file")
    _assert_output_directory(output)


def _discard_credentials(output: PrivateOutputDirectory) -> None:
    for name in EXPECTED_FILES:
        try:
            metadata = os.stat(name, dir_fd=output.descriptor, follow_symlinks=False)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid():
                os.unlink(name, dir_fd=output.descriptor)
        except FileNotFoundError:
            pass
    os.fsync(output.descriptor)


@isolated_loopback_resolution()
def prepare(arguments: argparse.Namespace) -> None:
    repository = Path(arguments.repository_root).expanduser().resolve(strict=True)
    with _fixture_stage("output-initialization"):
        output = _open_output_directory(Path(arguments.output_directory), repository)
    completed = False
    try:
        _prepare_into(arguments, repository, output)
        completed = True
    finally:
        try:
            if not completed:
                _discard_credentials(output)
        finally:
            os.close(output.descriptor)


def _prepare_into(
    arguments: argparse.Namespace,
    repository: Path,
    output: PrivateOutputDirectory,
) -> None:
    del arguments, repository
    with _fixture_stage("configuration"):
        private_url = _base_url("WEB_STARTER_GOVERNANCE_PRIVATE_BASE_URL", https=False)
        public_url = _base_url("WEB_STARTER_GOVERNANCE_PUBLIC_BASE_URL", https=True)
        admin_username = _required("WEB_STARTER_GOVERNANCE_ADMIN_USERNAME")
        admin_password = _required("WEB_STARTER_GOVERNANCE_ADMIN_PASSWORD")
        active_kid = _required("WEB_STARTER_GOVERNANCE_OAUTH_ACTIVE_KID")
        context = _tls_context(public_url)
        login_pacer = PublicLoginPacer()
    with _fixture_stage("admin-authentication"):
        admin = _authenticate(
            public_url, admin_username, admin_password, context, login_pacer
        )
    admin_opener = _strict_opener(admin.cookies, context)
    suffix = secrets.token_hex(6)

    labels = sorted({subject for subject, _scopes in PAT_PLAN.values()} | set(OAUTH_USERS))
    with _fixture_stage("account-creation"):
        accounts: dict[str, tuple[str, str, str]] = {
            label: _create_user(
                admin_opener, private_url, admin.write_headers, label, suffix
            )
            for label in labels
        }

    authenticated: dict[str, AuthenticatedUser] = {}
    with _fixture_stage("account-authentication"):
        for label, (expected_id, username, password) in accounts.items():
            session = _authenticate(
                public_url, username, password, context, login_pacer
            )
            if session.subject_id != expected_id:
                raise GovernanceFixtureError(
                    f"governance user {label} subject identity changed"
                )
            authenticated[label] = session

    with _fixture_stage("pat-issuance"):
        for filename, (label, scopes) in PAT_PLAN.items():
            session = authenticated[label]
            token = _create_pat(
                _strict_opener(session.cookies, context),
                private_url,
                session.write_headers,
                filename,
                scopes,
                suffix,
            )
            _write_private_json(output, filename, {"token": token})

    client_id = f"governance-client-{suffix}"
    redirect_uri = f"{public_url}/login"
    with _fixture_stage("oauth-client-creation"):
        client = release_prepare._api_data(
            admin_opener,
            "POST",
            f"{private_url}/api/security/oauth-clients",
            {
                "clientId": client_id,
                "clientName": "MCP governance shared public client",
                "authenticationMethods": ["none"],
                "grantTypes": ["authorization_code", "refresh_token"],
                "redirectUris": [redirect_uri],
                "scopes": list(OAUTH_SCOPES),
                "requireConsent": False,
                "serviceAccountId": None,
            },
            admin.write_headers,
        )
        if not isinstance(client, dict) or client.get("clientSecret") is not None:
            raise GovernanceFixtureError(
                "governance public OAuth client response is invalid"
            )

    with _fixture_stage("oauth-token-issuance"):
        for label in OAUTH_USERS:
            token_set = pkce.authorization_code_pkce_once(
                _oauth_opener(authenticated[label].cookies, context),
                token_opener=_token_opener(context),
                authorization_endpoint=f"{public_url}/oauth2/authorize",
                token_endpoint=f"{public_url}/oauth2/token",
                client_id=client_id,
                redirect_uri=redirect_uri,
                scopes=OAUTH_SCOPES,
                expected_kid=active_kid,
                expected_issuer=public_url,
                expected_audience=f"{public_url}/mcp",
                minimum_ttl_seconds=300,
            )
            filename = f"{label}.json"
            _write_private_json(
                output, filename, {"access_token": token_set.access_token}
            )

    with _fixture_stage("private-inventory"):
        _require_exact_private_inventory(output)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--output-directory", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        prepare(parse_arguments(sys.argv[1:] if argv is None else argv))
    except (
        GovernanceFixtureError,
        release_prepare.AcceptanceSetupError,
        pkce.PkceRefreshError,
        OSError,
        ValueError,
    ) as exception:
        stage = (
            f": stage={exception.stage}"
            if isinstance(exception, GovernanceFixtureStageError)
            else ""
        )
        print(
            "FAIL mcp-governance-fixtures: " + exception.__class__.__name__ + stage,
            file=sys.stderr,
        )
        return 1
    print("PASS mcp-governance-fixtures: isolated API and PKCE credentials created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
