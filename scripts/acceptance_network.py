"""Loopback-only hostname resolution for isolated release acceptance.

Production-mode acceptance needs a syntactically non-local OAuth issuer while
the disposable stack remains bound to loopback.  This helper maps only explicit
reserved test hostnames to a literal loopback address for the lifetime of the
calling Python function.  It never edits the system hosts file or performs a
fallback DNS lookup for an alias.
"""

from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import os
import re
import socket
from typing import Any, Iterator
from urllib.request import HTTPRedirectHandler, Request


_HOST_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+test\Z"
)


class RejectRedirectHandler(HTTPRedirectHandler):
    """Reject every redirect without creating a follow-up request.

    Release-acceptance clients carry cookies, Basic credentials, or bearer
    tokens. urllib's default redirect handler can copy those headers to the
    redirected request, so protocol verifiers must observe the original 3xx
    response instead of following it.
    """

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def reject_tls_key_logging() -> None:
    """Fail closed when OpenSSL would persist acceptance TLS session keys."""

    if os.environ.get("SSLKEYLOGFILE", "").strip():
        raise ValueError("SSLKEYLOGFILE must be unset for credential-bearing acceptance")


def loopback_aliases() -> tuple[tuple[str, ...], str]:
    """Return validated reserved aliases and their literal loopback target."""

    raw = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_HOSTS", "")
    aliases = tuple(dict.fromkeys(
        candidate.strip().lower() for candidate in raw.split(",") if candidate.strip()
    ))
    target = os.environ.get("WEB_STARTER_ACCEPTANCE_LOOPBACK_ADDRESS", "127.0.0.1").strip()
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise ValueError("acceptance loopback address must be an IP literal") from error
    if not address.is_loopback:
        raise ValueError("acceptance hostname aliases may resolve only to a loopback address")
    for alias in aliases:
        if not _HOST_PATTERN.fullmatch(alias):
            raise ValueError("acceptance hostname aliases must be reserved .test DNS names")
    return aliases, str(address)


def is_isolated_acceptance_host(host: str) -> bool:
    """Return whether self-signed TLS is restricted to a local acceptance host."""

    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    try:
        if ipaddress.ip_address(normalized).is_loopback:
            return True
    except ValueError:
        pass
    aliases, _ = loopback_aliases()
    return normalized in aliases


@contextmanager
def isolated_loopback_resolution() -> Iterator[None]:
    """Resolve explicit acceptance aliases to loopback within this process only."""

    aliases, target = loopback_aliases()
    if not aliases:
        yield
        return

    original = socket.getaddrinfo

    def mapped_getaddrinfo(host: object, port: object, *args: object, **kwargs: object):
        candidate = host.decode("ascii") if isinstance(host, bytes) else str(host)
        if candidate.rstrip(".").lower() in aliases:
            return original(target, port, *args, **kwargs)
        return original(host, port, *args, **kwargs)

    socket.getaddrinfo = mapped_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original  # type: ignore[assignment]
