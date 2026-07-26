#!/usr/bin/env python3
"""Strict OAuth public-client helpers for the V1-to-V2 upgrade rehearsal.

The module deliberately has no file, logging, retry, or database behavior.  An
authenticated ``urllib`` opener is used only for the authorization request.  A
separate cookie-free opener is mandatory for token and refresh requests.  A
redirect interceptor is installed before either transport is used, preventing
the authorization code from being sent to the registered callback.

JWT parsing in this module is *not* signature verification.  It binds the
metadata observed in a token returned by the local authorization server.  The
rehearsal separately proves signature acceptance through the resource server
and the official MCP SDK.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
from http.client import HTTPException
import json
import re
import secrets
import time
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse
from urllib.request import (
    DataHandler,
    FileHandler,
    FTPHandler,
    HTTPBasicAuthHandler,
    HTTPDefaultErrorHandler,
    HTTPDigestAuthHandler,
    HTTPErrorProcessor,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    HTTPCookieProcessor,
    OpenerDirector,
    ProxyBasicAuthHandler,
    ProxyDigestAuthHandler,
    ProxyHandler,
    Request,
    UnknownHandler,
)


_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_OPAQUE_CODE = re.compile(r"^[A-Za-z0-9._~-]{16,2048}$")
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_JSON_BYTES = 64 * 1024
_MAX_JWT_SEGMENT_BYTES = 32 * 1024
_TOKEN_FIELDS = frozenset({
    "access_token", "refresh_token", "token_type", "expires_in", "scope",
})
_ERROR_FIELDS = frozenset({"error", "error_description", "error_uri"})
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_TOKEN_LIFETIME_TOLERANCE_SECONDS = 60


class PkceRefreshError(RuntimeError):
    """A fail-closed error whose code and text never contain credential data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TokenEndpointOutcomeUnknown(PkceRefreshError):
    """The one-time grant may have been consumed; callers must not retry it."""

    retry_safe = False

    def __init__(self, operation: str) -> None:
        super().__init__(
            "TOKEN_ENDPOINT_OUTCOME_UNKNOWN",
            "token endpoint outcome is unknown; do not retry this one-time grant",
        )
        self.operation = operation


@dataclass(frozen=True, repr=False)
class OAuthTokenSet:
    """Validated access/refresh tokens with an intentionally redacted repr."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    token_type: str = "Bearer"
    expires_in: int = 0
    scopes: Tuple[str, ...] = ()

    def __repr__(self) -> str:
        return (
            "OAuthTokenSet(access_token=<redacted>, refresh_token=<redacted>, "
            f"token_type={self.token_type!r}, expires_in={self.expires_in!r}, "
            f"scopes={self.scopes!r})"
        )


@dataclass(frozen=True)
class JwtMetadata:
    """Non-token metadata extracted after strict JWT claim validation."""

    algorithm: str
    kid: str
    issuer: str
    audiences: Tuple[str, ...]
    expires_at: int
    scopes: Tuple[str, ...]


class NoRedirectHandler(HTTPRedirectHandler):
    """Return every redirect response without issuing a follow-up request."""

    # Run before urllib's default HTTPRedirectHandler (order 500).
    handler_order = 100

    def http_error_302(
            self, request: Request, response: Any, code: int, message: str,
            headers: Any) -> Any:
        del request, code, message, headers
        return response

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


_SAFE_HANDLER_LIMITS = {
    UnknownHandler: 1,
    HTTPHandler: 1,
    HTTPDefaultErrorHandler: 1,
    HTTPRedirectHandler: 1,
    FTPHandler: 1,
    FileHandler: 1,
    DataHandler: 1,
    HTTPSHandler: 1,
    HTTPCookieProcessor: 1,
    HTTPErrorProcessor: 1,
    NoRedirectHandler: 1,
    ProxyHandler: 1,
}


def install_no_redirect_handler(opener: Any) -> None:
    """Idempotently install redirect interception on an existing opener.

    ``OpenerDirector.add_handler`` keeps all existing handlers, including its
    authenticated ``HTTPCookieProcessor`` and TLS configuration.  The opener
    must not be used concurrently while this one-time installation occurs.
    """

    handlers = _validate_safe_opener(opener)
    existing = [handler for handler in handlers if type(handler) is NoRedirectHandler]
    if existing:
        interceptor = existing[0]
    else:
        interceptor = NoRedirectHandler()
        opener.add_handler(interceptor)
    _validate_safe_opener(opener)
    _assert_redirect_interceptor_first(opener, interceptor)


def _validate_safe_opener(opener: Any) -> list:
    """Reject opener features that can redirect, authenticate, proxy, or dump bodies."""

    if not isinstance(opener, OpenerDirector):
        raise PkceRefreshError(
            "OPENER_CONFIGURATION",
            "OAuth helper requires a standard urllib OpenerDirector",
        )
    handlers = getattr(opener, "handlers", None)
    if not isinstance(handlers, list) or not callable(getattr(opener, "add_handler", None)):
        raise PkceRefreshError(
            "OPENER_CONFIGURATION",
            "authenticated opener does not support safe redirect interception",
        )
    authentication_handlers = (
        HTTPBasicAuthHandler,
        ProxyBasicAuthHandler,
        HTTPDigestAuthHandler,
        ProxyDigestAuthHandler,
    )
    if any(isinstance(handler, authentication_handlers) for handler in handlers):
        raise PkceRefreshError(
            "PUBLIC_CLIENT_AUTH",
            "public-client opener must not contain an HTTP authentication handler",
        )
    counts: Dict[type, int] = {}
    for handler in handlers:
        handler_type = type(handler)
        if handler_type not in _SAFE_HANDLER_LIMITS:
            raise PkceRefreshError(
                "OPENER_CONFIGURATION",
                "OAuth opener contains a non-standard request or response handler",
            )
        counts[handler_type] = counts.get(handler_type, 0) + 1
        if counts[handler_type] > _SAFE_HANDLER_LIMITS[handler_type]:
            raise PkceRefreshError(
                "OPENER_CONFIGURATION", "OAuth opener contains duplicate handlers"
            )
        if handler_type in {HTTPHandler, HTTPSHandler} and getattr(
                handler, "_debuglevel", None) != 0:
            raise PkceRefreshError(
                "OPENER_DEBUG", "OAuth opener HTTP debug output must be disabled"
            )
        if handler_type is ProxyHandler and getattr(handler, "proxies", None) != {}:
            raise PkceRefreshError(
                "OPENER_PROXY", "OAuth opener must explicitly disable proxy routing"
            )
    addheaders = getattr(opener, "addheaders", None)
    if not isinstance(addheaders, list):
        raise PkceRefreshError("OPENER_CONFIGURATION", "OAuth opener headers are invalid")
    for header in addheaders:
        if (
                not isinstance(header, tuple)
                or len(header) != 2
                or not all(isinstance(value, str) for value in header)
                or header[0].casefold() != "user-agent"
                or "\r" in header[1]
                or "\n" in header[1]):
            raise PkceRefreshError(
                "PUBLIC_CLIENT_AUTH",
                "OAuth opener contains an unsafe automatic request header",
            )
    return handlers


def _assert_redirect_interceptor_first(opener: OpenerDirector, interceptor: Any) -> None:
    handle_error = getattr(opener, "handle_error", None)
    http_errors = handle_error.get("http") if isinstance(handle_error, dict) else None
    if not isinstance(http_errors, dict):
        raise PkceRefreshError(
            "OPENER_CONFIGURATION", "OAuth opener HTTP error chain is invalid"
        )
    for status in _REDIRECT_STATUSES:
        chain = http_errors.get(status)
        method = getattr(interceptor, f"http_error_{status}", None)
        expected = getattr(NoRedirectHandler, f"http_error_{status}")
        if (
                not isinstance(chain, list)
                or not chain
                or chain[0] is not interceptor
                or getattr(method, "__func__", None) is not expected):
            raise PkceRefreshError(
                "OPENER_REDIRECT_ORDER",
                "OAuth opener cannot guarantee redirect interception",
            )


def _require_authenticated_cookie_jar(opener: OpenerDirector) -> None:
    processors = [
        handler for handler in opener.handlers
        if type(handler) is HTTPCookieProcessor
    ]
    if len(processors) != 1:
        raise PkceRefreshError(
            "AUTHENTICATED_OPENER",
            "authorization request requires one authenticated in-memory cookie jar",
        )
    cookie_jar = getattr(processors[0], "cookiejar", None)
    try:
        has_cookie = any(True for _cookie in cookie_jar)
    except TypeError:
        has_cookie = False
    if not has_cookie:
        raise PkceRefreshError(
            "AUTHENTICATED_OPENER",
            "authorization request requires a non-empty authenticated cookie jar",
        )


def _require_cookie_free_opener(opener: OpenerDirector) -> None:
    if any(type(handler) is HTTPCookieProcessor for handler in opener.handlers):
        raise PkceRefreshError(
            "TOKEN_COOKIE_TRANSPORT",
            "token endpoint transport must not contain a cookie processor",
        )


def generate_pkce_verifier() -> str:
    """Generate a 64-character RFC 7636 verifier from 384 secure random bits."""

    verifier = _base64url_encode(secrets.token_bytes(48))
    if not 43 <= len(verifier) <= 128 or not _BASE64URL.fullmatch(verifier):
        raise PkceRefreshError("PKCE_GENERATION", "generated PKCE verifier is invalid")
    return verifier


def pkce_s256_challenge(verifier: str) -> str:
    """Derive the RFC 7636 S256 code challenge for a validated verifier."""

    if (
            not isinstance(verifier, str)
            or not 43 <= len(verifier) <= 128
            or not _BASE64URL.fullmatch(verifier)):
        raise PkceRefreshError("PKCE_VERIFIER", "PKCE verifier is invalid")
    return _base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def parse_jwt_header(token: str) -> Dict[str, Any]:
    """Parse a compact JWT protected header without retaining the token."""

    header, _ = _parse_compact_jwt(token)
    return dict(header)


def parse_jwt_claims(token: str) -> Dict[str, Any]:
    """Parse compact JWT claims without retaining the token."""

    _, claims = _parse_compact_jwt(token)
    return dict(claims)


def validate_jwt_metadata(
        token: str,
        *,
        expected_kid: str,
        expected_issuer: str,
        expected_audience: str,
        expected_scopes: Sequence[str],
        minimum_ttl_seconds: int = 1800,
        now: Optional[float] = None,
        expected_algorithm: str = "RS256") -> JwtMetadata:
    """Validate kid, alg, issuer, audience, expiry and scope claims.

    This is intentionally metadata validation, not cryptographic signature
    verification.  No returned value contains the compact access token.
    """

    if not isinstance(minimum_ttl_seconds, int) or isinstance(minimum_ttl_seconds, bool):
        raise PkceRefreshError("JWT_EXPECTATION", "JWT minimum TTL is invalid")
    if minimum_ttl_seconds < 0:
        raise PkceRefreshError("JWT_EXPECTATION", "JWT minimum TTL is invalid")
    expected_scope_tuple = _validate_scopes(expected_scopes, "expected JWT scopes")
    _validate_expected_string(expected_kid, "JWT_EXPECTATION")
    _validate_expected_string(expected_issuer, "JWT_EXPECTATION")
    _validate_expected_string(expected_audience, "JWT_EXPECTATION")
    _validate_expected_string(expected_algorithm, "JWT_EXPECTATION")

    header, claims = _parse_compact_jwt(token)
    algorithm = header.get("alg")
    kid = header.get("kid")
    if not isinstance(algorithm, str) or not _constant_time_equal(
            algorithm, expected_algorithm):
        raise PkceRefreshError("JWT_ALGORITHM", "JWT signing algorithm is not expected")
    if not isinstance(kid, str) or not _constant_time_equal(kid, expected_kid):
        raise PkceRefreshError("JWT_KID", "JWT signing key identifier is not expected")

    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not _constant_time_equal(issuer, expected_issuer):
        raise PkceRefreshError("JWT_ISSUER", "JWT issuer is not expected")

    audiences = _jwt_audiences(claims.get("aud"))
    if len(audiences) != 1 or not _constant_time_equal(audiences[0], expected_audience):
        raise PkceRefreshError("JWT_AUDIENCE", "JWT audience is not expected")

    expires_at = claims.get("exp")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        raise PkceRefreshError("JWT_EXPIRY", "JWT expiry claim is invalid")
    observed_now = _validation_time(now)
    if expires_at - float(observed_now) < minimum_ttl_seconds:
        raise PkceRefreshError("JWT_EXPIRY", "JWT remaining lifetime is insufficient")

    scopes = _parse_jwt_scopes(claims.get("scope"))
    if frozenset(scopes) != frozenset(expected_scope_tuple):
        raise PkceRefreshError("JWT_SCOPE", "JWT scopes are not expected")

    return JwtMetadata(
        algorithm=algorithm,
        kid=kid,
        issuer=issuer,
        audiences=audiences,
        expires_at=expires_at,
        scopes=scopes,
    )


def authorization_code_pkce_once(
        opener: Any,
        *,
        token_opener: Any,
        authorization_endpoint: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str,
        scopes: Sequence[str],
        expected_kid: str,
        expected_issuer: str,
        expected_audience: str,
        minimum_ttl_seconds: int = 1800,
        timeout: float = 20.0,
        now: Optional[float] = None) -> OAuthTokenSet:
    """Perform one authorization-code + PKCE S256 exchange without redirects.

    The authorization code, verifier and state stay in local variables and are
    discarded before the validated token set is returned.  The token POST is
    attempted exactly once; an ambiguous network outcome is never retried.
    """

    install_no_redirect_handler(opener)
    _require_authenticated_cookie_jar(opener)
    install_no_redirect_handler(token_opener)
    _require_cookie_free_opener(token_opener)
    _validate_timeout(timeout)
    authorization = _validate_endpoint(authorization_endpoint, "authorization endpoint")
    token = _validate_endpoint(token_endpoint, "token endpoint")
    issuer = _validate_issuer(expected_issuer)
    if _origin(authorization) != _origin(issuer) or _origin(token) != _origin(issuer):
        raise PkceRefreshError(
            "ENDPOINT_ORIGIN", "OAuth endpoints do not match the expected issuer origin"
        )
    redirect = _validate_redirect_uri(redirect_uri)
    _validate_client_id(client_id)
    scope_tuple = _validate_scopes(scopes, "authorization scopes")

    verifier = generate_pkce_verifier()
    challenge = pkce_s256_challenge(verifier)
    state = _base64url_encode(secrets.token_bytes(32))
    if len(state) != 43 or not _BASE64URL.fullmatch(state):
        raise PkceRefreshError("STATE_GENERATION", "generated OAuth state is invalid")

    authorize_query = urlencode((
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", " ".join(scope_tuple)),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ))
    request = Request(
        authorization_endpoint + "?" + authorize_query,
        headers={"Accept": "text/html,application/xhtml+xml"},
        method="GET",
    )
    response = _open_once(opener, request, timeout, operation="authorization")
    try:
        status = _response_status(response)
        location = _single_header(response.headers, "Location", required=True)
    finally:
        _close_response(response)
    if status != 302:
        raise PkceRefreshError(
            "AUTHORIZATION_STATUS", "authorization endpoint did not return HTTP 302"
        )
    code = _validate_authorization_redirect(location, redirect, state)

    body = urlencode((
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code", code),
        ("code_verifier", verifier),
    )).encode("ascii")
    document = _post_token_form_once(
        token_opener, token_endpoint, body, timeout, operation="authorization_code"
    )
    token_set = _validate_token_document(document, scope_tuple)
    validation_time = _validation_time(now)
    metadata = validate_jwt_metadata(
        token_set.access_token,
        expected_kid=expected_kid,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        expected_scopes=scope_tuple,
        minimum_ttl_seconds=minimum_ttl_seconds,
        now=validation_time,
    )
    _validate_token_lifetime(token_set, metadata, validation_time, minimum_ttl_seconds)
    return token_set


def refresh_token_once(
        opener: Any,
        *,
        token_endpoint: str,
        client_id: str,
        refresh_token: str,
        expected_kid: str,
        expected_issuer: str,
        expected_audience: str,
        expected_scopes: Sequence[str],
        minimum_ttl_seconds: int = 1800,
        timeout: float = 20.0,
        now: Optional[float] = None) -> OAuthTokenSet:
    """Submit one public-client refresh grant and require token rotation.

    There is deliberately no retry loop.  A network exception becomes
    ``TokenEndpointOutcomeUnknown(retry_safe=False)`` because the old refresh
    token may already have been consumed.
    """

    install_no_redirect_handler(opener)
    _require_cookie_free_opener(opener)
    _validate_timeout(timeout)
    token = _validate_endpoint(token_endpoint, "token endpoint")
    issuer = _validate_issuer(expected_issuer)
    if _origin(token) != _origin(issuer):
        raise PkceRefreshError(
            "ENDPOINT_ORIGIN", "token endpoint does not match the expected issuer origin"
        )
    _validate_client_id(client_id)
    _validate_refresh_token(refresh_token)
    scope_tuple = _validate_scopes(expected_scopes, "expected refresh scopes")

    body = urlencode((
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    )).encode("ascii")
    document = _post_token_form_once(
        opener, token_endpoint, body, timeout, operation="refresh_token"
    )
    token_set = _validate_token_document(document, scope_tuple)
    if hmac.compare_digest(token_set.refresh_token, refresh_token):
        raise PkceRefreshError("REFRESH_ROTATION", "refresh token was not rotated")
    validation_time = _validation_time(now)
    metadata = validate_jwt_metadata(
        token_set.access_token,
        expected_kid=expected_kid,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        expected_scopes=scope_tuple,
        minimum_ttl_seconds=minimum_ttl_seconds,
        now=validation_time,
    )
    _validate_token_lifetime(token_set, metadata, validation_time, minimum_ttl_seconds)
    return token_set


def expect_refresh_invalid_grant_once(
        opener: Any,
        *,
        token_endpoint: str,
        client_id: str,
        refresh_token: str,
        expected_issuer: str,
        timeout: float = 20.0) -> None:
    """Submit one replay probe and require an exact OAuth ``invalid_grant``."""

    install_no_redirect_handler(opener)
    _require_cookie_free_opener(opener)
    _validate_timeout(timeout)
    token = _validate_endpoint(token_endpoint, "token endpoint")
    issuer = _validate_issuer(expected_issuer)
    if _origin(token) != _origin(issuer):
        raise PkceRefreshError(
            "ENDPOINT_ORIGIN", "token endpoint does not match the expected issuer origin"
        )
    _validate_client_id(client_id)
    _validate_refresh_token(refresh_token)
    body = urlencode((
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    )).encode("ascii")
    request = _token_request(token_endpoint, body)
    response = _open_once(opener, request, timeout, operation="refresh_token_replay")
    status, payload, headers = _consume_token_response_once(
        response, operation="refresh_token_replay"
    )
    _require_json_content_type(headers)
    if status != 400:
        raise PkceRefreshError(
            "REFRESH_REPLAY_STATUS", "refresh replay did not return HTTP 400"
        )
    document = _parse_json_object(payload, "refresh replay response")
    if not set(document).issubset(_ERROR_FIELDS) or document.get("error") != "invalid_grant":
        raise PkceRefreshError(
            "REFRESH_REPLAY_ERROR", "refresh replay did not return invalid_grant"
        )
    if any(field in document for field in _TOKEN_FIELDS):
        raise PkceRefreshError(
            "REFRESH_REPLAY_TOKEN", "refresh replay response contained token fields"
        )


def _base64url_encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _constant_time_equal(left: str, right: str) -> bool:
    try:
        return hmac.compare_digest(left, right)
    except (TypeError, UnicodeEncodeError):
        return False


def _validation_time(now: Optional[float]) -> float:
    observed = time.time() if now is None else now
    if not isinstance(observed, (int, float)) or isinstance(observed, bool):
        raise PkceRefreshError("JWT_EXPECTATION", "JWT validation time is invalid")
    return float(observed)


def _validate_token_lifetime(
        token_set: OAuthTokenSet,
        metadata: JwtMetadata,
        observed_now: float,
        minimum_ttl_seconds: int) -> None:
    remaining = metadata.expires_at - observed_now
    if token_set.expires_in < minimum_ttl_seconds:
        raise PkceRefreshError(
            "TOKEN_EXPIRY", "token response lifetime is shorter than required"
        )
    if abs(remaining - token_set.expires_in) > _TOKEN_LIFETIME_TOLERANCE_SECONDS:
        raise PkceRefreshError(
            "TOKEN_EXPIRY", "token response lifetime contradicts JWT expiry"
        )


def _base64url_json(segment: str, label: str) -> Mapping[str, Any]:
    if (
            not isinstance(segment, str)
            or not segment
            or len(segment) > _MAX_JWT_SEGMENT_BYTES
            or "=" in segment
            or not _BASE64URL.fullmatch(segment)):
        raise PkceRefreshError("JWT_FORMAT", f"JWT {label} segment is invalid")
    try:
        payload = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError):
        raise PkceRefreshError("JWT_FORMAT", f"JWT {label} segment is invalid") from None
    return _parse_json_object(payload, f"JWT {label}")


def _parse_compact_jwt(token: str) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(token, str) or len(token) > 32 * 1024:
        raise PkceRefreshError("JWT_FORMAT", "access token is not a compact JWT")
    segments = token.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        raise PkceRefreshError("JWT_FORMAT", "access token is not a compact JWT")
    if "=" in segments[2] or not _BASE64URL.fullmatch(segments[2]):
        raise PkceRefreshError("JWT_FORMAT", "JWT signature segment is invalid")
    header = _base64url_json(segments[0], "header")
    claims = _base64url_json(segments[1], "claims")
    return header, claims


def _parse_json_object(payload: bytes, label: str) -> Dict[str, Any]:
    class DuplicateKey(ValueError):
        pass

    def object_pairs(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateKey()
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError()

    try:
        text = payload.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey, ValueError):
        raise PkceRefreshError("JSON_RESPONSE", f"{label} is not strict JSON") from None
    if not isinstance(document, dict):
        raise PkceRefreshError("JSON_RESPONSE", f"{label} is not a JSON object")
    return document


def _validate_expected_string(value: Any, code: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise PkceRefreshError(code, "OAuth expectation is invalid")


def _validate_client_id(client_id: str) -> None:
    if (
            not isinstance(client_id, str)
            or not 1 <= len(client_id) <= 255
            or any(ord(character) < 0x21 or ord(character) > 0x7e for character in client_id)):
        raise PkceRefreshError("CLIENT_ID", "OAuth public client identifier is invalid")


def _validate_refresh_token(refresh_token: str) -> None:
    if (
            not isinstance(refresh_token, str)
            or not 32 <= len(refresh_token) <= 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7e for character in refresh_token)):
        raise PkceRefreshError("REFRESH_TOKEN", "refresh token input is invalid")


def _validate_scopes(scopes: Sequence[str], label: str) -> Tuple[str, ...]:
    if isinstance(scopes, (str, bytes)):
        raise PkceRefreshError("SCOPE", f"{label} are invalid")
    try:
        values = tuple(scopes)
    except TypeError:
        raise PkceRefreshError("SCOPE", f"{label} are invalid") from None
    if not values or len(values) > 64 or any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 255
            or not _SCOPE_TOKEN.fullmatch(value)
            for value in values):
        raise PkceRefreshError("SCOPE", f"{label} are invalid")
    if len(set(values)) != len(values):
        raise PkceRefreshError("SCOPE", f"{label} are invalid")
    return values


def _parse_scope_claim(value: Any, label: str) -> Tuple[str, ...]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PkceRefreshError("JWT_SCOPE", f"{label} is invalid")
    values = tuple(value.split(" "))
    if " ".join(values) != value:
        raise PkceRefreshError("JWT_SCOPE", f"{label} is invalid")
    return _validate_scopes(values, label)


def _parse_jwt_scopes(value: Any) -> Tuple[str, ...]:
    # Spring Authorization Server encodes authorized scopes as a JSON array;
    # RFC 9068 access tokens can also use a space-delimited string.
    if isinstance(value, list):
        return _validate_scopes(value, "JWT scope claim")
    return _parse_scope_claim(value, "JWT scope claim")


def _jwt_audiences(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        audiences = (value,)
    elif isinstance(value, list):
        audiences = tuple(value)
    else:
        raise PkceRefreshError("JWT_AUDIENCE", "JWT audience claim is invalid")
    if not audiences or any(not isinstance(item, str) or not item for item in audiences):
        raise PkceRefreshError("JWT_AUDIENCE", "JWT audience claim is invalid")
    if len(set(audiences)) != len(audiences):
        raise PkceRefreshError("JWT_AUDIENCE", "JWT audience claim is invalid")
    return audiences


def _validate_url_common(url: str, label: str) -> Any:
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise PkceRefreshError("URL", f"{label} is invalid")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise PkceRefreshError("URL", f"{label} is invalid") from None
    hostname = parsed.hostname
    if (
            parsed.scheme.lower() != "https"
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or port is not None and not 1 <= port <= 65535
            or parsed.path and not parsed.path.startswith("/")
            or "\\" in parsed.path):
        raise PkceRefreshError("URL", f"{label} is invalid")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        raise PkceRefreshError("URL", f"{label} is invalid") from None
    return parsed


def _validate_endpoint(url: str, label: str) -> Any:
    parsed = _validate_url_common(url, label)
    if not parsed.path or parsed.query or parsed.fragment or parsed.params:
        raise PkceRefreshError("URL", f"{label} is invalid")
    return parsed


def _validate_issuer(url: str) -> Any:
    parsed = _validate_url_common(url, "expected issuer")
    if parsed.query or parsed.fragment or parsed.params:
        raise PkceRefreshError("URL", "expected issuer is invalid")
    return parsed


def _validate_redirect_uri(url: str) -> Any:
    parsed = _validate_url_common(url, "redirect URI")
    if not parsed.path or parsed.query or parsed.fragment or parsed.params:
        raise PkceRefreshError("REDIRECT_URI", "redirect URI is invalid")
    return parsed


def _origin(parsed: Any) -> Tuple[str, str, int]:
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or default_port


def _validate_timeout(timeout: float) -> None:
    if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout <= 0
            or timeout > 120):
        raise PkceRefreshError("TIMEOUT", "OAuth request timeout is invalid")


def _validate_authorization_redirect(location: str, redirect: Any, state: str) -> str:
    if _INVALID_PERCENT_ESCAPE.search(location):
        raise PkceRefreshError(
            "AUTHORIZATION_REDIRECT", "authorization redirect encoding is invalid"
        )
    returned = _validate_url_common(location, "authorization redirect")
    if returned.fragment or returned.params:
        raise PkceRefreshError(
            "AUTHORIZATION_REDIRECT", "authorization redirect target is invalid"
        )
    if _origin(returned) != _origin(redirect) or returned.path != redirect.path:
        raise PkceRefreshError(
            "AUTHORIZATION_REDIRECT", "authorization redirect target is invalid"
        )
    try:
        pairs = parse_qsl(
            returned.query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=8,
        )
    except (ValueError, UnicodeDecodeError):
        raise PkceRefreshError(
            "AUTHORIZATION_REDIRECT", "authorization redirect query is invalid"
        ) from None
    keys = [key for key, _value in pairs]
    if len(keys) != len(set(keys)):
        raise PkceRefreshError(
            "AUTHORIZATION_REDIRECT", "authorization redirect has duplicate parameters"
        )
    parameters = dict(pairs)
    returned_state = parameters.get("state")
    if not isinstance(returned_state, str) or not _constant_time_equal(returned_state, state):
        raise PkceRefreshError("AUTHORIZATION_STATE", "authorization state does not match")
    if "error" in parameters:
        allowed_error_fields = {"error", "error_description", "error_uri", "state"}
        error_code = parameters.get("error")
        if (
                not set(parameters).issubset(allowed_error_fields)
                or not isinstance(error_code, str)
                or not _SCOPE_TOKEN.fullmatch(error_code)):
            raise PkceRefreshError(
                "AUTHORIZATION_REDIRECT", "authorization error response is invalid"
            )
        raise PkceRefreshError(
            "AUTHORIZATION_ERROR", "authorization server returned an OAuth error"
        )
    if set(parameters) != {"code", "state"}:
        raise PkceRefreshError(
            "AUTHORIZATION_REDIRECT", "authorization redirect parameters are invalid"
        )
    code = parameters["code"]
    if not _OPAQUE_CODE.fullmatch(code):
        raise PkceRefreshError("AUTHORIZATION_CODE", "authorization code is invalid")
    return code


def _single_header(headers: Any, name: str, *, required: bool) -> Optional[str]:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = list(get_all(name) or [])
    elif isinstance(headers, Mapping):
        values = []
        for key, value in headers.items():
            if str(key).lower() != name.lower():
                continue
            if isinstance(value, (list, tuple)):
                values.extend(value)
            else:
                values.append(value)
    else:
        raise PkceRefreshError("HTTP_HEADERS", "OAuth response headers are invalid")
    if len(values) > 1 or required and len(values) != 1:
        raise PkceRefreshError("HTTP_HEADERS", f"OAuth response {name} header is invalid")
    if not values:
        return None
    value = values[0]
    if not isinstance(value, str) or not value or "\r" in value or "\n" in value:
        raise PkceRefreshError("HTTP_HEADERS", f"OAuth response {name} header is invalid")
    return value


def _require_json_content_type(headers: Any) -> None:
    content_type = _single_header(headers, "Content-Type", required=True)
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise PkceRefreshError(
            "TOKEN_CONTENT_TYPE", "token endpoint did not return application/json"
        )


def _response_status(response: Any) -> int:
    status = getattr(response, "status", None)
    if status is None:
        getcode = getattr(response, "getcode", None)
        status = getcode() if callable(getcode) else None
    if not isinstance(status, int) or isinstance(status, bool):
        raise PkceRefreshError("HTTP_STATUS", "OAuth response status is invalid")
    return status


def _read_limited(response: Any, limit: int) -> bytes:
    payload = response.read(limit + 1)
    if not isinstance(payload, bytes) or len(payload) > limit:
        raise PkceRefreshError("HTTP_BODY", "OAuth response body is invalid or too large")
    return payload


def _close_response(response: Any) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        close()


def _open_once(opener: Any, request: Request, timeout: float, *, operation: str) -> Any:
    try:
        return opener.open(request, timeout=timeout)
    except HTTPError as error:
        # HTTPError is also the response body and is needed for OAuth 400 and
        # for test/openers that surface a captured 302 as an exception.
        return error
    except (URLError, TimeoutError, ConnectionError, OSError, HTTPException):
        if operation in {"authorization_code", "refresh_token", "refresh_token_replay"}:
            raise TokenEndpointOutcomeUnknown(operation) from None
        raise PkceRefreshError(
            "AUTHORIZATION_NETWORK", "authorization request failed before a response"
        ) from None


def _token_request(token_endpoint: str, body: bytes) -> Request:
    request = Request(
        token_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Cache-Control": "no-store",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    if request.has_header("Authorization") or request.has_header("Cookie"):
        raise PkceRefreshError(
            "PUBLIC_CLIENT_AUTH", "public-client token request used a credential header"
        )
    return request


def _post_token_form_once(
        opener: Any, token_endpoint: str, body: bytes, timeout: float, *, operation: str
        ) -> Dict[str, Any]:
    request = _token_request(token_endpoint, body)
    response = _open_once(opener, request, timeout, operation=operation)
    status, payload, headers = _consume_token_response_once(response, operation=operation)
    _require_json_content_type(headers)
    if status != 200:
        raise PkceRefreshError("TOKEN_STATUS", "token endpoint did not return HTTP 200")
    return _parse_json_object(payload, "token response")


def _consume_token_response_once(
        response: Any, *, operation: str) -> Tuple[int, bytes, Any]:
    try:
        status = _response_status(response)
        payload = _read_limited(response, _MAX_JSON_BYTES)
        headers = response.headers
        return status, payload, headers
    except (URLError, TimeoutError, ConnectionError, OSError, HTTPException):
        raise TokenEndpointOutcomeUnknown(operation) from None
    finally:
        _close_response(response)


def _validate_token_document(
        document: Mapping[str, Any], expected_scopes: Sequence[str]) -> OAuthTokenSet:
    if set(document) != _TOKEN_FIELDS:
        raise PkceRefreshError("TOKEN_RESPONSE", "token response fields are invalid")
    access_token = document.get("access_token")
    refresh_token = document.get("refresh_token")
    token_type = document.get("token_type")
    expires_in = document.get("expires_in")
    if (
            not isinstance(access_token, str)
            or not 20 <= len(access_token) <= 32 * 1024
            or not isinstance(refresh_token, str)
            or not 32 <= len(refresh_token) <= 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7e for character in refresh_token)
            or hmac.compare_digest(access_token, refresh_token)):
        raise PkceRefreshError("TOKEN_RESPONSE", "token response credentials are invalid")
    if not isinstance(token_type, str) or token_type.casefold() != "bearer":
        raise PkceRefreshError("TOKEN_TYPE", "token response type is not Bearer")
    if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 1 <= expires_in <= 24 * 60 * 60):
        raise PkceRefreshError("TOKEN_EXPIRY", "token response lifetime is invalid")
    scopes = _parse_scope_claim(document.get("scope"), "token response scope")
    if frozenset(scopes) != frozenset(expected_scopes):
        raise PkceRefreshError("TOKEN_SCOPE", "token response scopes are not expected")
    return OAuthTokenSet(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=expires_in,
        scopes=scopes,
    )
