from __future__ import annotations

import base64
from email.message import Message
import hashlib
import hmac
from http.cookiejar import Cookie, CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from typing import Any, Callable, List, Optional, Sequence, Union
import unittest
from unittest.mock import patch
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse
from urllib.request import (
    HTTPBasicAuthHandler,
    HTTPRedirectHandler,
    HTTPCookieProcessor,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    build_opener,
)

import scripts.v1_upgrade_refresh as refresh


ISSUER = "https://upgrade.example.test:18443"
AUTHORIZE = ISSUER + "/oauth2/authorize"
TOKEN = ISSUER + "/oauth2/token"
REDIRECT = ISSUER + "/login"
AUDIENCE = ISSUER + "/mcp"
CLIENT_ID = "upgrade-pkce-client"
KID_V1 = "v1-signing-key"
KID_V2 = "v2-signing-key"
SCOPES = ("system:info", "project:list")
NOW = 1_800_000_000
OLD_REFRESH = "R" * 128
NEW_REFRESH = "N" * 128
NEXT_REFRESH = "X" * 128


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _jwt(
        *,
        kid: str = KID_V1,
        issuer: str = ISSUER,
        audience: Any = AUDIENCE,
        expires_at: Any = NOW + 7200,
        scopes: Any = "system:info project:list",
        algorithm: str = "RS256") -> str:
    header = json.dumps(
        {"alg": algorithm, "kid": kid, "typ": "JWT"},
        separators=(",", ":"),
    ).encode("utf-8")
    claims = json.dumps(
        {
            "iss": issuer,
            "aud": audience,
            "exp": expires_at,
            "scope": scopes,
            "sub": "upgrade-user",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{_b64(header)}.{_b64(claims)}.{_b64(b'test-signature')}"


def _token_document(
        *,
        access_token: Optional[str] = None,
        refresh_token: str = NEW_REFRESH,
        token_type: Any = "Bearer",
        expires_in: Any = 7199,
        scope: Any = "system:info project:list") -> dict:
    return {
        "access_token": access_token or _jwt(),
        "refresh_token": refresh_token,
        "token_type": token_type,
        "expires_in": expires_in,
        "scope": scope,
    }


def _json_bytes(document: Any) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class FakeResponse:
    def __init__(
            self,
            status: int,
            body: bytes = b"",
            headers: Sequence[tuple] = ()) -> None:
        self.status = status
        self._body = io.BytesIO(body)
        self.headers = Message()
        for name, value in headers:
            self.headers.add_header(name, value)
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def close(self) -> None:
        self.closed = True

    def getcode(self) -> int:
        return self.status


class FailingReadResponse(FakeResponse):
    def read(self, size: int = -1) -> bytes:
        del size
        raise TimeoutError("connection lost while reading response")


ScriptItem = Union[
    FakeResponse,
    BaseException,
    Callable[[Any], FakeResponse],
]


def _authenticated_cookie_jar() -> CookieJar:
    cookies = CookieJar()
    cookies.set_cookie(Cookie(
        version=0,
        name="WEB_STARTER_SESSION",
        value="test-session-cookie",
        port=None,
        port_specified=False,
        domain="upgrade.example.test",
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=True,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None},
        rfc2109=False,
    ))
    return cookies


class FakeAuthenticatedOpener(OpenerDirector):
    """Small opener that would follow redirects unless the helper intercepts."""

    def __init__(self, script: Sequence[ScriptItem]) -> None:
        super().__init__()
        self.script: List[ScriptItem] = list(script)
        self.requests: list = []
        self.timeouts: list = []
        self.callback_requests = 0
        template = build_opener(
            ProxyHandler({}),
            HTTPCookieProcessor(_authenticated_cookie_jar()),
        )
        self.addheaders = list(template.addheaders)
        for handler in template.handlers:
            self.add_handler(handler)

    def open(self, request: Any, timeout: float = 0) -> FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if not self.script:
            raise AssertionError("unexpected network call")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        response = item(request) if callable(item) else item
        if 300 <= response.status < 400 and not any(
                isinstance(handler, refresh.NoRedirectHandler) for handler in self.handlers):
            self.callback_requests += 1
            raise AssertionError("redirect would have been followed")
        return response


class FakeTokenOpener(FakeAuthenticatedOpener):
    """Scripted transport with proxy routing disabled and no cookie processor."""

    def __init__(self, script: Sequence[ScriptItem]) -> None:
        OpenerDirector.__init__(self)
        self.script = list(script)
        self.requests = []
        self.timeouts = []
        self.callback_requests = 0
        template = build_opener(ProxyHandler({}))
        self.addheaders = list(template.addheaders)
        for handler in template.handlers:
            self.add_handler(handler)


def _redirect_for_request(request: Any, *, code: str = "A" * 48) -> FakeResponse:
    parameters = dict(parse_qsl(urlparse(request.full_url).query, keep_blank_values=True))
    location = REDIRECT + "?" + urlencode({"code": code, "state": parameters["state"]})
    return FakeResponse(302, headers=(("Location", location),))


def _success_token_response(
        *,
        kid: str = KID_V1,
        refresh_token: str = NEW_REFRESH) -> FakeResponse:
    return FakeResponse(
        200,
        _json_bytes(_token_document(
            access_token=_jwt(kid=kid),
            refresh_token=refresh_token,
        )),
        (("Content-Type", "application/json;charset=UTF-8"),),
    )


class PkceAuthorizationFlowTest(unittest.TestCase):
    def test_secure_verifier_and_rfc7636_s256_challenge(self) -> None:
        random_bytes = bytes(range(48))
        with patch.object(refresh.secrets, "token_bytes", return_value=random_bytes) as secure:
            verifier = refresh.generate_pkce_verifier()
        self.assertEqual(_b64(random_bytes), verifier)
        self.assertEqual(64, len(verifier))
        self.assertRegex(verifier, r"^[A-Za-z0-9_-]+$")
        self.assertEqual(
            _b64(hashlib.sha256(verifier.encode("ascii")).digest()),
            refresh.pkce_s256_challenge(verifier),
        )
        secure.assert_called_once_with(48)

    def test_reuses_authenticated_opener_intercepts_302_and_posts_exact_public_form(self) -> None:
        verifier_bytes = b"v" * 48
        state_bytes = b"s" * 32

        def token_response(request: Any) -> FakeResponse:
            self.assertEqual("POST", request.get_method())
            fields = parse_qsl(request.data.decode("ascii"), keep_blank_values=True)
            self.assertEqual(
                [
                    ("grant_type", "authorization_code"),
                    ("client_id", CLIENT_ID),
                    ("redirect_uri", REDIRECT),
                    ("code", "A" * 48),
                    ("code_verifier", _b64(verifier_bytes)),
                ],
                fields,
            )
            self.assertNotIn(b"client_secret", request.data)
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(
                "application/x-www-form-urlencoded",
                request.get_header("Content-type"),
            )
            return _success_token_response()

        opener = FakeAuthenticatedOpener((_redirect_for_request,))
        token_opener = FakeTokenOpener((token_response,))
        original_handler = opener.handlers[0]
        with patch.object(
                refresh.secrets, "token_bytes", side_effect=(verifier_bytes, state_bytes)):
            tokens = refresh.authorization_code_pkce_once(
                opener,
                token_opener=token_opener,
                authorization_endpoint=AUTHORIZE,
                token_endpoint=TOKEN,
                client_id=CLIENT_ID,
                redirect_uri=REDIRECT,
                scopes=SCOPES,
                expected_kid=KID_V1,
                expected_issuer=ISSUER,
                expected_audience=AUDIENCE,
                now=NOW,
            )

        self.assertEqual(1, len(opener.requests))
        self.assertEqual(1, len(token_opener.requests))
        self.assertEqual(0, opener.callback_requests)
        self.assertIn(original_handler, opener.handlers)
        self.assertEqual(1, sum(
            isinstance(handler, refresh.NoRedirectHandler) for handler in opener.handlers
        ))
        authorize_request = opener.requests[0]
        self.assertEqual("GET", authorize_request.get_method())
        parameters = parse_qsl(urlparse(authorize_request.full_url).query)
        self.assertEqual(
            [
                ("response_type", "code"),
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT),
                ("scope", "system:info project:list"),
                ("state", _b64(state_bytes)),
                (
                    "code_challenge",
                    _b64(hashlib.sha256(_b64(verifier_bytes).encode("ascii")).digest()),
                ),
                ("code_challenge_method", "S256"),
            ],
            parameters,
        )
        self.assertIsNone(authorize_request.get_header("Authorization"))
        self.assertIsNone(token_opener.requests[0].get_header("Cookie"))
        self.assertEqual(_jwt(), tokens.access_token)
        self.assertEqual(NEW_REFRESH, tokens.refresh_token)
        self.assertNotIn(tokens.access_token, repr(tokens))
        self.assertNotIn(tokens.refresh_token, repr(tokens))

        # Installation is idempotent and does not replace the cookie/TLS handlers.
        refresh.install_no_redirect_handler(opener)
        self.assertEqual(1, sum(
            isinstance(handler, refresh.NoRedirectHandler) for handler in opener.handlers
        ))

    def test_redirect_state_uses_constant_time_comparison(self) -> None:
        expected = "e" * 43
        returned = "r" * 43
        location = REDIRECT + "?" + urlencode({"code": "A" * 48, "state": returned})
        redirect = urlparse(REDIRECT)
        with patch.object(
                refresh.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            with self.assertRaises(refresh.PkceRefreshError) as error:
                refresh._validate_authorization_redirect(location, redirect, expected)
        self.assertEqual("AUTHORIZATION_STATE", error.exception.code)
        compare.assert_called_once_with(returned, expected)

        non_ascii = REDIRECT + "?" + urlencode({
            "code": "A" * 48,
            "state": "状态",
        })
        with self.assertRaises(refresh.PkceRefreshError) as unicode_error:
            refresh._validate_authorization_redirect(non_ascii, redirect, expected)
        self.assertEqual("AUTHORIZATION_STATE", unicode_error.exception.code)

    def test_rejects_adversarial_redirect_targets_parameters_and_statuses(self) -> None:
        state = "s" * 43
        code = "A" * 48
        cases = {
            "other-origin": "https://evil.example.test/login?" + urlencode({
                "code": code, "state": state,
            }),
            "userinfo": "https://user@upgrade.example.test:18443/login?" + urlencode({
                "code": code, "state": state,
            }),
            "other-path": ISSUER + "/callback?" + urlencode({"code": code, "state": state}),
            "fragment": REDIRECT + "?" + urlencode({"code": code, "state": state}) + "#leak",
            "duplicate-code": REDIRECT + f"?code={code}&code={code}&state={state}",
            "duplicate-state": REDIRECT + f"?code={code}&state={state}&state={state}",
            "oauth-error": REDIRECT + "?" + urlencode({
                "error": "access_denied", "state": state,
            }),
            "oauth-error-wrong-state": REDIRECT + "?" + urlencode({
                "error": "access_denied", "state": "w" * 43,
            }),
            "extra-parameter": REDIRECT + "?" + urlencode({
                "code": code, "state": state, "iss": ISSUER,
            }),
            "blank-code": REDIRECT + "?" + urlencode({"code": "", "state": state}),
            "invalid-percent": REDIRECT + f"?code={code}&state=%GG",
        }
        for label, location in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(refresh.PkceRefreshError):
                    refresh._validate_authorization_redirect(
                        location, urlparse(REDIRECT), state
                    )

        opener = FakeAuthenticatedOpener((
            FakeResponse(307, headers=(("Location", REDIRECT),)),
        ))
        with patch.object(
                refresh.secrets, "token_bytes", side_effect=(b"v" * 48, b"s" * 32)):
            with self.assertRaises(refresh.PkceRefreshError) as status_error:
                refresh.authorization_code_pkce_once(
                    opener,
                    token_opener=FakeTokenOpener(()),
                    authorization_endpoint=AUTHORIZE,
                    token_endpoint=TOKEN,
                    client_id=CLIENT_ID,
                    redirect_uri=REDIRECT,
                    scopes=SCOPES,
                    expected_kid=KID_V1,
                    expected_issuer=ISSUER,
                    expected_audience=AUDIENCE,
                    now=NOW,
                )
        self.assertEqual("AUTHORIZATION_STATUS", status_error.exception.code)
        self.assertEqual(1, len(opener.requests))
        self.assertEqual(0, opener.callback_requests)

    def test_rejects_duplicate_or_missing_location_without_token_post(self) -> None:
        responses = (
            FakeResponse(302, headers=()),
            FakeResponse(302, headers=(
                ("Location", REDIRECT + "?code=a&state=b"),
                ("Location", REDIRECT + "?code=c&state=d"),
            )),
        )
        for response in responses:
            with self.subTest(headers=list(response.headers.items())):
                opener = FakeAuthenticatedOpener((response,))
                with patch.object(
                        refresh.secrets, "token_bytes",
                        side_effect=(b"v" * 48, b"s" * 32)):
                    with self.assertRaises(refresh.PkceRefreshError) as error:
                        refresh.authorization_code_pkce_once(
                            opener,
                            token_opener=FakeTokenOpener(()),
                            authorization_endpoint=AUTHORIZE,
                            token_endpoint=TOKEN,
                            client_id=CLIENT_ID,
                            redirect_uri=REDIRECT,
                            scopes=SCOPES,
                            expected_kid=KID_V1,
                            expected_issuer=ISSUER,
                            expected_audience=AUDIENCE,
                            now=NOW,
                        )
                self.assertEqual("HTTP_HEADERS", error.exception.code)
                self.assertEqual(1, len(opener.requests))

    def test_rejects_insecure_or_cross_origin_configuration_before_network(self) -> None:
        configurations = (
            {"authorization_endpoint": "http://upgrade.example.test/oauth2/authorize"},
            {"token_endpoint": "https://other.example.test/oauth2/token"},
            {"redirect_uri": REDIRECT + "?preexisting=true"},
            {"authorization_endpoint": "https://user@upgrade.example.test/oauth2/authorize"},
        )
        for override in configurations:
            with self.subTest(override=override):
                arguments = {
                    "token_opener": FakeTokenOpener(()),
                    "authorization_endpoint": AUTHORIZE,
                    "token_endpoint": TOKEN,
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT,
                    "scopes": SCOPES,
                    "expected_kid": KID_V1,
                    "expected_issuer": ISSUER,
                    "expected_audience": AUDIENCE,
                    "now": NOW,
                }
                arguments.update(override)
                opener = FakeAuthenticatedOpener(())
                with self.assertRaises(refresh.PkceRefreshError):
                    refresh.authorization_code_pkce_once(opener, **arguments)
                self.assertEqual([], opener.requests)


class JwtMetadataValidationTest(unittest.TestCase):
    def test_parses_and_validates_expected_metadata_without_returning_token(self) -> None:
        token = _jwt()
        self.assertEqual(KID_V1, refresh.parse_jwt_header(token)["kid"])
        self.assertEqual(ISSUER, refresh.parse_jwt_claims(token)["iss"])
        metadata = refresh.validate_jwt_metadata(
            token,
            expected_kid=KID_V1,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            expected_scopes=SCOPES,
            now=NOW,
        )
        self.assertEqual("RS256", metadata.algorithm)
        self.assertEqual(KID_V1, metadata.kid)
        self.assertEqual((AUDIENCE,), metadata.audiences)
        self.assertEqual(NOW + 7200, metadata.expires_at)
        self.assertEqual(SCOPES, metadata.scopes)
        self.assertNotIn(token, repr(metadata))

        spring_array = refresh.validate_jwt_metadata(
            _jwt(scopes=list(SCOPES)),
            expected_kid=KID_V1,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            expected_scopes=SCOPES,
            now=NOW,
        )
        self.assertEqual(SCOPES, spring_array.scopes)

    def test_rejects_wrong_algorithm_kid_issuer_audience_expiry_and_scope(self) -> None:
        cases = (
            ("algorithm", _jwt(algorithm="none"), "JWT_ALGORITHM"),
            ("kid", _jwt(kid=KID_V2), "JWT_KID"),
            ("issuer", _jwt(issuer="https://other.example.test"), "JWT_ISSUER"),
            ("audience", _jwt(audience="https://other.example.test/mcp"), "JWT_AUDIENCE"),
            ("extra-audience", _jwt(audience=[AUDIENCE, "extra"]), "JWT_AUDIENCE"),
            ("expiry", _jwt(expires_at=NOW + 1799), "JWT_EXPIRY"),
            ("boolean-expiry", _jwt(expires_at=True), "JWT_EXPIRY"),
            ("scope", _jwt(scopes="system:info audit:list"), "JWT_SCOPE"),
            ("duplicate-scope", _jwt(scopes="system:info system:info"), "SCOPE"),
            ("invalid-array-scope", _jwt(scopes=["system:info", 3]), "SCOPE"),
            ("duplicate-array-scope", _jwt(scopes=["system:info", "system:info"]), "SCOPE"),
        )
        for label, token, code in cases:
            with self.subTest(label=label):
                with self.assertRaises(refresh.PkceRefreshError) as error:
                    refresh.validate_jwt_metadata(
                        token,
                        expected_kid=KID_V1,
                        expected_issuer=ISSUER,
                        expected_audience=AUDIENCE,
                        expected_scopes=SCOPES,
                        now=NOW,
                    )
                self.assertEqual(code, error.exception.code)
                self.assertNotIn(token, str(error.exception))

    def test_rejects_malformed_padded_or_duplicate_json_segments(self) -> None:
        duplicate_header = _b64(b'{"alg":"RS256","alg":"none","kid":"x"}')
        valid_claims = _b64(_json_bytes({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": NOW + 7200,
            "scope": "system:info project:list",
        }))
        malformed = (
            "one.two",
            "one.two.three.four",
            f"{duplicate_header}.{valid_claims}.{_b64(b'sig')}",
            _jwt().replace(".", "=.", 1),
            f"{_b64(b'[]')}.{valid_claims}.{_b64(b'sig')}",
            f"{_b64(b'{not-json}')}.{valid_claims}.{_b64(b'sig')}",
        )
        for token in malformed:
            with self.subTest(token_length=len(token)):
                with self.assertRaises(refresh.PkceRefreshError):
                    refresh.parse_jwt_header(token)


class RefreshGrantTest(unittest.TestCase):
    def test_refresh_is_one_exact_public_post_and_requires_rotation(self) -> None:
        opener = FakeTokenOpener((
            _success_token_response(kid=KID_V2, refresh_token=NEXT_REFRESH),
        ))
        tokens = refresh.refresh_token_once(
            opener,
            token_endpoint=TOKEN,
            client_id=CLIENT_ID,
            refresh_token=OLD_REFRESH,
            expected_kid=KID_V2,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            expected_scopes=SCOPES,
            now=NOW,
        )
        self.assertEqual(1, len(opener.requests))
        request = opener.requests[0]
        self.assertEqual("POST", request.get_method())
        self.assertEqual(
            [
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT_ID),
                ("refresh_token", OLD_REFRESH),
            ],
            parse_qsl(request.data.decode("ascii")),
        )
        self.assertNotIn(b"client_secret", request.data)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(NEXT_REFRESH, tokens.refresh_token)
        self.assertNotIn(OLD_REFRESH, repr(tokens))
        self.assertNotIn(NEXT_REFRESH, repr(tokens))

        same = FakeTokenOpener((
            _success_token_response(kid=KID_V2, refresh_token=OLD_REFRESH),
        ))
        with self.assertRaises(refresh.PkceRefreshError) as error:
            refresh.refresh_token_once(
                same,
                token_endpoint=TOKEN,
                client_id=CLIENT_ID,
                refresh_token=OLD_REFRESH,
                expected_kid=KID_V2,
                expected_issuer=ISSUER,
                expected_audience=AUDIENCE,
                expected_scopes=SCOPES,
                now=NOW,
            )
        self.assertEqual("REFRESH_ROTATION", error.exception.code)
        self.assertNotIn(OLD_REFRESH, str(error.exception))

    def test_ambiguous_refresh_network_outcome_is_never_retried_or_chained(self) -> None:
        opener = FakeTokenOpener((URLError("connection lost after request send"),))
        with self.assertRaises(refresh.TokenEndpointOutcomeUnknown) as error:
            refresh.refresh_token_once(
                opener,
                token_endpoint=TOKEN,
                client_id=CLIENT_ID,
                refresh_token=OLD_REFRESH,
                expected_kid=KID_V2,
                expected_issuer=ISSUER,
                expected_audience=AUDIENCE,
                expected_scopes=SCOPES,
                now=NOW,
            )
        self.assertFalse(error.exception.retry_safe)
        self.assertEqual("refresh_token", error.exception.operation)
        self.assertEqual("TOKEN_ENDPOINT_OUTCOME_UNKNOWN", error.exception.code)
        self.assertEqual(1, len(opener.requests))
        self.assertIsNone(error.exception.__cause__)
        self.assertNotIn(OLD_REFRESH, str(error.exception))

        response_opener = FakeTokenOpener((FailingReadResponse(
            200, headers=(("Content-Type", "application/json"),)
        ),))
        with self.assertRaises(refresh.TokenEndpointOutcomeUnknown) as read_error:
            refresh.refresh_token_once(
                response_opener,
                token_endpoint=TOKEN,
                client_id=CLIENT_ID,
                refresh_token=OLD_REFRESH,
                expected_kid=KID_V2,
                expected_issuer=ISSUER,
                expected_audience=AUDIENCE,
                expected_scopes=SCOPES,
                now=NOW,
            )
        self.assertEqual("refresh_token", read_error.exception.operation)
        self.assertEqual(1, len(response_opener.requests))

    def test_ambiguous_authorization_code_exchange_is_not_retried(self) -> None:
        opener = FakeAuthenticatedOpener((_redirect_for_request,))
        token_opener = FakeTokenOpener((URLError("connection lost after request send"),))
        with patch.object(
                refresh.secrets, "token_bytes", side_effect=(b"v" * 48, b"s" * 32)):
            with self.assertRaises(refresh.TokenEndpointOutcomeUnknown) as error:
                refresh.authorization_code_pkce_once(
                    opener,
                    token_opener=token_opener,
                    authorization_endpoint=AUTHORIZE,
                    token_endpoint=TOKEN,
                    client_id=CLIENT_ID,
                    redirect_uri=REDIRECT,
                    scopes=SCOPES,
                    expected_kid=KID_V1,
                    expected_issuer=ISSUER,
                    expected_audience=AUDIENCE,
                    now=NOW,
                )
        self.assertEqual("authorization_code", error.exception.operation)
        self.assertEqual(1, len(opener.requests))
        self.assertEqual(1, len(token_opener.requests))
        self.assertFalse(error.exception.retry_safe)

    def test_replay_probe_accepts_only_one_exact_invalid_grant_response(self) -> None:
        opener = FakeTokenOpener((
            FakeResponse(
                400,
                _json_bytes({"error": "invalid_grant", "error_description": "replayed"}),
                (("Content-Type", "application/json"),),
            ),
        ))
        refresh.expect_refresh_invalid_grant_once(
            opener,
            token_endpoint=TOKEN,
            client_id=CLIENT_ID,
            refresh_token=OLD_REFRESH,
            expected_issuer=ISSUER,
        )
        self.assertEqual(1, len(opener.requests))
        request = opener.requests[0]
        self.assertEqual(
            [
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT_ID),
                ("refresh_token", OLD_REFRESH),
            ],
            parse_qsl(request.data.decode("ascii")),
        )
        self.assertIsNone(request.get_header("Authorization"))

        error_headers = Message()
        error_headers.add_header("Content-Type", "application/json")
        http_error = HTTPError(
            TOKEN,
            400,
            "Bad Request",
            error_headers,
            io.BytesIO(_json_bytes({"error": "invalid_grant"})),
        )
        error_opener = FakeTokenOpener((http_error,))
        refresh.expect_refresh_invalid_grant_once(
            error_opener,
            token_endpoint=TOKEN,
            client_id=CLIENT_ID,
            refresh_token=OLD_REFRESH,
            expected_issuer=ISSUER,
        )
        self.assertEqual(1, len(error_opener.requests))

        bad_responses = (
            FakeResponse(401, _json_bytes({"error": "invalid_grant"}), (
                ("Content-Type", "application/json"),
            )),
            FakeResponse(400, _json_bytes({"error": "invalid_client"}), (
                ("Content-Type", "application/json"),
            )),
            FakeResponse(400, _json_bytes({
                "error": "invalid_grant", "access_token": _jwt(),
            }), (("Content-Type", "application/json"),)),
        )
        for response in bad_responses:
            with self.subTest(status=response.status):
                rejected = FakeTokenOpener((response,))
                with self.assertRaises(refresh.PkceRefreshError):
                    refresh.expect_refresh_invalid_grant_once(
                        rejected,
                        token_endpoint=TOKEN,
                        client_id=CLIENT_ID,
                        refresh_token=OLD_REFRESH,
                        expected_issuer=ISSUER,
                    )
                self.assertEqual(1, len(rejected.requests))

    def test_ambiguous_replay_probe_is_not_retried(self) -> None:
        opener = FakeTokenOpener((TimeoutError("response timeout"),))
        with self.assertRaises(refresh.TokenEndpointOutcomeUnknown) as error:
            refresh.expect_refresh_invalid_grant_once(
                opener,
                token_endpoint=TOKEN,
                client_id=CLIENT_ID,
                refresh_token=OLD_REFRESH,
                expected_issuer=ISSUER,
            )
        self.assertFalse(error.exception.retry_safe)
        self.assertEqual("refresh_token_replay", error.exception.operation)
        self.assertEqual(1, len(opener.requests))

    def test_refresh_never_sends_a_token_to_a_cross_origin_endpoint(self) -> None:
        evil = "https://evil.example.test/oauth2/token"
        opener = FakeTokenOpener(())
        with self.assertRaises(refresh.PkceRefreshError) as error:
            refresh.refresh_token_once(
                opener,
                token_endpoint=evil,
                client_id=CLIENT_ID,
                refresh_token=OLD_REFRESH,
                expected_kid=KID_V2,
                expected_issuer=ISSUER,
                expected_audience=AUDIENCE,
                expected_scopes=SCOPES,
                now=NOW,
            )
        self.assertEqual("ENDPOINT_ORIGIN", error.exception.code)
        self.assertEqual([], opener.requests)

        with self.assertRaises(refresh.PkceRefreshError) as replay_error:
            refresh.expect_refresh_invalid_grant_once(
                opener,
                token_endpoint=evil,
                client_id=CLIENT_ID,
                refresh_token=OLD_REFRESH,
                expected_issuer=ISSUER,
            )
        self.assertEqual("ENDPOINT_ORIGIN", replay_error.exception.code)
        self.assertEqual([], opener.requests)


class TokenResponseValidationTest(unittest.TestCase):
    def _refresh_with_response(self, response: FakeResponse) -> None:
        refresh.refresh_token_once(
            FakeTokenOpener((response,)),
            token_endpoint=TOKEN,
            client_id=CLIENT_ID,
            refresh_token=OLD_REFRESH,
            expected_kid=KID_V2,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            expected_scopes=SCOPES,
            now=NOW,
        )

    def test_rejects_missing_extra_or_semantically_invalid_token_fields(self) -> None:
        valid = _token_document(access_token=_jwt(kid=KID_V2), refresh_token=NEXT_REFRESH)
        cases = []
        missing = dict(valid)
        missing.pop("refresh_token")
        cases.append(missing)
        extra = dict(valid)
        extra["id_token"] = _jwt(kid=KID_V2)
        cases.append(extra)
        wrong_type = dict(valid)
        wrong_type["token_type"] = "MAC"
        cases.append(wrong_type)
        bool_expiry = dict(valid)
        bool_expiry["expires_in"] = True
        cases.append(bool_expiry)
        wrong_scope = dict(valid)
        wrong_scope["scope"] = "system:info audit:list"
        cases.append(wrong_scope)
        short_refresh = dict(valid)
        short_refresh["refresh_token"] = "short"
        cases.append(short_refresh)

        for document in cases:
            with self.subTest(fields=tuple(document)):
                with self.assertRaises(refresh.PkceRefreshError):
                    self._refresh_with_response(FakeResponse(
                        200,
                        _json_bytes(document),
                        (("Content-Type", "application/json"),),
                    ))

    def test_rejects_token_response_and_jwt_lifetime_contradiction(self) -> None:
        contradiction = _token_document(
            access_token=_jwt(kid=KID_V2, expires_at=NOW + 7200),
            refresh_token=NEXT_REFRESH,
            expires_in=1,
        )
        with self.assertRaises(refresh.PkceRefreshError) as error:
            self._refresh_with_response(FakeResponse(
                200,
                _json_bytes(contradiction),
                (("Content-Type", "application/json"),),
            ))
        self.assertEqual("TOKEN_EXPIRY", error.exception.code)

    def test_rejects_duplicate_json_keys_wrong_content_type_and_oversized_body(self) -> None:
        duplicate = (
            b'{"access_token":"one","access_token":"two",'
            b'"refresh_token":"' + NEXT_REFRESH.encode("ascii") + b'",'
            b'"token_type":"Bearer","expires_in":7199,'
            b'"scope":"system:info project:list"}'
        )
        responses = (
            FakeResponse(200, duplicate, (("Content-Type", "application/json"),)),
            FakeResponse(200, _json_bytes(_token_document(
                access_token=_jwt(kid=KID_V2), refresh_token=NEXT_REFRESH,
            )), (("Content-Type", "text/plain"),)),
            FakeResponse(200, b"x" * (64 * 1024 + 1), (
                ("Content-Type", "application/json"),
            )),
            FakeResponse(200, _json_bytes(_token_document(
                access_token=_jwt(kid=KID_V2), refresh_token=NEXT_REFRESH,
            )), (
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
            )),
        )
        for response in responses:
            with self.subTest(body_length=len(response._body.getvalue())):
                with self.assertRaises(refresh.PkceRefreshError):
                    self._refresh_with_response(response)

    def test_error_messages_and_redacted_repr_do_not_expose_credentials(self) -> None:
        access = _jwt(kid=KID_V2)
        response = FakeResponse(
            200,
            _json_bytes(_token_document(
                access_token=access,
                refresh_token=NEXT_REFRESH,
                scope="unexpected",
            )),
            (("Content-Type", "application/json"),),
        )
        with self.assertRaises(refresh.PkceRefreshError) as error:
            self._refresh_with_response(response)
        message = str(error.exception)
        self.assertNotIn(access, message)
        self.assertNotIn(OLD_REFRESH, message)
        self.assertNotIn(NEXT_REFRESH, message)


class OpenerConfigurationTest(unittest.TestCase):
    def test_real_opener_sends_cookie_but_never_follows_authorization_redirect(self) -> None:
        observations = {"authorization": 0, "callback": 0, "cookie": ""}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/authorize":
                    observations["authorization"] += 1
                    observations["cookie"] = self.headers.get("Cookie", "")
                    self.send_response(302)
                    self.send_header(
                        "Location",
                        f"http://127.0.0.1:{self.server.server_port}/callback?code=secret",
                    )
                    self.end_headers()
                else:
                    observations["callback"] += 1
                    self.send_response(200)
                    self.end_headers()

            def log_message(self, _format: str, *args: Any) -> None:
                del args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cookies = CookieJar()
        cookies.set_cookie(Cookie(
            version=0,
            name="WEB_STARTER_SESSION",
            value="loopback-session",
            port=None,
            port_specified=False,
            domain="127.0.0.1",
            domain_specified=False,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        ))
        opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(cookies))
        try:
            refresh.install_no_redirect_handler(opener)
            with opener.open(
                    f"http://127.0.0.1:{server.server_port}/authorize",
                    timeout=2) as response:
                self.assertEqual(302, response.status)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(1, observations["authorization"])
        self.assertEqual(0, observations["callback"])
        self.assertIn("WEB_STARTER_SESSION=loopback-session", observations["cookie"])

    def test_redirect_interceptor_preserves_the_authenticated_cookie_jar(self) -> None:
        cookies = CookieJar()
        cookie_handler = HTTPCookieProcessor(cookies)
        opener = build_opener(ProxyHandler({}), cookie_handler)
        refresh.install_no_redirect_handler(opener)
        installed = [
            handler for handler in opener.handlers
            if isinstance(handler, HTTPCookieProcessor)
        ]
        self.assertEqual([cookie_handler], installed)
        self.assertIs(cookies, installed[0].cookiejar)

    def test_requires_an_opener_that_can_install_redirect_interception(self) -> None:
        class UnsafeOpener:
            def open(self, _request: Any, timeout: float = 0) -> Any:
                raise AssertionError(timeout)

        with self.assertRaises(refresh.PkceRefreshError) as error:
            refresh.install_no_redirect_handler(UnsafeOpener())
        self.assertEqual("OPENER_CONFIGURATION", error.exception.code)

    def test_rejects_an_opener_that_could_add_basic_authentication(self) -> None:
        opener = build_opener(HTTPBasicAuthHandler())
        with self.assertRaises(refresh.PkceRefreshError) as error:
            refresh.install_no_redirect_handler(opener)
        self.assertEqual("PUBLIC_CLIENT_AUTH", error.exception.code)

    def test_rejects_early_redirect_unsafe_headers_custom_handlers_and_debug_output(self) -> None:
        early = build_opener(ProxyHandler({}))
        redirect = next(
            handler for handler in early.handlers
            if type(handler) is HTTPRedirectHandler
        )
        redirect.handler_order = 50
        with self.assertRaises(refresh.PkceRefreshError) as redirect_error:
            refresh.install_no_redirect_handler(early)
        self.assertEqual("OPENER_REDIRECT_ORDER", redirect_error.exception.code)

        automatic_auth = build_opener(ProxyHandler({}))
        automatic_auth.addheaders.append(("Authorization", "Basic test-only"))
        with self.assertRaises(refresh.PkceRefreshError) as header_error:
            refresh.install_no_redirect_handler(automatic_auth)
        self.assertEqual("PUBLIC_CLIENT_AUTH", header_error.exception.code)

        debug = build_opener(ProxyHandler({}), HTTPSHandler(debuglevel=1))
        with self.assertRaises(refresh.PkceRefreshError) as debug_error:
            refresh.install_no_redirect_handler(debug)
        self.assertEqual("OPENER_DEBUG", debug_error.exception.code)

        class CustomRedirect(HTTPRedirectHandler):
            handler_order = 10

        custom = build_opener(ProxyHandler({}), CustomRedirect())
        with self.assertRaises(refresh.PkceRefreshError) as custom_error:
            refresh.install_no_redirect_handler(custom)
        self.assertEqual("OPENER_CONFIGURATION", custom_error.exception.code)

    def test_unhashable_scope_and_audience_inputs_fail_closed(self) -> None:
        with self.assertRaises(refresh.PkceRefreshError):
            refresh._validate_scopes((["nested"],), "test scopes")
        with self.assertRaises(refresh.PkceRefreshError):
            refresh._jwt_audiences([["nested"]])

    def test_no_redirect_handler_returns_original_response_for_every_redirect(self) -> None:
        handler = refresh.NoRedirectHandler()
        response = object()
        request = object()
        headers = Message()
        for status in (301, 302, 303, 307, 308):
            method = getattr(handler, f"http_error_{status}")
            self.assertIs(response, method(request, response, status, "redirect", headers))


if __name__ == "__main__":
    unittest.main()
