from __future__ import annotations

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from scripts import rehearse_jwks_rotation as ac26


def b64_integer(value: int) -> str:
    payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def rsa_jwk(kid: str, *, private: bool, exp: int | None = None,
            revoked: bool = False, modulus_seed: int = 1) -> dict[str, object]:
    modulus = (1 << 3071) | (modulus_seed << 128) | 1
    value: dict[str, object] = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64_integer(modulus),
        "e": b64_integer(65537),
    }
    if private:
        value.update({name: "AQ" for name in ("d", "p", "q", "dp", "dq", "qi")})
    if exp is not None:
        value["exp"] = exp
    if revoked:
        value["rev"] = {"revoked_at": 2_000_000_010, "reason": "COMPROMISED"}
    return value


class JwksRotationProducerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def private_json(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def rings(self) -> tuple[Path, Path, Path]:
        old = rsa_jwk("old-2025", private=True, modulus_seed=1)
        new = rsa_jwk("new-2026", private=True, modulus_seed=2)
        retiring = rsa_jwk("old-2025", private=False, exp=2_000_000_120, modulus_seed=1)
        revoked = dict(retiring)
        revoked["rev"] = {"revoked_at": 2_000_000_010, "reason": "COMPROMISED"}
        return (
            self.private_json("initial.json", {"keys": [old]}),
            self.private_json("rotated.json", {"keys": [new, retiring]}),
            self.private_json("revoked.json", {"keys": [new, revoked]}),
        )

    def test_accepts_exact_public_only_rotation_and_revocation_sequence(self) -> None:
        initial_path, rotated_path, revoked_path = self.rings()

        initial = ac26.load_key_ring(initial_path, "old-2025", "initial")
        rotated = ac26.load_key_ring(rotated_path, "new-2026", "rotated")
        revoked = ac26.load_key_ring(revoked_path, "new-2026", "terminal")
        ac26.validate_ring_sequence(initial, rotated, revoked, "revocation")

        self.assertEqual(1, initial.private_key_count)
        self.assertEqual(1, rotated.private_key_count)
        self.assertFalse(rotated.retiring_has_private_material)
        self.assertTrue(revoked.revoked)
        self.assertNotIn('"d"', json.dumps({
            "oldFingerprint": rotated.retiring_public_fingerprint,
            "newFingerprint": rotated.active_public_fingerprint,
        }))

    def test_accepts_expiry_mode_without_terminal_ring(self) -> None:
        initial_path, rotated_path, _ = self.rings()
        initial = ac26.load_key_ring(initial_path, "old-2025", "initial")
        rotated = ac26.load_key_ring(rotated_path, "new-2026", "rotated")

        ac26.validate_ring_sequence(initial, rotated, None, "expiry")

    def test_rejects_private_retiring_key_changed_public_key_and_bad_rev(self) -> None:
        initial_path, _, _ = self.rings()
        initial = ac26.load_key_ring(initial_path, "old-2025", "initial")

        private_retiring = self.private_json("private-retiring.json", {"keys": [
            rsa_jwk("new-2026", private=True, modulus_seed=2),
            rsa_jwk("old-2025", private=True, exp=2_000_000_120, modulus_seed=1),
        ]})
        rotated = ac26.load_key_ring(private_retiring, "new-2026", "rotated")
        with self.assertRaisesRegex(ac26.RehearsalError, "public-only"):
            ac26.validate_ring_sequence(initial, rotated, None, "expiry")

        wrong_public = self.private_json("wrong-public.json", {"keys": [
            rsa_jwk("new-2026", private=True, modulus_seed=2),
            rsa_jwk("old-2025", private=False, exp=2_000_000_120, modulus_seed=9),
        ]})
        rotated = ac26.load_key_ring(wrong_public, "new-2026", "rotated")
        with self.assertRaisesRegex(ac26.RehearsalError, "does not match"):
            ac26.validate_ring_sequence(initial, rotated, None, "expiry")

        bad_rev = self.private_json("bad-rev.json", {"keys": [
            rsa_jwk("new-2026", private=True, modulus_seed=2),
            {**rsa_jwk("old-2025", private=False, exp=2_000_000_120, modulus_seed=1), "rev": {}},
        ]})
        with self.assertRaisesRegex(ac26.RehearsalError, "non-empty"):
            ac26.load_key_ring(bad_rev, "new-2026", "terminal")

    def test_rejects_unknown_active_duplicate_kid_short_rsa_and_nonprivate_file(self) -> None:
        initial_path, _, _ = self.rings()
        with self.assertRaisesRegex(ac26.RehearsalError, "active kid"):
            ac26.load_key_ring(initial_path, "missing", "initial")

        duplicate = self.private_json("duplicate.json", {"keys": [
            rsa_jwk("same", private=True, modulus_seed=1),
            rsa_jwk("same", private=False, exp=2_000_000_120, modulus_seed=1),
        ]})
        with self.assertRaisesRegex(ac26.RehearsalError, "repeats"):
            ac26.load_key_ring(duplicate, "same", "rotated")

        short = rsa_jwk("short", private=True)
        short["n"] = b64_integer((1 << 2047) | 1)
        short_path = self.private_json("short.json", {"keys": [short]})
        with self.assertRaisesRegex(ac26.RehearsalError, "safe RSA"):
            ac26.load_key_ring(short_path, "short", "initial")

        initial_path.chmod(0o644)
        with self.assertRaisesRegex(ac26.RehearsalError, "0600"):
            ac26.load_key_ring(initial_path, "old-2025", "initial")

        public_key = rsa_jwk("published", private=False, modulus_seed=7)
        metadata = json.dumps({
            "issuer": "https://mcp.ac26.webstarter.test:18443",
            "jwks_uri": "https://mcp.ac26.webstarter.test:18443/oauth2/jwks",
        }).encode()
        duplicate_jwks = json.dumps({"keys": [public_key, public_key]}).encode()
        with patch.object(ac26, "_request", side_effect=[
            (200, metadata, {"content-type": "application/json"}),
            (200, duplicate_jwks, {"content-type": "application/json"}),
        ]), self.assertRaisesRegex(ac26.RehearsalError, "duplicate kid"):
            ac26.observe_jwks(
                object(),
                "https://mcp.ac26.webstarter.test:18443",
                {"published": ac26._public_fingerprint(public_key)},
            )

    def test_phase_environment_changes_only_four_fixed_oauth_members(self) -> None:
        _, rotated_path, _ = self.rings()
        ring = ac26.load_key_ring(rotated_path, "new-2026", "rotated")
        base = {
            "WEB_STARTER_APP_IMAGE": "registry.invalid/app",
            "WEB_STARTER_APP_DIGEST": "sha256:" + "a" * 64,
            "WEB_STARTER_DB_PASSWORD": "not-persisted-in-evidence",
            "WEB_STARTER_OAUTH_RSA_PRIVATE_KEY": "legacy-private",
            "WEB_STARTER_OAUTH_RSA_PUBLIC_KEY": "legacy-public",
            "WEB_STARTER_OAUTH_RSA_JWK_SET": "old-ring",
            "WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID": "old",
        }
        target = self.root / "phase.env"

        ac26._write_phase_env(target, base, ring)

        lines = dict(line.split("=", 1) for line in target.read_text().splitlines())
        self.assertEqual("", lines["WEB_STARTER_OAUTH_RSA_PRIVATE_KEY"])
        self.assertEqual("", lines["WEB_STARTER_OAUTH_RSA_PUBLIC_KEY"])
        self.assertEqual("new-2026", lines["WEB_STARTER_OAUTH_RSA_ACTIVE_KEY_ID"])
        self.assertEqual(ring.compact_json, lines["WEB_STARTER_OAUTH_RSA_JWK_SET"])
        self.assertEqual(base["WEB_STARTER_DB_PASSWORD"], lines["WEB_STARTER_DB_PASSWORD"])
        self.assertEqual(0o600, target.stat().st_mode & 0o777)

    def test_runtime_environment_requires_loopback_digest_images_and_private_tls_files(self) -> None:
        cert = self.root / "tls.crt"
        key = self.root / "tls.key"
        cert.write_text("certificate fixture")
        key.write_text("private fixture")
        cert.chmod(0o600)
        key.chmod(0o600)
        values = {
            "WEB_STARTER_APP_IMAGE": "registry.invalid/app",
            "WEB_STARTER_APP_DIGEST": "sha256:" + "a" * 64,
            "WEB_STARTER_NGINX_IMAGE": "registry.invalid/nginx",
            "WEB_STARTER_NGINX_DIGEST": "sha256:" + "b" * 64,
            "WEB_STARTER_HTTP_BIND_ADDRESS": "127.0.0.1",
            "WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS": "127.0.0.1",
            "WEB_STARTER_HTTP_PORT": "18088",
            "WEB_STARTER_PUBLIC_MCP_PORT": "18443",
            "WEB_STARTER_PUBLIC_TLS_CERT_FILE": str(cert),
            "WEB_STARTER_PUBLIC_TLS_KEY_FILE": str(key),
        }
        repository = self.root / "candidate"
        repository.mkdir()

        ac26._validate_runtime_env_files(values, repository)

        public = dict(values)
        public["WEB_STARTER_PUBLIC_MCP_BIND_ADDRESS"] = "0.0.0.0"
        with self.assertRaisesRegex(ac26.RehearsalError, "127.0.0.1"):
            ac26._validate_runtime_env_files(public, repository)
        mutable = dict(values)
        mutable["WEB_STARTER_APP_DIGEST"] = "latest"
        with self.assertRaisesRegex(ac26.RehearsalError, "immutable"):
            ac26._validate_runtime_env_files(mutable, repository)
        controlled = dict(values)
        controlled["DOCKER_HOST"] = "tcp://example.invalid:2375"
        with self.assertRaisesRegex(ac26.RehearsalError, "control variables"):
            ac26._validate_runtime_env_files(controlled, repository)

    def test_compose_controller_has_fixed_no_hook_no_pull_no_build_contract(self) -> None:
        app = ac26.AppIdentity(
            reference="registry.invalid/app@sha256:" + "a" * 64,
            image_id="sha256:" + "b" * 64,
            manifest_digest="sha256:" + "a" * 64,
            oci_version="2.0.0",
            oci_revision="c" * 40,
            nginx_reference="registry.invalid/nginx@sha256:" + "e" * 64,
            nginx_image_id="sha256:" + "f" * 64,
            nginx_manifest_digest="sha256:" + "e" * 64,
            nginx_oci_version="2.0.0",
            nginx_oci_revision="c" * 40,
            runtime_identity_sha256="d" * 64,
        )
        base_values = {
            "WEB_STARTER_HTTP_PORT": "18088",
            "WEB_STARTER_PUBLIC_MCP_PORT": "18443",
        }
        controller = ac26.ComposeController(
            self.root,
            self.root / "compose.production.yaml",
            "web-starter-ac26-unit-1",
            self.root / "runtime.env",
            base_values,
            None,
            app,
            self.root,
            {},
        )
        command = controller._base(self.root / "phase.env")
        self.assertEqual("docker", command[0])
        self.assertEqual("compose", command[1])
        self.assertNotIn("--project-directory", command)
        self.assertNotIn("--profile", command)

        with self.assertRaisesRegex(ac26.RehearsalError, "isolated"):
            ac26.ComposeController(
                self.root,
                self.root / "compose.production.yaml",
                "production;touch-pwned",
                self.root / "runtime.env",
                base_values,
                None,
                app,
                self.root,
                {},
            )
        source = Path(ac26.__file__).read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("docker system prune", source)
        self.assertNotIn('"down"', source)
        self.assertNotIn("--hook", source)

        def ingress_document(service: str, container_id: str, target: str, port: str) -> bytes:
            return json.dumps([{
                "Id": container_id,
                "Image": app.nginx_image_id,
                "Config": {
                    "Image": app.nginx_reference,
                    "Labels": {
                        "com.docker.compose.project": "web-starter-ac26-unit-1",
                        "com.docker.compose.service": service,
                    },
                },
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "NetworkSettings": {"Ports": {
                    target: [{"HostIp": "127.0.0.1", "HostPort": port}],
                }},
            }]).encode()

        private_id = "1" * 64
        public_id = "2" * 64
        with patch.object(ac26, "_run", side_effect=[
            private_id.encode(), ingress_document("nginx", private_id, "8080/tcp", "18088"),
            public_id.encode(), ingress_document(
                "mcp-public-nginx", public_id, "8443/tcp", "18443"
            ),
        ]):
            self.assertEqual(
                {"nginx": private_id, "mcp-public-nginx": public_id},
                controller.inspect_ingresses(self.root / "phase.env"),
            )

        wrong_public = json.loads(
            ingress_document("mcp-public-nginx", public_id, "8443/tcp", "18443")
        )
        wrong_public[0]["NetworkSettings"]["Ports"]["8443/tcp"][0]["HostPort"] = "19443"
        with patch.object(ac26, "_run", side_effect=[
            private_id.encode(), ingress_document("nginx", private_id, "8080/tcp", "18088"),
            public_id.encode(), json.dumps(wrong_public).encode(),
        ]), self.assertRaisesRegex(ac26.RehearsalError, "port binding"):
            controller.inspect_ingresses(self.root / "phase.env")

    def test_docker_context_must_be_local_unix_and_environment_cannot_redirect_it(self) -> None:
        socket_path = self.root / "docker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_path))
            inspection = json.dumps([{
                "Name": "unit",
                "Endpoints": {"docker": {"Host": "unix://" + str(socket_path)}},
            }]).encode()
            with patch.dict(ac26.os.environ, {}, clear=True), patch.object(
                ac26, "_run", side_effect=[b"unit\n", inspection]
            ):
                environment = ac26._local_docker_environment()
            self.assertEqual({}, environment)

            with patch.dict(
                ac26.os.environ,
                {"DOCKER_HOST": "tcp://production.example.invalid:2375"},
                clear=True,
            ), self.assertRaisesRegex(ac26.RehearsalError, "refuses"):
                ac26._local_docker_environment()
        finally:
            listener.close()

    def test_argument_contract_rejects_hook_terminal_mismatch_and_unbounded_wait(self) -> None:
        common = [
            "--repository-root", str(self.root),
            "--runtime-manifest", str(self.root / "manifest"),
            "--runtime-identity", str(self.root / "identity"),
            "--compose-env-file", str(self.root / "env"),
            "--compose-project", "web-starter-ac26-unit-1",
            "--trace-prefix", "ac26-unit-0001",
            "--initial-jwk-set", str(self.root / "initial"),
            "--rotated-jwk-set", str(self.root / "rotated"),
            "--old-kid", "old",
            "--new-kid", "new",
            "--output-dir", str(self.root / "out"),
        ]
        with self.assertRaises(SystemExit):
            ac26.parse_arguments([*common, "--terminal-mode", "expiry", "--hook", "true"])
        with self.assertRaises(SystemExit):
            ac26.parse_arguments([
                *common, "--terminal-mode", "expiry", "--terminal-jwk-set", "revoked.json",
            ])
        with self.assertRaises(SystemExit):
            ac26.parse_arguments([
                *common, "--terminal-mode", "expiry", "--max-wait-seconds", "3600",
            ])

    def test_wait_is_bounded_and_requires_exclusive_boundary(self) -> None:
        with patch.object(ac26.time, "time", return_value=1_000):
            with self.assertRaisesRegex(ac26.RehearsalError, "outside"):
                ac26._wait_for_terminal(2_000, 60)
        with patch.object(ac26.time, "time", side_effect=[1_000, 1_011]), \
                patch.object(ac26.time, "sleep") as sleeper:
            observed = ac26._wait_for_terminal(1_010, 60)
        self.assertEqual(1_011, observed)
        sleeper.assert_called_once_with(11)

    def test_structured_tool_results_bind_one_exact_audit_record(self) -> None:
        ac26._validate_structured_tool_result(
            "system.info",
            {},
            {"structuredContent": {
                "product": "启程 Web Starter",
                "server": "web-starter-mcp",
                "java": 21,
            }},
        )
        arguments = {
            "page": 1,
            "size": 20,
            "traceId": "ac26-source-trace",
            "toolName": "system.info",
            "result": "SUCCESS",
        }
        exact = {"structuredContent": {
            "records": [{
                "traceId": "ac26-source-trace",
                "toolName": "system.info",
                "permissionCode": "system:info",
                "result": "SUCCESS",
            }],
            "total": 1,
            "page": 1,
            "size": 20,
        }}
        ac26._validate_structured_tool_result("audit.list", arguments, exact)

        distributed_markers = {"structuredContent": {
            "records": [
                {"traceId": "ac26-source-trace", "toolName": "other", "result": "FAILED"},
                {"traceId": "other-trace", "toolName": "system.info", "result": "SUCCESS"},
            ],
            "total": 2,
            "page": 1,
            "size": 20,
        }}
        with self.assertRaisesRegex(ac26.RehearsalError, "one exact"):
            ac26._validate_structured_tool_result(
                "audit.list", arguments, distributed_markers
            )

    def test_redirects_never_forward_basic_or_bearer_credentials(self) -> None:
        requests: list[tuple[str, str | None]] = []

        class RedirectFixture(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
                requests.append((self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path.endswith("start"):
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://127.0.0.1:{self.server.server_port}/sink"
                    )
                    self.end_headers()
                    return
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            opener = ac26.build_opener(
                ac26.ProxyHandler({}), ac26.RejectRedirectHandler()
            )
            for path, authorization in (
                ("basic-start", "Basic " + base64.b64encode(b"fixture:value").decode()),
                ("bearer-start", "Bearer " + "x" * 32),
            ):
                status, _, _ = ac26._request(
                    opener,
                    "POST",
                    f"http://127.0.0.1:{server.server_port}/{path}",
                    b"fixture=true",
                    {"Authorization": authorization},
                )
                self.assertEqual(302, status)
            self.assertEqual(["/basic-start", "/bearer-start"], [item[0] for item in requests])
            self.assertNotIn("/sink", [item[0] for item in requests])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_tls_context_refuses_session_key_logging(self) -> None:
        keylog = self.root / "tls-session.keys"
        with patch.dict(ac26.os.environ, {"SSLKEYLOGFILE": str(keylog)}, clear=True), \
                self.assertRaisesRegex(ac26.RehearsalError, "session key logging"):
            ac26._tls_context("https://mcp.ac26.webstarter.test:18443")
        self.assertFalse(keylog.exists())


if __name__ == "__main__":
    unittest.main()
