from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_runtime_identity as identity


COMMIT = "c" * 40
VERSION = "2.0.0"
APP_ID = "sha256:" + "a" * 64
NGINX_ID = "sha256:" + "b" * 64
MYSQL_ID = "sha256:" + "c" * 64
REDIS_ID = "sha256:" + "d" * 64
APP_REFERENCE = "registry.example/app@sha256:" + "1" * 64
NGINX_REFERENCE = "registry.example/nginx@sha256:" + "2" * 64
MYSQL_REFERENCE = "registry.example/mysql@sha256:" + "3" * 64
REDIS_REFERENCE = "registry.example/redis@sha256:" + "4" * 64
PROJECT = "web-starter-release-test"

CONTAINER_IDS = {
    "app": "a" * 64,
    "nginx": "b" * 64,
    "mysql": "c" * 64,
    "redis": "d" * 64,
}
REFERENCES = {
    "app": APP_REFERENCE,
    "nginx": NGINX_REFERENCE,
    "mysql": MYSQL_REFERENCE,
    "redis": REDIS_REFERENCE,
}


class VerifyRuntimeIdentityTest(unittest.TestCase):

    def test_actuator_identity_rejects_tls_key_logging_before_network(self) -> None:
        with patch.dict(os.environ, {"SSLKEYLOGFILE": "/tmp/runtime-identity.keys"}, clear=False):
            with self.assertRaisesRegex(identity.RuntimeIdentityError, "must be unset"):
                identity.fetch_actuator_info("https://127.0.0.1:18081", "ops", "secret")

    def test_container_image_must_match_project_digest_and_oci_identity(self) -> None:
        container = [{
            "State": {"Running": True},
            "Image": APP_ID,
            "Config": {
                "Image": APP_REFERENCE,
                "Labels": {
                    "com.docker.compose.project": PROJECT,
                    "com.docker.compose.service": "app",
                },
            },
        }]
        image = [{
            "Id": APP_ID,
            "Config": {"Labels": {
                "org.opencontainers.image.version": VERSION,
                "org.opencontainers.image.revision": COMMIT,
            }},
        }]

        def runner(command):
            document = container if command[1:3] == ["container", "inspect"] else image
            return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

        result = identity.inspect_runtime_image(
            container_id="a" * 64,
            reference=APP_REFERENCE,
            project=PROJECT,
            service="app",
            version=VERSION,
            commit=COMMIT,
            run_command=runner,
        )
        self.assertEqual(APP_ID, result["imageId"])

        image[0]["Config"]["Labels"]["org.opencontainers.image.revision"] = "d" * 40
        with self.assertRaisesRegex(identity.RuntimeIdentityError, "revision"):
            identity.inspect_runtime_image(
                container_id="a" * 64,
                reference=APP_REFERENCE,
                project=PROJECT,
                service="app",
                version=VERSION,
                commit=COMMIT,
                run_command=runner,
            )

    def test_java_identity_requires_actual_specification_version_21(self) -> None:
        def runner(_command):
            return subprocess.CompletedProcess(
                [], 0, "", "    java.runtime.version = 21.0.8+9\n    java.specification.version = 21\n"
            )

        self.assertEqual("21", identity.java_identity("a" * 64, runner)["specificationVersion"])

        def wrong(_command):
            return subprocess.CompletedProcess(
                [], 0, "", "java.runtime.version = 17.0.1\njava.specification.version = 17\n"
            )

        with self.assertRaisesRegex(identity.RuntimeIdentityError, "Java 21"):
            identity.java_identity("a" * 64, wrong)

    def test_dependency_image_is_bound_without_inventing_web_starter_oci_labels(self) -> None:
        container = [{
            "State": {"Running": True},
            "Image": MYSQL_ID,
            "Config": {
                "Image": MYSQL_REFERENCE,
                "Labels": {
                    "com.docker.compose.project": PROJECT,
                    "com.docker.compose.service": "mysql",
                },
            },
        }]
        image = [{"Id": MYSQL_ID, "Config": {"Labels": {}}}]

        def runner(command):
            document = container if command[1:3] == ["container", "inspect"] else image
            return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

        result = identity.inspect_runtime_dependency_image(
            container_id=CONTAINER_IDS["mysql"],
            reference=MYSQL_REFERENCE,
            project=PROJECT,
            service="mysql",
            run_command=runner,
        )
        self.assertEqual(MYSQL_ID, result["imageId"])
        self.assertIsNone(result["ociVersion"])
        self.assertIsNone(result["ociRevision"])

        container[0]["Config"]["Image"] = "registry.example/mysql@sha256:" + "9" * 64
        with self.assertRaisesRegex(identity.RuntimeIdentityError, "digest reference"):
            identity.inspect_runtime_dependency_image(
                container_id=CONTAINER_IDS["mysql"],
                reference=MYSQL_REFERENCE,
                project=PROJECT,
                service="mysql",
                run_command=runner,
            )

    def test_actuator_info_must_match_release_and_admin_artifact(self) -> None:
        result = identity.validate_actuator_info({
            "app": {"version": VERSION},
            "build": {
                "version": VERSION,
                "artifact": "web-starter-admin",
                "group": "dev.webstarter",
            },
        }, VERSION)
        self.assertEqual(VERSION, result["applicationVersion"])

        with self.assertRaisesRegex(identity.RuntimeIdentityError, "release version"):
            identity.validate_actuator_info({
                "app": {"version": "2.0.0-SNAPSHOT"},
                "build": {
                    "version": VERSION,
                    "artifact": "web-starter-admin",
                    "group": "dev.webstarter",
                },
            }, VERSION)

    def test_inputs_reject_mutable_images_and_non_loopback_management(self) -> None:
        with self.assertRaisesRegex(identity.RuntimeIdentityError, "immutable"):
            identity._validate_inputs(
                PROJECT,
                CONTAINER_IDS,
                {**REFERENCES, "app": "registry.example/app:2.0.0"},
                VERSION,
                COMMIT,
            )
        with self.assertRaisesRegex(identity.RuntimeIdentityError, "unique"):
            identity._validate_inputs(
                PROJECT,
                {**CONTAINER_IDS, "redis": CONTAINER_IDS["mysql"]},
                REFERENCES,
                VERSION,
                COMMIT,
            )
        with self.assertRaisesRegex(identity.RuntimeIdentityError, "loopback"):
            identity._loopback_origin("https://management.example.invalid")

    def test_report_is_private_and_cannot_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "runtime-identity.json"
            identity._write_private(target, {"status": "PASS"})
            self.assertEqual(0, stat.S_IMODE(target.stat().st_mode) & 0o077)
            with self.assertRaisesRegex(identity.RuntimeIdentityError, "already exists"):
                identity._write_private(target, {"status": "FAIL"})


if __name__ == "__main__":
    unittest.main()
