from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import refresh_release_runtime_read_token as refresh


class RefreshReleaseRuntimeReadTokenTest(unittest.TestCase):
    def _fixture(self, base: Path) -> tuple[Path, Path, Path, Path]:
        repository = base / "repository"
        repository.mkdir()
        credentials = base / "credentials"
        credentials.mkdir(mode=0o700)
        manifest = credentials / "manifest.json"
        manifest.write_text(
            json.dumps({"schemaVersion": 1, "ownerId": "17"}),
            encoding="utf-8",
        )
        manifest.chmod(0o600)
        output = credentials / "pat-read-refreshed.json"
        return repository, credentials, manifest, output

    def test_safe_inputs_require_private_external_direct_children(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, credentials, manifest, output = self._fixture(Path(directory))
            resolved = refresh._safe_inputs(repository, credentials, manifest, output)
            self.assertEqual(credentials.resolve(), resolved[0])
            self.assertEqual(manifest.resolve(), resolved[1])
            self.assertEqual(output.absolute(), resolved[2])

            output.write_text("occupied", encoding="utf-8")
            with self.assertRaisesRegex(refresh.AcceptanceSetupError, "must not already exist"):
                refresh._safe_inputs(repository, credentials, manifest, output)

    def test_safe_inputs_reject_repository_credentials_and_wrong_output_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repository"
            repository.mkdir()
            credentials = repository / "credentials"
            credentials.mkdir(mode=0o700)
            manifest = credentials / "manifest.json"
            manifest.write_text('{"schemaVersion":1,"ownerId":"17"}', encoding="utf-8")
            manifest.chmod(0o600)
            with self.assertRaisesRegex(refresh.AcceptanceSetupError, "outside"):
                refresh._safe_inputs(
                    repository,
                    credentials,
                    manifest,
                    credentials / "pat-read-refreshed.json",
                )

            external = base / "external"
            external.mkdir(mode=0o700)
            external_manifest = external / "manifest.json"
            external_manifest.write_bytes(manifest.read_bytes())
            external_manifest.chmod(0o600)
            with self.assertRaisesRegex(refresh.AcceptanceSetupError, "allowed fixed name"):
                refresh._safe_inputs(
                    repository,
                    external,
                    external_manifest,
                    external / "other.json",
                )

            unified = external / "pat-read-unified.json"
            self.assertEqual(
                unified.absolute(),
                refresh._safe_inputs(
                    repository,
                    external,
                    external_manifest,
                    unified,
                )[2],
            )

    def test_refresh_writes_only_the_new_private_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, credentials, manifest, output = self._fixture(Path(directory))
            args = argparse.Namespace(
                repository_root=str(repository),
                credential_directory=str(credentials),
                manifest=str(manifest),
                output=str(output),
            )
            responses = [
                {"subjectId": "17"},
                {"id": "29", "token": "wst_pat_one-time-secret"},
                [{"id": "29", "name": "refreshed"}],
            ]
            environment = {
                "WEB_STARTER_ACCEPTANCE_PRIVATE_BASE_URL": "http://127.0.0.1:18088",
                "WEB_STARTER_ACCEPTANCE_PUBLIC_BASE_URL": "https://localhost:18443",
                "WEB_STARTER_ACCEPTANCE_ADMIN_USERNAME": "release_admin",
                "WEB_STARTER_ACCEPTANCE_ADMIN_PASSWORD": "not-printed",
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                patch.object(refresh, "_tls_context", return_value=object()),
                patch.object(refresh, "HTTPSHandler", return_value=object()),
                patch.object(refresh, "HTTPCookieProcessor", return_value=object()),
                patch.object(refresh, "ProxyHandler", return_value=object()),
                patch.object(refresh, "RejectRedirectHandler", return_value=object()),
                patch.object(refresh, "build_opener", return_value=object()),
                patch.object(refresh, "_csrf", return_value=("X-XSRF-TOKEN", "csrf")),
                patch.object(refresh, "_cookie_header", return_value="WEB_STARTER_SESSION=session"),
                patch.object(refresh, "_api_data", side_effect=responses) as api,
            ):
                result = refresh.refresh.__wrapped__(args)

            self.assertEqual({"ownerId": "17", "credentialId": "29"}, result)
            self.assertEqual({"token": "wst_pat_one-time-secret"}, json.loads(output.read_text()))
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual(3, api.call_count)
            self.assertNotIn("not-printed", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
