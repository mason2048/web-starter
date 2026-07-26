from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import release_trivy


DIGEST_REFERENCE = "registry.example/web-starter/app@sha256:" + ("a" * 64)


class ReleaseTrivyTest(unittest.TestCase):
    def test_repository_configs_and_trivy_environment_cannot_change_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            work_root = root / "work"
            docker_config = root / "docker"
            output_dir = root / "artifacts"
            for path in (repository / "security", work_root, docker_config, output_dir):
                path.mkdir(parents=True)

            (repository / "trivy.yaml").write_text("scanners: [misconfig]\n", encoding="utf-8")
            (repository / "trivy-secret.yaml").write_text("disable-builtin-rules: true\n", encoding="utf-8")
            config = repository / "security/trivy-release.yaml"
            secret_config = repository / "security/trivy-secret-release.yaml"
            ignore_file = repository / "security/trivy-release.ignore"
            config.write_text("{}\n", encoding="utf-8")
            secret_config.write_text("{}\n", encoding="utf-8")
            ignore_file.write_text("", encoding="utf-8")

            fake_trivy = root / "fake-trivy"
            record = root / "record.json"
            fake_trivy.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "output = pathlib.Path(args[args.index('--output') + 1])\n"
                "record = pathlib.Path(os.environ['RELEASE_TRIVY_TEST_RECORD'])\n"
                "record.write_text(json.dumps({'args': args, 'cwd': os.getcwd(), "
                "'env': {k: v for k, v in os.environ.items() if k.upper().startswith('TRIVY_')}}))\n"
                "output.write_text(json.dumps({'SchemaVersion': 2, 'Results': []}))\n",
                encoding="utf-8",
            )
            fake_trivy.chmod(fake_trivy.stat().st_mode | stat.S_IXUSR)
            output = output_dir / "report.json"

            with mock.patch.dict(
                os.environ,
                {
                    "RELEASE_TRIVY_TEST_RECORD": str(record),
                    "TRIVY_CONFIG": str(repository / "trivy.yaml"),
                    "TRIVY_SECRET_CONFIG": str(repository / "trivy-secret.yaml"),
                    "TRIVY_SCANNERS": "misconfig",
                    "TRIVY_IGNORE_UNFIXED": "true",
                },
                clear=False,
            ):
                release_trivy.run_scan(
                    trivy=fake_trivy,
                    repository_root=repository,
                    config=config,
                    secret_config=secret_config,
                    ignore_file=ignore_file,
                    work_root=work_root,
                    docker_config=docker_config,
                    scanner="secret",
                    reference=DIGEST_REFERENCE,
                    output=output,
                )

            invocation = json.loads(record.read_text(encoding="utf-8"))
            args = invocation["args"]
            self.assertEqual({}, invocation["env"])
            self.assertNotEqual(str(repository), invocation["cwd"])
            self.assertTrue(Path(invocation["cwd"]).name.startswith("web-starter-trivy-"))
            self.assertEqual(str(config.resolve()), args[args.index("--config") + 1])
            self.assertEqual(
                str(secret_config.resolve()), args[args.index("--secret-config") + 1]
            )
            self.assertEqual(str(ignore_file.resolve()), args[args.index("--ignorefile") + 1])
            self.assertEqual("secret", args[args.index("--scanners") + 1])
            self.assertIn("--image-src", args)
            self.assertEqual(DIGEST_REFERENCE, args[-1])

    def test_work_root_inside_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            security = repository / "security"
            docker_config = root / "docker"
            output_dir = root / "artifacts"
            for path in (security, docker_config, output_dir):
                path.mkdir(parents=True)
            trivy = root / "trivy"
            trivy.write_text("binary", encoding="utf-8")
            for path in (
                security / "trivy-release.yaml",
                security / "trivy-secret-release.yaml",
                security / "trivy-release.ignore",
            ):
                path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(release_trivy.ReleaseTrivyError, "outside"):
                release_trivy.run_scan(
                    trivy=trivy,
                    repository_root=repository,
                    config=security / "trivy-release.yaml",
                    secret_config=security / "trivy-secret-release.yaml",
                    ignore_file=security / "trivy-release.ignore",
                    work_root=repository,
                    docker_config=docker_config,
                    scanner="vuln",
                    reference=DIGEST_REFERENCE,
                    output=output_dir / "report.json",
                )

    def test_mutable_tag_reference_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            security = repository / "security"
            docker_config = root / "docker"
            work_root = root / "work"
            output_dir = root / "artifacts"
            for path in (security, docker_config, work_root, output_dir):
                path.mkdir(parents=True)
            trivy = root / "trivy"
            trivy.write_text("binary", encoding="utf-8")
            for path in (
                security / "trivy-release.yaml",
                security / "trivy-secret-release.yaml",
                security / "trivy-release.ignore",
            ):
                path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(release_trivy.ReleaseTrivyError, "digest-bound"):
                release_trivy.run_scan(
                    trivy=trivy,
                    repository_root=repository,
                    config=security / "trivy-release.yaml",
                    secret_config=security / "trivy-secret-release.yaml",
                    ignore_file=security / "trivy-release.ignore",
                    work_root=work_root,
                    docker_config=docker_config,
                    scanner="vuln",
                    reference="registry.example/web-starter/app:latest",
                    output=output_dir / "report.json",
                )


if __name__ == "__main__":
    unittest.main()
