from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

import repository_policy as policy


class RepositoryPolicyTest(unittest.TestCase):
    def candidate(self, root: Path, relative_path: str) -> policy.ScanInput:
        return policy.ScanInput(relative_path, root / relative_path)

    def test_secret_scan_accepts_placeholders_and_environment_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_file = root / ".env.example"
            env_file.write_text(
                "DB_PASSWORD=replace-with-a-password\n"
                "TOKEN_PEPPER=${TOKEN_PEPPER:?required}\n",
                encoding="utf-8",
            )
            workflow = root / "ci.yml"
            workflow.write_text(
                "PASSWORD: validation-only\nPRIVATE_KEY: ''\n",
                encoding="utf-8",
            )

            findings = policy.scan_secrets(
                [
                    self.candidate(root, ".env.example"),
                    self.candidate(root, "ci.yml"),
                ]
            )

            self.assertEqual([], findings)

    def test_secret_scan_accepts_schema_structures_but_scans_nested_literals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = root / "schema.json"
            schema.write_text(
                '{\n'
                '  "bootstrapCredential": {"$ref": "#/$defs/bootstrapCredential"},\n'
                '  "$defs": {\n'
                '    "bootstrapCredential": {\n'
                '      "type": "object"\n'
                '    }\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
            )
            config = root / "application.json"
            config.write_text(
                '{\n'
                '  "credentials": {\n'
                '    "password": "genuinely-secret-value"\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
            )

            findings = policy.scan_secrets(
                [
                    self.candidate(root, "schema.json"),
                    self.candidate(root, "application.json"),
                ]
            )

            self.assertEqual(
                [
                    policy.Finding(
                        "application.json",
                        3,
                        "literal-sensitive-value",
                    )
                ],
                findings,
            )

    def test_secret_scan_detects_provider_key_literal_and_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cloud_key = "AK" + "IA" + ("Z" * 16)
            config = root / "application.yml"
            config.write_text(
                "password: genuinely-secret-value\nprovider: " + cloud_key + "\n",
                encoding="utf-8",
            )
            key_file = root / "server.key"
            key_file.write_text("not-real-key-material\n", encoding="utf-8")
            embedded_key = root / "fixture.txt"
            embedded_key.write_bytes(
                (b"-----BEGIN RSA " + b"PRIVATE KEY-----\n")
                + b"not-real-key-material\n"
            )

            findings = policy.scan_secrets(
                [
                    self.candidate(root, "application.yml"),
                    self.candidate(root, "server.key"),
                    self.candidate(root, "fixture.txt"),
                ]
            )

            self.assertEqual(
                {
                    "cloud-access-key",
                    "credential-file",
                    "literal-sensitive-value",
                    "private-key-material",
                },
                {finding.rule for finding in findings},
            )

    def test_forbidden_scan_checks_paths_and_content_without_echoing_terms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            term = "obsolete" + "-module"
            source = root / "module.txt"
            source.write_text("The Obsolete-Module integration remains.\n", encoding="utf-8")

            findings = policy.scan_forbidden_terms(
                [self.candidate(root, "module.txt")], [term]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual("forbidden-term-1", findings[0].rule)

    def test_short_uppercase_acronym_matches_only_as_a_standalone_word(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.txt"
            source.write_text(
                "NotERPClient is an unrelated identifier.\n"
                "ERP is forbidden when it is a standalone word.\n",
                encoding="utf-8",
            )

            findings = policy.scan_forbidden_terms(
                [self.candidate(root, "module.txt")], ["ERP"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual(2, findings[0].line)

    def test_forbidden_check_without_external_terms_is_non_passing_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = policy.run_forbidden_check(
                    Path(directory), [], None, {}
                )

            self.assertEqual(policy.SKIP, result)
            self.assertIn("SKIP forbidden-business-term-scan", output.getvalue())

    def test_forbidden_term_file_must_be_external(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            term_file = root / "terms.txt"
            term_file.write_text("some-term\n", encoding="utf-8")

            terms, error = policy.load_forbidden_terms(
                root, str(term_file), {}
            )

            self.assertIsNone(terms)
            self.assertIn("outside", error or "")

    def test_forbidden_terms_load_from_external_file(self) -> None:
        with tempfile.TemporaryDirectory() as repository_directory:
            with tempfile.TemporaryDirectory() as policy_directory:
                root = Path(repository_directory)
                term = "retired" + "-feature"
                term_file = Path(policy_directory) / "terms.txt"
                term_file.write_text(term + "\n", encoding="utf-8")

                terms, error = policy.load_forbidden_terms(
                    root, str(term_file), {}
                )

                self.assertEqual([term], terms)
                self.assertIsNone(error)

    def test_forbidden_check_passes_with_zero_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module.txt"
            source.write_text("generic starter content\n", encoding="utf-8")
            output = io.StringIO()
            term = "obsolete" + "-module"

            with contextlib.redirect_stdout(output):
                result = policy.run_forbidden_check(
                    root,
                    [self.candidate(root, "module.txt")],
                    None,
                    {policy.FORBIDDEN_TERMS_ENV: term},
                )

            self.assertEqual(policy.PASS, result)
            self.assertIn("PASS forbidden-business-term-scan", output.getvalue())
            self.assertNotIn(term, output.getvalue())


if __name__ == "__main__":
    unittest.main()
