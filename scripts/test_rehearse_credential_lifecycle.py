from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import rehearse_credential_lifecycle as producer


class CredentialLifecycleProducerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def private_file(self, name: str, value: str) -> Path:
        path = self.root / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_reads_unique_private_environment_assignments(self) -> None:
        path = self.private_file("runtime.env", "ONE=value\nTWO=second=value\n")

        values = producer._environment(path)

        self.assertEqual({"ONE": "value", "TWO": "second=value"}, values)

    def test_rejects_duplicate_environment_assignment(self) -> None:
        path = self.private_file("runtime.env", "ONE=value\nONE=other\n")

        with self.assertRaisesRegex(producer.LifecycleError, "unsafe assignment"):
            producer._environment(path)

    def test_rejects_group_readable_private_input(self) -> None:
        path = self.private_file("runtime.env", "ONE=value\n")
        path.chmod(0o640)

        with self.assertRaisesRegex(producer.LifecycleError, "mode-0600"):
            producer._environment(path)

    def test_atomically_refreshes_owned_private_acceptance_credential(self) -> None:
        self.root.chmod(0o700)
        path = self.private_file(
            "oauth-client.json",
            '{"client_id":"client-one","client_secret":"old-secret"}\n',
        )

        producer._replace_private_json(
            path,
            {"client_id": "client-one", "client_secret": "new-secret"},
            "OAuth client fixture",
        )

        self.assertEqual(
            {"client_id": "client-one", "client_secret": "new-secret"},
            json.loads(path.read_text(encoding="utf-8")),
        )
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual([], list(self.root.glob(".oauth-client.json.*.tmp")))

    def test_private_acceptance_credential_refresh_rejects_linked_target(self) -> None:
        self.root.chmod(0o700)
        path = self.private_file("oauth-client.json", '{"client_id":"client-one"}\n')
        linked = self.root / "linked.json"
        linked.symlink_to(path)

        with self.assertRaisesRegex(producer.LifecycleError, "existing real regular file"):
            producer._replace_private_json(
                linked,
                {"client_id": "client-one", "client_secret": "new-secret"},
                "OAuth client fixture",
            )

    def test_failed_check_diagnostics_are_sorted_and_contain_only_check_names(self) -> None:
        with self.assertRaisesRegex(
            producer.LifecycleError,
            "security contract: private-boundary,revocation",
        ):
            producer._require_checks(
                "security contract",
                {"revocation": False, "scope": True, "private-boundary": False},
            )

    def test_accepts_only_positive_decimal_string_identifiers_at_web_boundary(self) -> None:
        self.assertTrue(producer._is_opaque_id("1"))
        self.assertTrue(producer._is_opaque_id("9223372036854775807"))
        for value in (1, True, "0", "01", "-1", "1.0", "", None):
            with self.subTest(value=value):
                self.assertFalse(producer._is_opaque_id(value))

    def test_checks_service_account_and_token_audits_with_their_actual_resource_types(self) -> None:
        admin = object()
        expectations = (
            ("service-account-created", "service-account"),
            ("service-account-token-issued", "token"),
        )

        with mock.patch.object(producer, "_audit_present", return_value=True) as audit_present:
            observed = producer._operation_audits_present(admin, expectations)

        self.assertTrue(observed)
        self.assertEqual(
            [
                mock.call(admin, "service-account-created", "service-account"),
                mock.call(admin, "service-account-token-issued", "token"),
            ],
            audit_present.call_args_list,
        )

    def test_removes_lifecycle_user_and_proves_404_with_correlated_audit(self) -> None:
        admin = mock.Mock()
        admin.request.return_value = (404, b'{"code":"NOT_FOUND"}', {})

        with (
            mock.patch.object(producer, "_api_data") as api_data,
            mock.patch.object(producer, "_audit_present", return_value=True) as audit_present,
        ):
            trace, status = producer._remove_lifecycle_user(
                admin, "2080554431372251138", "release-lifecycle-password-reset-1", False
            )

        self.assertEqual("release-lifecycle-password-reset-1-cleanup", trace)
        self.assertEqual(404, status)
        api_data.assert_called_once_with(
            admin,
            "DELETE",
            "/api/users/2080554431372251138",
            trace_id="release-lifecycle-password-reset-1-cleanup",
        )
        admin.request.assert_called_once_with(
            "GET", "/api/users/2080554431372251138"
        )
        audit_present.assert_called_once_with(
            admin, "release-lifecycle-password-reset-1-cleanup", "user"
        )

    def test_accepts_subject_remove_as_the_fixture_cleanup_operation(self) -> None:
        admin = mock.Mock()
        admin.request.return_value = (404, b'{"code":"NOT_FOUND"}', {})

        with (
            mock.patch.object(producer, "_api_data") as api_data,
            mock.patch.object(producer, "_audit_present", return_value=True),
        ):
            trace, status = producer._remove_lifecycle_user(
                admin, "2080554431372251138", "release-lifecycle-subject-remove-3", True
            )

        self.assertEqual("release-lifecycle-subject-remove-3", trace)
        self.assertEqual(404, status)
        api_data.assert_not_called()

    def test_rejects_lifecycle_user_that_remains_visible_after_cleanup(self) -> None:
        admin = mock.Mock()
        admin.request.return_value = (200, b'{"data":{"id":"1"}}', {})

        with (
            mock.patch.object(producer, "_api_data"),
            self.assertRaisesRegex(producer.LifecycleError, "remained visible"),
        ):
            producer._remove_lifecycle_user(
                admin, "2080554431372251138", "release-lifecycle-password-reset-1", False
            )

    def test_parses_json_and_event_stream_rpc_documents(self) -> None:
        direct = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"isError": True}}).encode()
        stream = b"event: message\ndata: " + direct + b"\n\n"

        self.assertTrue(producer._rpc_document(direct, 2)["result"]["isError"])
        self.assertTrue(producer._rpc_document(stream, 2)["result"]["isError"])

    def test_sql_literal_quotes_without_executing_input(self) -> None:
        self.assertEqual("'a''b\\\\c'", producer._sql_literal("a'b\\c"))
        with self.assertRaisesRegex(producer.LifecycleError, "NUL"):
            producer._sql_literal("unsafe\0value")

    def test_rejects_unsafe_compose_project_before_subprocess(self) -> None:
        with self.assertRaisesRegex(producer.LifecycleError, "project name"):
            producer.ComposeDatabase(
                Path("compose.yaml"), Path("override.yaml"), Path("runtime.env"), "../unsafe"
            )

    def test_mcp_negative_call_requires_structured_forbidden_result(self) -> None:
        session = "session-12345678"
        responses = [
            (200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}}).encode(),
             {"mcp-session-id": session}),
            (202, b"", {}),
            (200, json.dumps({"jsonrpc": "2.0", "id": 2, "result": {
                "isError": True, "structuredContent": {"code": "FORBIDDEN"}
            }}).encode(), {}),
            (204, b"", {}),
        ]
        with mock.patch.object(producer, "_request", side_effect=responses) as request:
            code = producer._mcp_tool_error(
                object(), "http://mcp-private.example", "opaque-token",
                "release-forbidden", "project.create", {"name": "Denied"},
            )

        self.assertEqual("FORBIDDEN", code)
        self.assertEqual("DELETE", request.call_args_list[-1].args[1])
        self.assertEqual(
            session,
            request.call_args_list[-1].args[4]["Mcp-Session-Id"],
        )

    def test_one_shot_mcp_initialize_closes_the_created_session(self) -> None:
        session = "session-12345678"
        responses = [
            (200, b'{"jsonrpc":"2.0","id":1,"result":{}}', {"mcp-session-id": session}),
            (204, b"", {}),
        ]

        with mock.patch.object(producer, "_request", side_effect=responses) as request:
            status = producer._mcp_initialize(
                object(), "http://mcp-private.example", "opaque-token", "release-initialize"
            )

        self.assertEqual(200, status)
        self.assertEqual("DELETE", request.call_args_list[-1].args[1])
        self.assertEqual(
            session,
            request.call_args_list[-1].args[4]["Mcp-Session-Id"],
        )

    def test_mcp_negative_call_rejects_success(self) -> None:
        responses = [
            (200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode(),
             {"mcp-session-id": "session-12345678"}),
            (202, b"", {}),
            (200, json.dumps({"jsonrpc": "2.0", "id": 2, "result": {
                "isError": False, "structuredContent": {"created": True}
            }}).encode(), {}),
            (204, b"", {}),
        ]
        with mock.patch.object(producer, "_request", side_effect=responses) as request:
            with self.assertRaisesRegex(producer.LifecycleError, "was not rejected"):
                producer._mcp_tool_error(
                    object(), "http://mcp-private.example", "opaque-token",
                    "release-forbidden", "project.create", {"name": "Denied"},
                )
        self.assertEqual("DELETE", request.call_args_list[-1].args[1])

    def test_error_response_scan_rejects_secret_values_and_fields(self) -> None:
        with self.assertRaisesRegex(producer.LifecycleError, "credential material"):
            producer._assert_redacted_error(
                b'{"error":"opaque-token"}', ["opaque-token"], "runtime error"
            )

        with self.assertRaisesRegex(producer.LifecycleError, "credential field"):
            producer._assert_redacted_error(
                b'{"authorization":"Bearer redacted"}', [], "runtime error"
            )

        producer._assert_redacted_error(
            b'{"error":"invalid_grant","error_description":"request rejected"}',
            ["opaque-token"],
            "runtime error",
        )


if __name__ == "__main__":
    unittest.main()
