from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, patch

import scripts.rehearse_v1_to_v2_upgrade as upgrade
from scripts.v1_upgrade_refresh import OAuthTokenSet, TokenEndpointOutcomeUnknown


RUN_ID = "abcdef135790"


class V1UpgradeRefreshIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-refresh-glue-")
        root = Path(self.temporary.name)
        runtime_root = root / "runtime"
        runtime_root.mkdir(mode=0o700)
        self.runtime = upgrade.RuntimeContext(
            root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(48080, 48443, 48081),
            upgrade.EvidenceState(),
        )
        self.credential_root = runtime_root / "credentials"
        self.credential_root.mkdir(mode=0o700)
        self.issuer = (
            f"https://{self.runtime.names.public_hostname}:{self.runtime.ports.public_https}"
        )
        self.manifest = {
            "publicBaseUrl": self.issuer,
            "publicClientId": "release-pkce-abcdef135790",
            "redirectUri": self.issuer + "/login",
            "ownerId": "1",
            "projectId": "2",
        }
        self.old = OAuthTokenSet(
            access_token="a" * 128,
            refresh_token="r" * 64,
            token_type="Bearer",
            expires_in=7200,
            scopes=("system:info", "project:list"),
        )
        self.rotated = OAuthTokenSet(
            access_token="b" * 128,
            refresh_token="s" * 64,
            token_type="Bearer",
            expires_in=upgrade.V2_ACCESS_TOKEN_TTL_SECONDS,
            scopes=("system:info", "project:list"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    @contextmanager
    def loopback(_runtime):
        yield

    def test_capture_writes_only_the_four_private_fields(self) -> None:
        api = SimpleNamespace(opener=object())
        with patch.object(upgrade, "_public_loopback_resolution", self.loopback), patch.object(
            upgrade, "authorization_code_pkce_once", return_value=self.old
        ) as capture:
            tokens, path, parameters = upgrade._capture_v1_pkce_tokens(
                self.runtime,
                api,  # type: ignore[arg-type]
                self.manifest,
                self.credential_root,
                "v1-kid",
            )
        self.assertIs(tokens, self.old)
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            {"client_id", "redirect_uri", "access_token", "refresh_token"},
            set(document),
        )
        self.assertNotIn("code", document)
        self.assertNotIn("state", document)
        self.assertNotIn("code_verifier", document)
        self.assertEqual(self.issuer + "/oauth2/token", parameters["token_endpoint"])
        self.assertEqual(1, capture.call_count)

    def test_v2_rotation_replay_calls_each_one_time_operation_exactly_once(self) -> None:
        parameters = upgrade._pkce_parameters(self.runtime, self.manifest)
        old_file = self.credential_root / "v1-pkce-refresh.json"
        upgrade._write_pkce_token_set(old_file, parameters, self.old)
        sdk_calls: list[str] = []

        def sdk(*args, **_kwargs):
            sdk_calls.append(Path(args[4]).name)

        with patch.object(upgrade, "_public_loopback_resolution", self.loopback), patch.object(
            upgrade, "_run_sdk_test", side_effect=sdk
        ), patch.object(
            upgrade, "refresh_token_once", return_value=self.rotated
        ) as refresh, patch.object(
            upgrade, "expect_refresh_invalid_grant_once"
        ) as replay, patch.object(
            upgrade, "_raw_mcp_initialize_status", side_effect=[401, 401, 401]
        ) as access_status, patch.object(
            upgrade, "_validate_refresh_storage_after_rotation"
        ) as rotated_storage, patch.object(
            upgrade, "_validate_refresh_storage_after_reuse"
        ) as replay_storage:
            rotated_file = upgrade._rotate_and_replay_v2_refresh(
                self.runtime,
                object(),  # type: ignore[arg-type]
                object(),
                parameters,
                self.old,
                old_file,
                "authorization-1",
                "v2-kid",
                {},
                self.manifest,
            )
        self.assertEqual(["v1-pkce-refresh.json", "v2-pkce-rotated.json"], sdk_calls)
        self.assertEqual(1, refresh.call_count)
        self.assertEqual(
            upgrade.V2_MINIMUM_REMAINING_TTL_SECONDS,
            refresh.call_args.kwargs["minimum_ttl_seconds"],
        )
        self.assertEqual(2, replay.call_count)
        self.assertEqual(
            [self.old.refresh_token, self.rotated.refresh_token],
            [value.kwargs["refresh_token"] for value in replay.call_args_list],
        )
        self.assertEqual(3, access_status.call_count)
        rotated_storage.assert_called_once()
        replay_storage.assert_called_once_with(self.runtime, ANY, "authorization-1")
        self.assertEqual(0o600, stat.S_IMODE(rotated_file.stat().st_mode))

    def test_ambiguous_refresh_outcome_fails_without_replay_or_retry(self) -> None:
        parameters = upgrade._pkce_parameters(self.runtime, self.manifest)
        old_file = self.credential_root / "v1-pkce-refresh.json"
        upgrade._write_pkce_token_set(old_file, parameters, self.old)
        with patch.object(upgrade, "_public_loopback_resolution", self.loopback), patch.object(
            upgrade, "_run_sdk_test"
        ), patch.object(
            upgrade,
            "refresh_token_once",
            side_effect=TokenEndpointOutcomeUnknown("refresh_token"),
        ) as refresh, patch.object(
            upgrade, "expect_refresh_invalid_grant_once"
        ) as replay, self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "rotation failed"):
            upgrade._rotate_and_replay_v2_refresh(
                self.runtime,
                object(),  # type: ignore[arg-type]
                object(),
                parameters,
                self.old,
                old_file,
                "authorization-1",
                "v2-kid",
                {},
                self.manifest,
            )
        self.assertEqual(1, refresh.call_count)
        replay.assert_not_called()

    def test_v2_rotation_rejects_a_nonstandard_new_access_token_ttl(self) -> None:
        parameters = upgrade._pkce_parameters(self.runtime, self.manifest)
        old_file = self.credential_root / "v1-pkce-refresh.json"
        upgrade._write_pkce_token_set(old_file, parameters, self.old)
        wrong_ttl = OAuthTokenSet(
            access_token=self.rotated.access_token,
            refresh_token=self.rotated.refresh_token,
            token_type=self.rotated.token_type,
            expires_in=upgrade.V2_ACCESS_TOKEN_TTL_SECONDS + 1,
            scopes=self.rotated.scopes,
        )
        with patch.object(upgrade, "_public_loopback_resolution", self.loopback), patch.object(
            upgrade, "_run_sdk_test"
        ), patch.object(
            upgrade, "refresh_token_once", return_value=wrong_ttl
        ), patch.object(
            upgrade, "expect_refresh_invalid_grant_once"
        ) as replay, self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "exact short-lived access-token TTL"
        ):
            upgrade._rotate_and_replay_v2_refresh(
                self.runtime,
                object(),  # type: ignore[arg-type]
                object(),
                parameters,
                self.old,
                old_file,
                "authorization-1",
                "v2-kid",
                {},
                self.manifest,
            )
        replay.assert_not_called()


if __name__ == "__main__":
    unittest.main()
