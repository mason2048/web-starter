from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_operational_metrics as metrics


def snapshot(values: dict[str, float]) -> dict:
    return {
        "authorization": {
            "healthAnonymous": 200,
            "infoAnonymous": 401,
            "metricsAnonymous": 401,
            "metricsWrongCredential": 401,
            "infoOperationalCredential": 200,
            "metricsOperationalCredential": 200,
            "prometheusOperationalCredential": 200,
        },
        "metrics": {
            name: {
                "present": name in values,
                "measurements": {"COUNT": values.get(name, 0.0)},
                "tags": {},
            }
            for name in metrics.SNAPSHOT_METRICS
        },
        "protocolEndpoints": {
            endpoint: {
                "present": True,
                "measurements": {"COUNT": values.get("webstarter.protocol.requests", 0.0)},
                "tags": {},
            }
            for endpoint in metrics.PROTOCOL_ENDPOINTS
        },
    }


class VerifyOperationalMetricsTest(unittest.TestCase):

    def test_https_metrics_reject_tls_key_logging_before_context_creation(self) -> None:
        with patch.dict(os.environ, {"SSLKEYLOGFILE": "/tmp/metrics.keys"}, clear=False):
            with self.assertRaisesRegex(metrics.OperationalMetricsError, "must be unset"):
                metrics._opener("https://127.0.0.1:18081")

    def test_request_uses_the_requested_representation(self) -> None:
        captured = {}

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b""

        class Opener:
            def open(self, request, timeout):
                captured["accept"] = request.get_header("Accept")
                captured["timeout"] = timeout
                return Response()

        status, _ = metrics._request(
            Opener(),
            "http://127.0.0.1:18081/actuator/prometheus",
            accept="text/plain",
        )

        self.assertEqual(200, status)
        self.assertEqual("text/plain", captured["accept"])
        self.assertEqual(20, captured["timeout"])

    def test_accepts_required_runtime_deltas(self) -> None:
        before = snapshot({name: 1.0 for name in metrics.SNAPSHOT_METRICS})
        after = snapshot({name: 2.0 for name in metrics.SNAPSHOT_METRICS})

        checks = metrics.evaluate(before, after, True, True)

        self.assertTrue(all(checks.values()))

    def test_fails_when_a_required_counter_does_not_move(self) -> None:
        before = snapshot({name: 1.0 for name in metrics.SNAPSHOT_METRICS})
        after = snapshot({name: 2.0 for name in metrics.SNAPSHOT_METRICS})
        after["metrics"]["webstarter.audit.operations"]["measurements"]["COUNT"] = 1.0

        checks = metrics.evaluate(before, after, False, False)

        self.assertFalse(checks["operationAuditCounterIncreased"])

    def test_rejects_identity_and_secret_tag_material(self) -> None:
        documents = {
            name: {
                "present": True,
                "measurements": {"COUNT": 0.0},
                "tags": {
                    key: sorted(values)
                    for key, values in metrics.ALLOWED_TAG_VALUES[name].items()
                },
            }
            for name in metrics.CUSTOM_METRICS
        }
        documents["webstarter.mcp.calls"] = {
            "present": True,
            "measurements": {"COUNT": 1.0},
            "tags": {"subject": ["user-7"]},
        }

        with self.assertRaises(metrics.OperationalMetricsError):
            metrics._validate_custom_tags(documents, "operations-password")

    def test_rejects_missing_or_incomplete_metric_series(self) -> None:
        documents = {
            name: {
                "present": True,
                "measurements": {"COUNT": 0.0},
                "tags": {
                    key: sorted(values)
                    for key, values in metrics.ALLOWED_TAG_VALUES[name].items()
                },
            }
            for name in metrics.CUSTOM_METRICS
        }
        documents["webstarter.audit.persist.failures"]["present"] = False
        with self.assertRaisesRegex(metrics.OperationalMetricsError, "not pre-registered"):
            metrics._validate_custom_tags(documents, "operations-password")

        documents["webstarter.audit.persist.failures"]["present"] = True
        documents["webstarter.protocol.requests"]["tags"]["endpoint"] = ["mcp"]
        with self.assertRaisesRegex(metrics.OperationalMetricsError, "incomplete or drifting"):
            metrics._validate_custom_tags(documents, "operations-password")

    def test_accepts_only_loopback_management_origins(self) -> None:
        self.assertEqual(
            "http://127.0.0.1:18081",
            metrics._base_url("http://127.0.0.1:18081/"),
        )
        with self.assertRaises(metrics.OperationalMetricsError):
            metrics._base_url("http://10.0.0.8:8081")

    def test_extracts_only_bounded_ecs_protocol_log_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("compose.yaml", "override.yaml", "runtime.env")]
            for path in paths:
                path.write_text("safe\n", encoding="utf-8")
            line = (
                b'app-1 | {"@timestamp":"2026-07-20T08:00:00Z","log":{"level":"INFO"},'
                b'"message":"protocol_request","traceId":"release-observe-123",'
                b'"endpoint":"mcp","method":"POST","outcome":"SUCCESS",'
                b'"ignored":"must-not-be-copied"}\n'
            )

            def run(command, **kwargs):
                self.assertEqual("docker", command[0])
                self.assertEqual(60, kwargs["timeout"])
                return subprocess.CompletedProcess(command, 0, line, b"")

            sample = metrics._structured_log_sample(
                paths[0], paths[1], paths[2], "web-starter-observe", run
            )

            self.assertEqual("ecs", sample["format"])
            self.assertEqual("release-observe-123", sample["traceId"])
            self.assertNotIn("ignored", sample)
            self.assertRegex(sample["sourceLineSha256"], r"^[0-9a-f]{64}$")

    def test_structured_log_fails_closed_without_a_valid_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("compose.yaml", "override.yaml", "runtime.env")]
            for path in paths:
                path.write_text("safe\n", encoding="utf-8")

            def run(command, **_kwargs):
                return subprocess.CompletedProcess(
                    command, 0,
                    b'app-1 | {"message":"protocol_request","traceId":"short"}\n', b"",
                )

            with self.assertRaisesRegex(metrics.OperationalMetricsError, "no bounded ECS"):
                metrics._structured_log_sample(
                    paths[0], paths[1], paths[2], "web-starter-observe", run
                )


if __name__ == "__main__":
    unittest.main()
