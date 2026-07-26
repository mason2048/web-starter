from __future__ import annotations

import copy
import unittest

import validate_observability_evidence as evidence


def metric(name: str, count: float) -> dict:
    tags = {
        key: sorted(values)
        for key, values in evidence.CUSTOM_TAGS.get(name, {}).items()
    }
    return {"present": True, "measurements": {"COUNT": count}, "tags": tags}


def documents() -> tuple[dict, dict]:
    before = {
        "schemaVersion": 1,
        "status": "SNAPSHOT",
        "observedAt": "2026-07-20T00:00:00+00:00",
        "authorization": dict(evidence.AUTHORIZATION),
        "metrics": {name: metric(name, 1.0) for name in evidence.METRICS},
        "protocolEndpoints": {
            endpoint: {"present": True, "measurements": {"COUNT": 1.0}, "tags": {}}
            for endpoint in evidence.PROTOCOL_ENDPOINTS
        },
    }
    after = copy.deepcopy(before)
    after.update({
        "status": "PASS",
        "observedAt": "2026-07-20T01:00:00+00:00",
        "baselineObservedAt": before["observedAt"],
        "structuredLog": {
            "format": "ecs",
            "timestamp": "2026-07-20T00:30:00.123456789Z",
            "level": "INFO",
            "message": "protocol_request",
            "traceId": "release-observe-123",
            "endpoint": "mcp",
            "method": "POST",
            "outcome": "SUCCESS",
            "sourceLineSha256": "a" * 64,
        },
    })
    for value in after["metrics"].values():
        value["measurements"]["COUNT"] = 2.0
    for value in after["protocolEndpoints"].values():
        value["measurements"]["COUNT"] = 2.0
    after["checks"] = {
        "authorizationMatrix": True,
        "operationAuditCounterIncreased": True,
        "loginAttemptCounterIncreased": True,
        "mcpCallCounterIncreased": True,
        "mcpCallDurationCounterIncreased": True,
        "mcpSessionCounterIncreased": True,
        "hikariUsageCounterIncreased": True,
        "loginProtocolCounterIncreased": True,
        "oauth_tokenProtocolCounterIncreased": True,
        "mcpProtocolCounterIncreased": True,
        "rateLimitedCounterIncreased": True,
    }
    return before, after


class ObservabilityEvidenceTest(unittest.TestCase):

    def test_exact_metric_and_structured_log_contract_passes(self) -> None:
        before, after = documents()
        checks = evidence.validate_reports(before, after)
        self.assertEqual("PASS", checks["structuredTraceLog"])
        self.assertEqual(
            evidence.EXPECTED_CHECKS | {"structuredTraceLog"}, set(checks)
        )

    def test_missing_metric_and_high_cardinality_tag_are_rejected(self) -> None:
        before, after = documents()
        del after["metrics"]["webstarter.audit.persist.failures"]
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "inventory"):
            evidence.validate_reports(before, after)

        before, after = documents()
        after["metrics"]["webstarter.mcp.calls"]["tags"]["subject"] = ["user-7"]
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "tag keys"):
            evidence.validate_reports(before, after)

    def test_zero_delta_or_self_reported_check_drift_is_rejected(self) -> None:
        before, after = documents()
        after["metrics"]["webstarter.login.attempts"]["measurements"]["COUNT"] = 1.0
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "deltas"):
            evidence.validate_reports(before, after)

        before, after = documents()
        after["checks"]["unexpected"] = True
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "deltas"):
            evidence.validate_reports(before, after)

    def test_structured_log_requires_ecs_trace_and_fixed_dimensions(self) -> None:
        before, after = documents()
        after["structuredLog"]["traceId"] = "short"
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "ECS"):
            evidence.validate_reports(before, after)

        before, after = documents()
        after["structuredLog"]["actor"] = "admin"
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "unexpected"):
            evidence.validate_reports(before, after)

    def test_structured_log_timestamp_rejects_unbounded_precision_and_missing_timezone(self) -> None:
        before, after = documents()
        after["structuredLog"]["timestamp"] = "2026-07-20T00:30:00.1234567890Z"
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "ISO-8601"):
            evidence.validate_reports(before, after)

        before, after = documents()
        after["structuredLog"]["timestamp"] = "2026-07-20T00:30:00.123456789"
        with self.assertRaisesRegex(evidence.ObservabilityEvidenceError, "ISO-8601"):
            evidence.validate_reports(before, after)


if __name__ == "__main__":
    unittest.main()
