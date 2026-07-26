from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

from scripts import orchestrate_mcp_governance_restart as restart


PROJECT = "web-starter-governance"
VERSION = "2.0.0"
COMMIT = "a" * 40
APP_ID = "b" * 64
REDIS_ID = "c" * 64
NGINX_ID = "2" * 64
PUBLIC_NGINX_ID = "3" * 64
APP_IMAGE_ID = "sha256:" + "d" * 64
REDIS_IMAGE_ID = "sha256:" + "e" * 64
NGINX_IMAGE_ID = "sha256:" + "4" * 64
APP_REFERENCE = "registry.invalid/web-starter-app@sha256:" + "f" * 64
REDIS_REFERENCE = "redis@sha256:" + "1" * 64
NGINX_REFERENCE = "registry.invalid/web-starter-nginx@sha256:" + "5" * 64
TRACE = "governance-proof"
MARKER = "9" * 64


def inspect_payload(stop_signal: object) -> bytes:
    return json.dumps({
        "id": APP_ID,
        "imageId": APP_IMAGE_ID,
        "imageReference": APP_REFERENCE,
        "labels": {},
        "stopSignal": stop_signal,
        "state": {
            "Running": True,
            "Status": "running",
            "Pid": 100,
            "StartedAt": "2026-07-20T01:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
            "ExitCode": 0,
            "OOMKilled": False,
            "Dead": False,
            "Error": "",
            "Health": {"Status": "healthy"},
        },
        "restartCount": 0,
        "mounts": [],
    }, separators=(",", ":")).encode()


def snapshot(
    service: str,
    *,
    running: bool = True,
    pid: int = 100,
    started: str = "2026-07-20T01:00:00Z",
    finished: str = "0001-01-01T00:00:00Z",
    exit_code: int = 0,
    health: str | None = "healthy",
    stop_signal: str = "",
) -> restart.ContainerSnapshot:
    app = service == "app"
    container_id, image_id, image_reference = {
        "app": (APP_ID, APP_IMAGE_ID, APP_REFERENCE),
        "redis": (REDIS_ID, REDIS_IMAGE_ID, REDIS_REFERENCE),
        "nginx": (NGINX_ID, NGINX_IMAGE_ID, NGINX_REFERENCE),
        "mcp-public-nginx": (
            PUBLIC_NGINX_ID, NGINX_IMAGE_ID, NGINX_REFERENCE,
        ),
    }[service]
    labels = {
        "com.docker.compose.project": PROJECT,
        "com.docker.compose.service": service,
    }
    if service in {"app", "nginx", "mcp-public-nginx"}:
        labels.update({
            "org.opencontainers.image.version": VERSION,
            "org.opencontainers.image.revision": COMMIT,
        })
    return restart.ContainerSnapshot(
        container_id=container_id,
        image_id=image_id,
        image_reference=image_reference,
        labels=labels,
        stop_signal=stop_signal,
        running=running,
        status="running" if running else "exited",
        pid=pid,
        started_at=started,
        finished_at=finished,
        exit_code=exit_code,
        oom_killed=False,
        dead=False,
        error="",
        health=health,
        restart_count=0,
        mounts=(("redis-data", "/data", "volume", True),) if service == "redis" else (),
    )


class GovernanceRestartEvidenceTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = Path(restart.__file__).resolve().parents[1]
        self.raw = self.root / "raw"
        self.raw.mkdir(mode=0o700)
        self.raw.chmod(0o700)
        self.state = self.raw / restart.STATE_FILE
        self.created_ms = int(time.time() * 1_000) - 1_000
        self.state.write_text(
            "schemaVersion=1\n"
            "sessionId=session-governance-1234\n"
            f"createdAtEpochMillis={self.created_ms}\n"
            f"tracePrefix={TRACE}\n"
            "expectedIdleTtlSeconds=50\n"
            "expectedAbsoluteTtlSeconds=60\n"
        )
        self.state.chmod(0o600)
        self.output = self.raw / restart.RECEIPT_FILE

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def kwargs(self) -> dict[str, object]:
        return {
            "repository_root": self.repository,
            "state_file": self.state,
            "output": self.output,
            "compose_project": PROJECT,
            "app_container_id": APP_ID,
            "redis_container_id": REDIS_ID,
            "nginx_container_id": NGINX_ID,
            "public_nginx_container_id": PUBLIC_NGINX_ID,
            "expected_app_image_id": APP_IMAGE_ID,
            "expected_app_reference": APP_REFERENCE,
            "expected_redis_image_id": REDIS_IMAGE_ID,
            "expected_redis_reference": REDIS_REFERENCE,
            "expected_nginx_image_id": NGINX_IMAGE_ID,
            "expected_nginx_reference": NGINX_REFERENCE,
            "candidate_version": VERSION,
            "candidate_commit": COMMIT,
            "trace_prefix": TRACE,
            "redis_password": "private-redis-password",
        }

    def run_with(
        self,
        old_app: restart.ContainerSnapshot | None = None,
        stopped: restart.ContainerSnapshot | None = None,
        new_redis: restart.ContainerSnapshot | None = None,
        new_ingress: tuple[
            restart.ContainerSnapshot, restart.ContainerSnapshot
        ] | None = None,
        redis_results_override: list[str] | None = None,
        docker_commands: list[tuple[object, ...]] | None = None,
    ) -> dict[str, object]:
        initial_app = old_app or snapshot("app")
        old_redis = snapshot("redis", pid=200)
        stopped_app = stopped or snapshot(
            "app",
            running=False,
            pid=0,
            finished="2026-07-20T01:01:00Z",
            health=None,
        )
        new_app = snapshot("app", pid=101, started="2026-07-20T01:01:01Z")
        final_redis = new_redis or old_redis
        old_ingress = (snapshot("nginx", pid=300), snapshot("mcp-public-nginx", pid=400))
        final_ingress = new_ingress or old_ingress
        snapshots = [initial_app, old_redis, stopped_app, old_redis, final_redis]
        redis_results = ["OK", MARKER, MARKER, MARKER, "120", "1"]
        if not stopped_app.running and stopped_app.exit_code not in {0, 143}:
            snapshots = [initial_app, old_redis, stopped_app, old_redis, stopped_app]
            redis_results = ["OK", MARKER, "1"]
        elif new_redis is not None and new_redis != old_redis:
            snapshots.append(new_app)
            redis_results = ["OK", MARKER, MARKER, "1"]
        elif new_ingress is not None and new_ingress != old_ingress:
            snapshots.append(new_app)
            redis_results = ["OK", MARKER, MARKER, "1"]
        if redis_results_override is not None:
            redis_results = redis_results_override

        def docker(*arguments: object, **_kwargs: object) -> bytes:
            if docker_commands is not None:
                docker_commands.append(arguments)
            return b""

        with mock.patch.object(
            restart,
            "_snapshot_container",
            side_effect=snapshots,
        ), mock.patch.object(restart, "_wait_for_healthy", return_value=new_app), \
                mock.patch.object(restart, "_docker", side_effect=docker), \
                mock.patch.object(restart, "_redis_cli", side_effect=redis_results), \
                mock.patch.object(
                    restart, "_snapshot_ingress_pair",
                    side_effect=[old_ingress, final_ingress],
                ), \
                mock.patch.object(restart.secrets, "token_hex", return_value=MARKER):
            return restart.orchestrate(**self.kwargs())

    def test_records_graceful_process_and_redis_continuity(self) -> None:
        commands: list[tuple[object, ...]] = []
        document = self.run_with(docker_commands=commands)

        self.assertEqual("PASS", document["status"])
        self.assertEqual(
            hashlib.sha256(Path(restart.__file__).read_bytes()).hexdigest(),
            document["producerSha256"],
        )
        self.assertEqual(COMMIT, document["candidate"]["gitCommit"])
        self.assertEqual(0, document["gracefulRestart"]["stopped"]["exitCode"])
        self.assertTrue(document["redisContinuity"]["markerSurvived"])
        self.assertTrue(document["ingressContinuity"]["healthyAfterRestart"])
        self.assertEqual(
            {"nginx", "mcp-public-nginx"},
            set(document["ingressContinuity"]["services"]),
        )
        self.assertTrue(self.output.is_file())
        self.assertEqual(0o600, self.output.stat().st_mode & 0o777)
        self.assertEqual(
            {restart.STATE_FILE, restart.RECEIPT_FILE},
            {path.name for path in self.raw.iterdir()},
        )
        self.assertIn(
            ("stop", "--timeout", str(restart.STOP_TIMEOUT_SECONDS), APP_ID),
            commands,
        )
        self.assertFalse(any("--time" in command for command in commands))

    def test_rejects_forced_kill_instead_of_graceful_stop(self) -> None:
        killed = snapshot(
            "app",
            running=False,
            pid=0,
            finished="2026-07-20T01:01:00Z",
            exit_code=137,
            health=None,
        )

        with self.assertRaisesRegex(restart.RestartEvidenceError, "graceful SIGTERM"):
            self.run_with(stopped=killed)
        self.assertFalse(self.output.exists())

    def test_recovery_failure_is_reported_and_never_publishes_receipt(self) -> None:
        old_app = snapshot("app")
        old_redis = snapshot("redis", pid=200)
        stopped_app = snapshot(
            "app", running=False, pid=0,
            finished="2026-07-20T01:01:00Z", health=None,
        )

        def docker(*arguments: object, **_kwargs: object) -> bytes:
            if arguments[0] == "stop":
                raise restart.RestartEvidenceError("stop result lost")
            raise restart.RestartEvidenceError("recovery start failed")

        with mock.patch.object(
            restart, "_snapshot_container", side_effect=[old_app, old_redis, stopped_app]
        ), mock.patch.object(
            restart, "_snapshot_ingress_pair",
            return_value=(snapshot("nginx"), snapshot("mcp-public-nginx")),
        ), mock.patch.object(restart, "_docker", side_effect=docker), \
                mock.patch.object(restart, "_redis_cli", side_effect=["OK", MARKER, "1"]), \
                mock.patch.object(restart.secrets, "token_hex", return_value=MARKER):
            with self.assertRaisesRegex(restart.RestartEvidenceError, "app recovery failed"):
                restart.orchestrate(**self.kwargs())
        self.assertFalse(self.output.exists())
        self.assertEqual({restart.STATE_FILE}, {path.name for path in self.raw.iterdir()})

    def test_marker_cleanup_failure_blocks_receipt(self) -> None:
        with self.assertRaisesRegex(restart.RestartEvidenceError, "marker cleanup failed"):
            self.run_with(redis_results_override=[
                "OK", MARKER, MARKER, MARKER, "120", "0",
            ])
        self.assertFalse(self.output.exists())
        self.assertEqual({restart.STATE_FILE}, {path.name for path in self.raw.iterdir()})

    def test_rejects_redis_process_or_volume_discontinuity(self) -> None:
        changed = snapshot("redis", pid=201, started="2026-07-20T01:01:01Z")

        with self.assertRaisesRegex(restart.RestartEvidenceError, "Redis container, process"):
            self.run_with(new_redis=changed)
        self.assertFalse(self.output.exists())

    def test_rejects_nginx_process_discontinuity(self) -> None:
        changed_private = snapshot(
            "nginx", pid=301, started="2026-07-20T01:01:01Z"
        )
        with self.assertRaisesRegex(restart.RestartEvidenceError, "nginx changed"):
            self.run_with(
                new_ingress=(changed_private, snapshot("mcp-public-nginx", pid=400))
            )
        self.assertFalse(self.output.exists())

    def test_ingress_pair_requires_both_exact_release_containers(self) -> None:
        with mock.patch.object(
            restart,
            "_snapshot_container",
            side_effect=[snapshot("nginx"), snapshot("mcp-public-nginx")],
        ):
            private, public = restart._snapshot_ingress_pair(
                private_container_id=NGINX_ID,
                public_container_id=PUBLIC_NGINX_ID,
                expected_image_id=NGINX_IMAGE_ID,
                expected_reference=NGINX_REFERENCE,
                compose_project=PROJECT,
                candidate_version=VERSION,
                candidate_commit=COMMIT,
            )
        self.assertEqual(NGINX_ID, private.container_id)
        self.assertEqual(PUBLIC_NGINX_ID, public.container_id)

        with mock.patch.object(
            restart,
            "_snapshot_container",
            side_effect=[snapshot("nginx"), snapshot("mcp-public-nginx")],
        ), self.assertRaisesRegex(restart.RestartEvidenceError, "image identity"):
            restart._snapshot_ingress_pair(
                private_container_id=NGINX_ID,
                public_container_id=PUBLIC_NGINX_ID,
                expected_image_id="sha256:" + "6" * 64,
                expected_reference=NGINX_REFERENCE,
                compose_project=PROJECT,
                candidate_version=VERSION,
                candidate_commit=COMMIT,
            )

    def test_rejects_non_sigterm_container_before_any_runtime_mutation(self) -> None:
        non_sigterm = snapshot("app", stop_signal="SIGQUIT")

        with self.assertRaisesRegex(restart.RestartEvidenceError, "SIGTERM"):
            self.run_with(old_app=non_sigterm)
        self.assertFalse(self.output.exists())

    def test_preflights_repository_boundary_before_docker_or_redis(self) -> None:
        unsafe_output = self.repository / restart.RECEIPT_FILE
        values = self.kwargs()
        values["output"] = unsafe_output
        with mock.patch.object(restart, "_snapshot_container") as inspect, \
                mock.patch.object(restart, "_redis_cli") as redis:
            with self.assertRaisesRegex(restart.RestartEvidenceError, "outside the Git"):
                restart.orchestrate(**values)
        inspect.assert_not_called()
        redis.assert_not_called()

    def test_rejects_raw_directory_replacement_and_removes_unpublished_receipt(self) -> None:
        moved = self.root / "raw-moved"

        def replace_raw_directory(*_arguments: object) -> None:
            self.raw.rename(moved)
            self.raw.mkdir(mode=0o700)

        with mock.patch.object(
            restart,
            "_require_unchanged_executing_source",
            side_effect=replace_raw_directory,
        ):
            with self.assertRaisesRegex(restart.RestartEvidenceError, "directory changed"):
                self.run_with()

        self.assertFalse(self.output.exists())
        self.assertEqual(set(), {path.name for path in self.raw.iterdir()})
        self.assertEqual({restart.STATE_FILE}, {path.name for path in moved.iterdir()})

    def test_outer_finally_discards_reservation_when_publish_precheck_is_interrupted(self) -> None:
        with mock.patch.object(
            restart,
            "_require_unchanged_executing_source",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.run_with()

        self.assertEqual({restart.STATE_FILE}, {path.name for path in self.raw.iterdir()})

    def test_recovers_and_rechecks_health_when_stop_command_loses_result(self) -> None:
        old_app = snapshot("app")
        old_redis = snapshot("redis", pid=200)
        stopped_app = snapshot(
            "app", running=False, pid=0,
            finished="2026-07-20T01:01:00Z", health=None,
        )
        recovered = snapshot("app", pid=101, started="2026-07-20T01:01:01Z")
        commands: list[tuple[object, ...]] = []

        def docker(*arguments: object, **_kwargs: object) -> bytes:
            commands.append(arguments)
            if arguments[0] == "stop":
                raise restart.RestartEvidenceError("stop result lost")
            return b""

        with mock.patch.object(
            restart, "_snapshot_container", side_effect=[old_app, old_redis, stopped_app]
        ), mock.patch.object(
            restart, "_snapshot_ingress_pair",
            return_value=(snapshot("nginx"), snapshot("mcp-public-nginx")),
        ), mock.patch.object(restart, "_wait_for_healthy", return_value=recovered), \
                mock.patch.object(restart, "_docker", side_effect=docker), \
                mock.patch.object(restart, "_redis_cli", side_effect=["OK", MARKER, "1"]), \
                mock.patch.object(restart.secrets, "token_hex", return_value=MARKER):
            with self.assertRaisesRegex(restart.RestartEvidenceError, "stop result lost"):
                restart.orchestrate(**self.kwargs())

        self.assertTrue(any(command[0] == "start" for command in commands))
        self.assertFalse(self.output.exists())

    def test_interrupt_after_stop_still_recovers_cleans_marker_and_reservation(self) -> None:
        old_app = snapshot("app")
        old_redis = snapshot("redis", pid=200)
        stopped_app = snapshot(
            "app", running=False, pid=0,
            finished="2026-07-20T01:01:00Z", health=None,
        )
        recovered = snapshot("app", pid=101, started="2026-07-20T01:01:01Z")
        commands: list[tuple[object, ...]] = []
        redis_commands: list[tuple[object, ...]] = []

        def docker(*arguments: object, **_kwargs: object) -> bytes:
            commands.append(arguments)
            if arguments[0] == "stop":
                raise KeyboardInterrupt()
            return b""

        def redis_cli(*arguments: object, **_kwargs: object) -> str:
            redis_commands.append(arguments)
            if "SET" in arguments:
                return "OK"
            if "GET" in arguments:
                return MARKER
            if "DEL" in arguments:
                return "1"
            raise AssertionError(f"unexpected Redis command: {arguments!r}")

        with mock.patch.object(
            restart, "_snapshot_container", side_effect=[old_app, old_redis, stopped_app]
        ), mock.patch.object(
            restart, "_snapshot_ingress_pair",
            return_value=(snapshot("nginx"), snapshot("mcp-public-nginx")),
        ), mock.patch.object(restart, "_wait_for_healthy", return_value=recovered), \
                mock.patch.object(restart, "_docker", side_effect=docker), \
                mock.patch.object(restart, "_redis_cli", side_effect=redis_cli), \
                mock.patch.object(restart.secrets, "token_hex", return_value=MARKER):
            with self.assertRaises(KeyboardInterrupt):
                restart.orchestrate(**self.kwargs())

        self.assertTrue(any(command[0] == "start" for command in commands))
        self.assertTrue(any("DEL" in command for command in redis_commands))
        self.assertEqual({restart.STATE_FILE}, {path.name for path in self.raw.iterdir()})

    def test_rejects_stale_probe_before_docker_or_redis(self) -> None:
        stale_ms = int(time.time() * 1_000) \
                - (restart.PROBE_MAX_AGE_SECONDS + 1) * 1_000
        self.state.write_text(self.state.read_text().replace(
            str(self.created_ms), str(stale_ms)))
        self.state.chmod(0o600)
        with mock.patch.object(restart, "_snapshot_container") as inspect, \
                mock.patch.object(restart, "_redis_cli") as redis:
            with self.assertRaisesRegex(restart.RestartEvidenceError, "stale"):
                restart.orchestrate(**self.kwargs())
        inspect.assert_not_called()
        redis.assert_not_called()

    def test_rejects_trace_drift_and_unsafe_state_file(self) -> None:
        self.state.write_text(self.state.read_text().replace(TRACE, "other-trace"))
        self.state.chmod(0o600)

        with self.assertRaisesRegex(restart.RestartEvidenceError, "trace-bound"):
            restart.orchestrate(**self.kwargs())

        self.state.unlink()
        target = self.raw / "actual-state"
        target.write_text("state")
        target.chmod(0o600)
        self.state.symlink_to(target.name)
        with self.assertRaisesRegex(restart.RestartEvidenceError, "cannot open"):
            restart.orchestrate(**self.kwargs())

    def test_rejects_malformed_docker_inspect_envelope(self) -> None:
        with mock.patch.object(restart, "_docker", return_value=b"{}"):
            with self.assertRaisesRegex(restart.RestartEvidenceError, "unexpected envelope"):
                restart._snapshot_container(APP_ID)

    def test_inspect_template_preserves_only_null_as_default_stop_signal(self) -> None:
        self.assertIn(
            '{{json (index .Config "StopSignal")}}',
            restart.DOCKER_INSPECT_TEMPLATE,
        )
        self.assertNotIn(".Config.StopSignal", restart.DOCKER_INSPECT_TEMPLATE)

        with mock.patch.object(restart, "_docker", return_value=inspect_payload(None)) as docker:
            missing = restart._snapshot_container(APP_ID)
        self.assertEqual("", missing.stop_signal)
        docker.assert_called_once_with(
            "inspect", "--type", "container", "--format",
            restart.DOCKER_INSPECT_TEMPLATE, APP_ID,
        )

        with mock.patch.object(
            restart, "_docker", return_value=inspect_payload("SIGQUIT")
        ):
            explicit = restart._snapshot_container(APP_ID)
        with self.assertRaisesRegex(restart.RestartEvidenceError, "SIGTERM"):
            restart._resolved_stop_signal(explicit)

        for malformed in (False, 0, [], {}):
            with self.subTest(stop_signal=malformed), mock.patch.object(
                restart, "_docker", return_value=inspect_payload(malformed)
            ):
                with self.assertRaisesRegex(
                    restart.RestartEvidenceError, "stop signal is invalid"
                ):
                    restart._snapshot_container(APP_ID)

    def test_parses_docker_rfc3339nano_without_losing_order(self) -> None:
        earlier = restart._parse_timestamp(
            "2026-07-20T03:19:00.518599094Z", "Docker startedAt"
        )
        later = restart._parse_timestamp(
            "2026-07-20T03:19:00.518599095Z", "Docker startedAt"
        )
        self.assertIsInstance(earlier, int)
        self.assertEqual(1, later - earlier)
        self.assertIsNone(restart._parse_timestamp(
            "0001-01-01T00:00:00Z", "Docker finishedAt", allow_zero=True
        ))
        for invalid in (
            "0001-01-01T00:00:00Z",
            "2026-07-20T03:19:00.1234567890Z",
            "2026-07-20T03:19:00.123456789+00:00",
            "2026-02-30T03:19:00Z",
        ):
            with self.subTest(timestamp=invalid), self.assertRaisesRegex(
                restart.RestartEvidenceError, "timestamp is invalid"
            ):
                restart._parse_timestamp(invalid, "Docker startedAt")

    def test_bounded_runner_kills_timeout_and_rejects_output_overflow(self) -> None:
        with self.assertRaisesRegex(restart.RestartEvidenceError, "timed out"):
            restart._run_bounded(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout_seconds=1,
                environment={"PATH": "/usr/bin:/bin"},
            )
        with mock.patch.object(restart, "MAX_COMMAND_STDOUT", 1_024):
            with self.assertRaisesRegex(restart.RestartEvidenceError, "byte limit"):
                restart._run_bounded(
                    [sys.executable, "-c", "print('x' * 2048)"],
                    timeout_seconds=3,
                    environment={"PATH": "/usr/bin:/bin"},
                )


if __name__ == "__main__":
    unittest.main()
