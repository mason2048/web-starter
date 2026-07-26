from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import scripts.rehearse_v1_to_v2_upgrade as upgrade


RUN_ID = "13579bdf2468"
COMMIT = "a" * 40
TREE = "b" * 40


class V1UpgradeSourceImageBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-upgrade-binding-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runtime(self) -> upgrade.RuntimeContext:
        runtime_root = self.root / "runtime"
        runtime_root.mkdir(mode=0o700, exist_ok=True)
        runtime = upgrade.RuntimeContext(
            self.root,
            runtime_root,
            upgrade.generate_resource_names(RUN_ID),
            upgrade.Ports(28080, 28443, 28081),
            upgrade.EvidenceState(),
        )
        runtime.compose_files_v1 = (self.root / "v1.yaml",)
        runtime.compose_files_v2 = (self.root / "v2.yaml",)
        runtime.resolved_images = {
            "mysql": "sha256:" + "1" * 64,
            "redis": "sha256:" + "2" * 64,
            "v1-app": "sha256:" + "3" * 64,
            "v1-nginx": "sha256:" + "4" * 64,
            "v2-app": "sha256:" + "5" * 64,
            "v2-nginx": "sha256:" + "6" * 64,
        }
        return runtime

    def frozen_candidate_source(self, runtime: upgrade.RuntimeContext) -> Path:
        source = runtime.runtime_root / "v2-sdk-source"
        (source / "deploy/nginx").mkdir(parents=True, mode=0o700)
        (source / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (source / "deploy/nginx/Dockerfile").write_text(
            "FROM scratch\n", encoding="utf-8"
        )
        runtime.sdk_source_root = source
        runtime.sdk_source_hashes = {
            path.relative_to(source).as_posix(): upgrade.sha256_file(path)
            for path in sorted(source.rglob("*"))
            if path.is_file()
        }
        runtime.v2_commit = COMMIT
        return source

    @staticmethod
    def fake_git(*, dirty: bool = False, tracked: bytes = b"H pom.xml\0"):
        def run(arguments: tuple[str, ...]) -> bytes:
            if arguments == ("rev-parse", "--verify", "HEAD^{commit}"):
                return (COMMIT + "\n").encode("ascii")
            if arguments == ("rev-parse", "--verify", "HEAD^{tree}"):
                return (TREE + "\n").encode("ascii")
            if arguments == ("merge-base", "--is-ancestor", upgrade.V1_COMMIT, COMMIT):
                return b""
            if arguments == ("ls-files", "-v", "-z"):
                return tracked
            if arguments == ("status", "--porcelain=v1", "-z", "--untracked-files=all"):
                return b" M pom.xml\0" if dirty else b""
            raise AssertionError(arguments)

        return run

    def test_clean_commit_and_tree_are_bound_and_dirty_worktree_fails_closed(self) -> None:
        runtime = self.runtime()
        identity = upgrade.validate_v2_source_identity(self.fake_git(), runtime)
        self.assertEqual(COMMIT, identity["commit"])
        self.assertEqual(TREE, identity["tree"])
        self.assertTrue(runtime.clean_worktree)

        dirty_runtime = self.runtime()
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "clean worktree"):
            upgrade.validate_v2_source_identity(self.fake_git(dirty=True), dirty_runtime)
        self.assertEqual(COMMIT, dirty_runtime.v2_commit)
        self.assertEqual(TREE, dirty_runtime.v2_tree)
        self.assertFalse(dirty_runtime.clean_worktree)

    def test_assume_unchanged_or_skip_worktree_index_flags_are_rejected(self) -> None:
        for tracked in (b"h pom.xml\0", b"S pom.xml\0", b"s pom.xml\0"):
            with self.subTest(tracked=tracked), self.assertRaisesRegex(
                upgrade.UpgradeRehearsalError, "assume-unchanged"
            ):
                upgrade.validate_v2_source_identity(self.fake_git(tracked=tracked))

    def test_candidate_revision_label_must_match_the_frozen_commit(self) -> None:
        upgrade._validate_candidate_image_revision(
            "v2-app", {"org.opencontainers.image.revision": COMMIT}, COMMIT
        )
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "revision"):
            upgrade._validate_candidate_image_revision(
                "v2-nginx", {"org.opencontainers.image.revision": TREE}, COMMIT
            )
        upgrade._validate_candidate_image_revision("mysql", {}, COMMIT)

    def test_production_image_environment_separates_aliases_from_image_ids(self) -> None:
        runtime = self.runtime()
        runtime.created_image_tags = {
            "mysql": f"web-starter-upgrade-{RUN_ID}-mysql:candidate",
            "redis": f"web-starter-upgrade-{RUN_ID}-redis:candidate",
            "v2-app": f"web-starter-upgrade-{RUN_ID}-v2-app:candidate",
            "v2-nginx": f"web-starter-upgrade-{RUN_ID}-v2-nginx:candidate",
        }

        values = upgrade._production_image_environment(runtime)

        self.assertEqual(
            runtime.created_image_tags["v2-app"], values["WEB_STARTER_APP_IMAGE"]
        )
        self.assertEqual(
            runtime.resolved_images["v2-app"], values["WEB_STARTER_APP_DIGEST"]
        )
        self.assertEqual(
            runtime.resolved_images["v2-nginx"], values["WEB_STARTER_NGINX_DIGEST"]
        )

    def test_production_image_environment_rejects_unsafe_alias_or_mutable_digest(self) -> None:
        runtime = self.runtime()
        runtime.created_image_tags = {
            "mysql": f"web-starter-upgrade-{RUN_ID}-mysql:candidate",
            "redis": f"web-starter-upgrade-{RUN_ID}-redis:candidate",
            "v2-app": runtime.resolved_images["v2-app"],
            "v2-nginx": f"web-starter-upgrade-{RUN_ID}-v2-nginx:candidate",
        }
        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "image reference is unsafe"
        ):
            upgrade._production_image_environment(runtime)

        runtime.created_image_tags["v2-app"] = (
            f"web-starter-upgrade-{RUN_ID}-v2-app:candidate"
        )
        runtime.resolved_images["v2-nginx"] = "registry.example.test/app:mutable"
        with self.assertRaisesRegex(
            upgrade.UpgradeRehearsalError, "immutable SHA256 image ID"
        ):
            upgrade._production_image_environment(runtime)

    def test_v2_images_are_built_once_from_the_frozen_commit_archive(self) -> None:
        runtime = self.runtime()
        source = self.frozen_candidate_source(runtime)

        class BuildRunner:
            def __init__(self) -> None:
                self.built: dict[str, tuple[str, dict[str, str]]] = {}
                self.build_calls: list[tuple[list[str], dict[str, object]]] = []

            def run(self, command, **kwargs):
                values = list(command)
                if values[:3] == ["docker", "image", "inspect"]:
                    reference = values[-1]
                    if reference not in self.built:
                        return upgrade.CommandResult(1, b"", b"not found")
                    image_id, labels = self.built[reference]
                    document = [{"Id": image_id, "Config": {"Labels": labels}}]
                    return upgrade.CommandResult(0, json.dumps(document).encode("utf-8"), b"")
                if values[:3] == ["docker", "image", "ls"]:
                    return upgrade.CommandResult(0, b"", b"")
                if values[:2] == ["docker", "build"]:
                    self.build_calls.append((values, dict(kwargs)))
                    tag = values[values.index("--tag") + 1]
                    role = next(
                        value.split("=", 1)[1]
                        for value in values
                        if value.startswith(f"{upgrade.LABEL_ROLE}=")
                    )
                    character = "5" if role == "v2-app" else "6"
                    labels = {
                        upgrade.LABEL_OWNER: upgrade.OWNER_VALUE,
                        upgrade.LABEL_RUN: RUN_ID,
                        upgrade.LABEL_ROLE: role,
                        "org.opencontainers.image.revision": COMMIT,
                    }
                    self.built[tag] = ("sha256:" + character * 64, labels)
                    return upgrade.CommandResult(0, b"", b"")
                raise AssertionError(values)

        runner = BuildRunner()
        upgrade._build_v2_images(runtime, runner)  # type: ignore[arg-type]
        self.assertEqual(2, len(runner.build_calls))
        self.assertEqual({"v2-app", "v2-nginx"}, set(runtime.created_image_ids))
        observed_roles: set[str] = set()
        for command, kwargs in runner.build_calls:
            role = next(
                value.split("=", 1)[1]
                for value in command
                if value.startswith(f"{upgrade.LABEL_ROLE}=")
            )
            observed_roles.add(role)
            self.assertEqual(str(source), command[-1])
            dockerfile = Path(command[command.index("--file") + 1])
            self.assertTrue(dockerfile.is_relative_to(source))
            expected_dockerfile = (
                source / "Dockerfile"
                if role == "v2-app"
                else source / "deploy/nginx/Dockerfile"
            )
            self.assertEqual(expected_dockerfile, dockerfile)
            self.assertEqual(
                f"web-starter-upgrade-{RUN_ID}-{role}:candidate",
                command[command.index("--tag") + 1],
            )
            labels = [
                command[index + 1]
                for index, value in enumerate(command)
                if value == "--label"
            ]
            self.assertEqual({
                f"{upgrade.LABEL_OWNER}={upgrade.OWNER_VALUE}",
                f"{upgrade.LABEL_RUN}={RUN_ID}",
                f"{upgrade.LABEL_ROLE}={role}",
                f"org.opencontainers.image.revision={COMMIT}",
            }, set(labels))
            self.assertTrue(kwargs["replace_environment"])
            environment = kwargs["environment"]
            self.assertEqual("1", environment["DOCKER_BUILDKIT"])  # type: ignore[index]
            self.assertFalse(any(
                key.startswith("WEB_STARTER_") for key in environment  # type: ignore[union-attr]
            ))
        self.assertEqual({"v2-app", "v2-nginx"}, observed_roles)
        self.assertEqual(
            runtime.created_image_ids["v2-app"], runtime.resolved_images["v2-app"]
        )
        self.assertEqual(
            runtime.created_image_ids["v2-nginx"], runtime.resolved_images["v2-nginx"]
        )

    def test_uncertain_build_result_keeps_intended_tag_cleanup_owned(self) -> None:
        runtime = self.runtime()
        del runtime.resolved_images["v2-app"]
        del runtime.resolved_images["v2-nginx"]
        self.frozen_candidate_source(runtime)

        class TimeoutBuildRunner:
            def run(self, command, **_kwargs):
                values = list(command)
                if values[:3] == ["docker", "image", "inspect"]:
                    return upgrade.CommandResult(1, b"", b"not found")
                if values[:3] == ["docker", "image", "ls"]:
                    return upgrade.CommandResult(0, b"", b"")
                if values[:2] == ["docker", "build"]:
                    raise upgrade.UpgradeRehearsalError(
                        "COMMAND_TIMEOUT", "build outcome is uncertain"
                    )
                raise AssertionError(values)

        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "uncertain"):
            upgrade._build_v2_images(runtime, TimeoutBuildRunner())  # type: ignore[arg-type]
        tag = f"web-starter-upgrade-{RUN_ID}-v2-app:candidate"
        self.assertEqual(tag, runtime.intended_image_tags["v2-app"])
        self.assertTrue(runtime.resource_mutation_started)
        self.assertNotIn("v2-app", runtime.created_image_ids)

        runtime.resource_cleanup_authorized = True
        image_id = "sha256:" + "7" * 64
        labels = {
            upgrade.LABEL_OWNER: upgrade.OWNER_VALUE,
            upgrade.LABEL_RUN: RUN_ID,
            upgrade.LABEL_ROLE: "v2-app",
        }

        class CleanupRunner:
            def __init__(self) -> None:
                self.tag_removed = False
                self.image_removed = False

            def run(self, command, **_kwargs):
                values = list(command)
                if values[:3] in (
                    ["docker", "container", "ls"],
                    ["docker", "volume", "ls"],
                    ["docker", "network", "ls"],
                ):
                    return upgrade.CommandResult(0, b"", b"")
                if values[:3] == ["docker", "image", "inspect"]:
                    reference = values[-1]
                    if reference == tag and self.tag_removed:
                        return upgrade.CommandResult(1, b"", b"not found")
                    if reference == image_id and self.image_removed:
                        return upgrade.CommandResult(1, b"", b"not found")
                    if reference in {tag, image_id}:
                        repo_tags = [] if self.tag_removed else [tag]
                        document = [{
                            "Id": image_id,
                            "Config": {"Labels": labels},
                            "RepoTags": repo_tags,
                        }]
                        return upgrade.CommandResult(
                            0, json.dumps(document).encode("utf-8"), b""
                        )
                    return upgrade.CommandResult(1, b"", b"not found")
                if values[:4] == ["docker", "image", "ls", "--all"]:
                    payload = b"" if self.image_removed else (image_id + "\n").encode("ascii")
                    return upgrade.CommandResult(0, payload, b"")
                if values[:3] == ["docker", "image", "ls"]:
                    return upgrade.CommandResult(0, b"", b"")
                if values[:3] == ["docker", "image", "rm"]:
                    if values[-1] == tag:
                        self.tag_removed = True
                    elif values[-1] == image_id:
                        self.image_removed = True
                    else:
                        raise AssertionError(values)
                    return upgrade.CommandResult(0, b"", b"")
                raise AssertionError(values)

        cleaner = CleanupRunner()
        summary = upgrade._cleanup_owned_resources(runtime, cleaner)  # type: ignore[arg-type]
        self.assertEqual("PASS", summary["status"])
        self.assertTrue(cleaner.tag_removed)
        self.assertTrue(cleaner.image_removed)
        self.assertEqual(1, summary["removed"]["images"])

    def test_project_and_run_collision_scan_authorizes_cleanup_only_after_all_empty(self) -> None:
        runtime = self.runtime()

        class EmptyRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def run(self, command, **_kwargs):
                self.commands.append(list(command))
                return upgrade.CommandResult(0, b"", b"")

        empty = EmptyRunner()
        upgrade._assert_project_unused(runtime, empty)  # type: ignore[arg-type]
        self.assertTrue(runtime.resource_cleanup_authorized)
        self.assertEqual(7, len(empty.commands))

        colliding_runtime = self.runtime()

        class CollisionRunner(EmptyRunner):
            def run(self, command, **_kwargs):
                self.commands.append(list(command))
                if command[:3] == ["docker", "image", "ls"]:
                    return upgrade.CommandResult(0, b"existing-image\n", b"")
                return upgrade.CommandResult(0, b"", b"")

        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "already owns"):
            upgrade._assert_project_unused(colliding_runtime, CollisionRunner())  # type: ignore[arg-type]
        self.assertFalse(colliding_runtime.resource_cleanup_authorized)

    def test_no_mutation_cleanup_without_collision_authorization_never_contacts_docker(self) -> None:
        runtime = self.runtime()

        class RefusingRunner:
            def run(self, _command, **_kwargs):
                raise AssertionError("Docker must not be contacted")

        summary = upgrade._cleanup_owned_resources(runtime, RefusingRunner())  # type: ignore[arg-type]
        self.assertEqual("PASS", summary["status"])
        self.assertTrue(summary["exactOwnershipVerified"])
        self.assertEqual([], summary["failureCodes"])

        runtime.resource_mutation_started = True
        summary = upgrade._cleanup_owned_resources(runtime, RefusingRunner())  # type: ignore[arg-type]
        self.assertEqual("FAIL", summary["status"])
        self.assertEqual(["RESOURCE_CLEANUP_NOT_AUTHORIZED"], summary["failureCodes"])

    def test_generated_alias_cleanup_proves_original_image_reference_survives(self) -> None:
        runtime = self.runtime()
        runtime.resource_cleanup_authorized = True
        image_id = runtime.resolved_images["mysql"]
        alias = f"web-starter-upgrade-{RUN_ID}-mysql:candidate"
        original = "registry.example.test/mysql@sha256:" + "a" * 64
        runtime.created_image_tags = {"mysql": alias}
        runtime.input_image_references = {"mysql": original}

        class AliasRunner:
            def __init__(self) -> None:
                self.original_inspections = 0
                self.alias_removed = False

            def run(self, command, **_kwargs):
                values = list(command)
                if values[:3] in (
                    ["docker", "container", "ls"],
                    ["docker", "volume", "ls"],
                    ["docker", "network", "ls"],
                ):
                    return upgrade.CommandResult(0, b"", b"")
                if values[:3] == ["docker", "image", "inspect"]:
                    reference = values[-1]
                    if reference == alias and self.alias_removed:
                        return upgrade.CommandResult(1, b"", b"not found")
                    if reference == original:
                        self.original_inspections += 1
                    document = [{"Id": image_id, "Config": {"Labels": {}}}]
                    return upgrade.CommandResult(0, json.dumps(document).encode("utf-8"), b"")
                if values[:3] == ["docker", "image", "ls"]:
                    return upgrade.CommandResult(0, b"", b"")
                if values[:3] == ["docker", "image", "rm"]:
                    self.alias_removed = True
                    return upgrade.CommandResult(0, b"", b"")
                raise AssertionError(values)

        runner = AliasRunner()
        summary = upgrade._cleanup_owned_resources(runtime, runner)  # type: ignore[arg-type]
        self.assertEqual("PASS", summary["status"])
        self.assertFalse(summary["residual"]["imageTags"])
        self.assertEqual(2, runner.original_inspections)
        self.assertTrue(runner.alias_removed)

    def test_started_service_images_are_exactly_bound_for_all_five_services(self) -> None:
        runtime = self.runtime()
        ids = {service: f"{index + 1:012x}" for index, service in enumerate(upgrade.SERVICE_IMAGE_ROLES)}
        expected_roles = {
            "mysql": "mysql",
            "redis": "redis",
            "app": "v2-app",
            "nginx": "v2-nginx",
            "mcp-public-nginx": "v2-nginx",
        }

        class ContainerRunner:
            def run(self, command, **_kwargs):
                values = list(command)
                if values[0:2] == ["docker", "compose"]:
                    service = values[-1]
                    return upgrade.CommandResult(0, (ids[service] + "\n").encode("ascii"), b"")
                if values[0:3] == ["docker", "container", "inspect"]:
                    service = next(name for name, identifier in ids.items() if identifier == values[-1])
                    document = [{
                        "Image": runtime.resolved_images[expected_roles[service]],
                        "Config": {"Labels": {
                            upgrade.LABEL_OWNER: upgrade.OWNER_VALUE,
                            upgrade.LABEL_RUN: RUN_ID,
                            upgrade.LABEL_ROLE: service,
                            "com.docker.compose.project": runtime.names.compose_project,
                            "com.docker.compose.service": service,
                        }},
                    }]
                    return upgrade.CommandResult(0, json.dumps(document).encode("utf-8"), b"")
                raise AssertionError(values)

        with patch.object(upgrade, "_compose_env", return_value={}):
            upgrade._verify_started_container_images(
                runtime, ContainerRunner(), v2=True  # type: ignore[arg-type]
            )
        self.assertEqual(
            {service: runtime.resolved_images[role] for service, role in expected_roles.items()},
            runtime.started_container_images["v2"],
        )


if __name__ == "__main__":
    unittest.main()
