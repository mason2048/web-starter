from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import build_v1_upgrade_dependency_seed as builder
from scripts import rehearse_v1_to_v2_upgrade as upgrade


class DependencySeedArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="web-starter-ac40-seed-builder-")
        self.root = Path(self.temporary.name)
        self.repository = self.root / "candidate"
        self.inputs_root = self.root / "inputs"
        self.output_root = self.root / "outputs"
        for path in (self.repository, self.inputs_root, self.output_root):
            path.mkdir(mode=0o700)
        self.inputs = self._create_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _private_file(self, path: Path, payload: bytes, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)
        for parent in path.parents:
            if parent == self.root.parent:
                break
            if parent.exists() and parent != self.root:
                parent.chmod(0o700)

    def _create_candidate(self) -> None:
        distribution_url = (
            "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.15/"
            "apache-maven-3.9.15-bin.zip"
        )
        for relative in upgrade.DEPENDENCY_SEED_SOURCE_FILES:
            path = self.repository / relative
            if relative == ".mvn/wrapper/maven-wrapper.properties":
                payload = (
                    f"distributionUrl={distribution_url}\n"
                    f"distributionSha256Sum={'a' * 64}\n"
                ).encode("utf-8")
            else:
                payload = f"candidate bytes: {relative}\n".encode("utf-8")
            self._private_file(path, payload, 0o700 if relative == "mvnw" else 0o600)

    def _create_inputs(self) -> builder.BuildInputs:
        self._create_candidate()
        maven_home = self.inputs_root / "maven-home"
        maven_repository = self.inputs_root / "maven-repository"
        corepack_home = self.inputs_root / "corepack-home"
        pnpm_store = self.inputs_root / "pnpm-store"
        playwright = self.inputs_root / "playwright-browsers"
        for path in (maven_home, maven_repository, corepack_home, pnpm_store, playwright):
            path.mkdir(mode=0o700)

        properties = (self.repository / ".mvn/wrapper/maven-wrapper.properties").read_text()
        distribution_url = next(
            line.partition("=")[2] for line in properties.splitlines() if line.startswith("distributionUrl=")
        )
        maven = (
            maven_home
            / "wrapper"
            / "dists"
            / "apache-maven-3.9.15"
            / upgrade._java_string_hash(distribution_url)
            / "bin"
            / "mvn"
        )
        self._private_file(maven, b"#!/bin/sh\nexit 0\n", 0o755)
        self._private_file(
            maven.parent.parent / "conf" / "settings.xml",
            b"""<settings><mirrors><mirror>
<id>maven-default-http-blocker</id><mirrorOf>external:http:*</mirrorOf>
<name>Pseudo repository to mirror external repositories initially using HTTP.</name>
<url>http://0.0.0.0/</url><blocked>true</blocked>
</mirror></mirrors></settings>\n""",
            0o644,
        )
        self._private_file(maven_home / "unrelated-user-home-file", b"must not be copied", 0o644)
        self._private_file(maven_repository / "org" / "example" / "sample" / "1" / "sample-1.jar", b"jar", 0o644)
        self._private_file(maven_repository / "org" / "example" / "sample" / "1" / "sample-1.pom", b"pom", 0o644)
        self._private_file(
            maven_repository / "org" / "example" / "sample" / "1" / "_remote.repositories",
            b"sample-1.jar>central=\nsample-1.pom>central=\n",
            0o644,
        )
        self._private_file(
            maven_repository / "dev" / "webstarter" / "local" / "1" / "web-starter-local-1.jar",
            b"must be excluded",
            0o644,
        )
        self._private_file(
            maven_repository / "dev" / "webstarter" / "local" / "1" / "web-starter-local-1.pom",
            b"must be excluded",
            0o644,
        )
        self._private_file(
            corepack_home / "v1" / "pnpm" / "9.15.9" / "package.json",
            b'{"version":"9.15.9"}\n',
            0o644,
        )
        self._private_file(
            corepack_home / "v1" / "pnpm" / "9.15.9" / "bin" / "pnpm.cjs",
            b"#!/usr/bin/env node\n",
            0o755,
        )
        self._private_file(
            corepack_home
            / "v1"
            / "pnpm"
            / "9.15.9"
            / "dist"
            / "node_modules"
            / "dependency-with-a-directory-name-long-enough-for-a-gnu-long-name-record"
            / "nested"
            / "module.js",
            b"export {};\n",
            0o644,
        )
        self._private_file(
            corepack_home / "v1" / "pnpm" / "10.0.0" / "package.json",
            b'{"version":"10.0.0"}\n',
            0o644,
        )
        self._private_file(pnpm_store / "v3" / "files" / "00" / "content-addressed", b"pnpm-v3", 0o444)
        self._private_file(pnpm_store / "v11" / "projects" / "unrelated", b"newer-store", 0o644)

        chromium = playwright / "chromium-1228"
        self._private_file(chromium / "INSTALLATION_COMPLETE", b"complete\n", 0o644)
        self._private_file(chromium / "chrome", b"browser", 0o755)
        framework_versions = chromium / "Framework.framework" / "Versions"
        self._private_file(framework_versions / "A" / "Framework", b"framework", 0o755)
        os.symlink("A", framework_versions / "Current")
        self._private_file(playwright / ".links" / "local-cache-owner", b"/private/local/node_modules\n")
        return builder.BuildInputs(
            repository_root=self.repository,
            maven_home=maven_home,
            maven_repository=maven_repository,
            corepack_home=corepack_home,
            pnpm_store_root=pnpm_store,
            playwright_browsers=playwright,
        )

    def _build(self, suffix: str = "one") -> tuple[Path, Path, Path, dict[str, object]]:
        seed = self.output_root / f"seed-{suffix}"
        archive = self.output_root / f"seed-{suffix}.tar"
        receipt = self.output_root / f"seed-{suffix}.receipt.json"
        document = builder.build_dependency_seed(
            self.inputs,
            seed_output=seed,
            archive_output=archive,
            receipt_output=receipt,
        )
        return seed, archive, receipt, document

    def test_rooted_archive_round_trip_uses_real_v3_layout_excludes_project_artifacts_and_preserves_safe_link(self) -> None:
        seed, archive, receipt_path, receipt = self._build()

        self.assertTrue((seed / "pnpm-store" / "v3" / "files" / "00" / "content-addressed").is_file())
        self.assertFalse((seed / "pnpm-store" / "v11").exists())
        self.assertFalse((seed / "corepack-home" / "v1" / "pnpm" / "10.0.0").exists())
        self.assertFalse((seed / "playwright-browsers" / ".links").exists())
        self.assertFalse((seed / "maven-repository" / "dev" / "webstarter").exists())
        preserved = seed / "playwright-browsers" / "chromium-1228" / "Framework.framework" / "Versions" / "Current"
        self.assertTrue(preserved.is_symlink())
        self.assertEqual("A", os.readlink(preserved))
        self.assertEqual(0o700, stat.S_IMODE((seed / "maven-home").stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((seed / "maven-repository" / "org" / "example" / "sample" / "1" / "sample-1.jar").stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE((seed / "maven-home" / "wrapper" / "dists" / "apache-maven-3.9.15").stat().st_mode))
        self.assertFalse((seed / "maven-home" / "unrelated-user-home-file").exists())
        self.assertEqual(0o600, stat.S_IMODE(archive.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(receipt_path.stat().st_mode))
        self.assertEqual(receipt, json.loads(receipt_path.read_text(encoding="utf-8")))
        self.assertRegex(str(receipt["archiveSha256"]), r"^[0-9a-f]{64}$")
        self.assertRegex(str(receipt["aggregateSha256"]), r"^[0-9a-f]{64}$")
        self.assertRegex(str(receipt["manifestSha256"]), r"^[0-9a-f]{64}$")
        self.assertEqual(sys.platform, receipt["platform"])
        with tarfile.open(archive, mode="r:") as packaged:
            packaged_names = [member.name for member in packaged.getmembers()]
        self.assertEqual(builder.ARCHIVE_ROOT, packaged_names[0])
        self.assertTrue(
            all(
                name == builder.ARCHIVE_ROOT
                or name.startswith(f"{builder.ARCHIVE_ROOT}/")
                for name in packaged_names
            )
        )

        extracted = self.output_root / "extracted"
        extracted.mkdir(mode=0o700)
        extracted_receipt = builder.extract_and_verify_dependency_seed(
            repository_root=self.repository,
            archive_path=archive,
            expected_archive_sha256=str(receipt["archiveSha256"]),
            expected_aggregate_sha256=str(receipt["aggregateSha256"]),
            seed_output=extracted,
        )
        self.assertEqual(receipt, extracted_receipt)
        extracted_link = extracted / "playwright-browsers" / "chromium-1228" / "Framework.framework" / "Versions" / "Current"
        self.assertTrue(extracted_link.is_symlink())
        self.assertEqual("A", os.readlink(extracted_link))

    def test_archive_is_deterministic(self) -> None:
        first_seed, first_archive, first_receipt_path, first = self._build("first")
        second_seed, second_archive, second_receipt_path, second = self._build("second")
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first_receipt_path.read_bytes(), second_receipt_path.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(
            (first_seed / "manifest.json").read_bytes(),
            (second_seed / "manifest.json").read_bytes(),
        )

    def test_archive_hash_tampering_is_rejected_before_extraction(self) -> None:
        _seed, archive, _receipt, document = self._build()
        with archive.open("ab") as stream:
            stream.write(b"tamper")
        archive.chmod(0o600)
        destination = self.output_root / "tampered-extract"
        destination.mkdir(mode=0o700)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "archive SHA-256"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=archive,
                expected_archive_sha256=str(document["archiveSha256"]),
                expected_aggregate_sha256=str(document["aggregateSha256"]),
                seed_output=destination,
            )
        self.assertEqual([], list(destination.iterdir()))

    def test_aggregate_tampering_is_rejected_and_extraction_is_rolled_back(self) -> None:
        _seed, archive, _receipt, document = self._build()
        destination = self.output_root / "aggregate-extract"
        destination.mkdir(mode=0o700)
        with self.assertRaisesRegex(upgrade.UpgradeRehearsalError, "expected aggregate"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=archive,
                expected_archive_sha256=str(document["archiveSha256"]),
                expected_aggregate_sha256="0" * 64,
                seed_output=destination,
            )
        self.assertEqual([], list(destination.iterdir()))

    def _malicious_archive(
        self,
        name: str,
        members: list[tarfile.TarInfo],
        *,
        archive_format: int = tarfile.GNU_FORMAT,
    ) -> tuple[Path, str]:
        archive_path = self.output_root / name
        with archive_path.open("wb") as output:
            with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
                for member in members:
                    member.uid = 0
                    member.gid = 0
                    member.uname = ""
                    member.gname = ""
                    member.mtime = 0
                    if archive_format != tarfile.PAX_FORMAT:
                        member.pax_headers = {}
                    payload = io.BytesIO(b"x" * member.size) if member.isreg() else None
                    archive.addfile(member, payload)
        archive_path.chmod(0o600)
        return archive_path, hashlib.sha256(archive_path.read_bytes()).hexdigest()

    def test_tar_traversal_and_out_of_bounds_links_are_rejected(self) -> None:
        traversal = tarfile.TarInfo("../escape")
        traversal.type = tarfile.REGTYPE
        traversal.mode = 0o600
        traversal.size = 1
        traversal_archive, traversal_sha = self._malicious_archive("traversal.tar", [traversal])
        destination = self.output_root / "traversal-output"
        destination.mkdir(mode=0o700)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "traversal"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=traversal_archive,
                expected_archive_sha256=traversal_sha,
                expected_aggregate_sha256="0" * 64,
                seed_output=destination,
            )
        self.assertFalse((self.output_root / "escape").exists())

        unsafe_link = tarfile.TarInfo("dependency-seed/playwright-browsers/escape")
        unsafe_link.type = tarfile.SYMTYPE
        unsafe_link.mode = 0o777
        unsafe_link.size = 0
        unsafe_link.linkname = "../../outside"
        unsafe_archive, unsafe_sha = self._malicious_archive("unsafe-link.tar", [unsafe_link])
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "escapes"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=unsafe_archive,
                expected_archive_sha256=unsafe_sha,
                expected_aggregate_sha256="0" * 64,
                seed_output=destination,
            )

        component_escape = tarfile.TarInfo("dependency-seed/playwright-browsers/escape")
        component_escape.type = tarfile.SYMTYPE
        component_escape.mode = 0o777
        component_escape.size = 0
        component_escape.linkname = "../manifest.json"
        component_archive, component_sha = self._malicious_archive(
            "component-escape.tar", [component_escape]
        )
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "escapes"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=component_archive,
                expected_archive_sha256=component_sha,
                expected_aggregate_sha256="0" * 64,
                seed_output=destination,
            )

    def test_unrooted_and_extra_root_archives_are_rejected(self) -> None:
        for archive_name, member_name, message in (
            ("unrooted.tar", "manifest.json", "one dependency-seed root"),
            ("extra-root.tar", "dependency-seed-extra/manifest.json", "one dependency-seed root"),
            ("nested-extra.tar", "dependency-seed/unexpected/file", "extra root entry"),
        ):
            with self.subTest(archive_name=archive_name):
                member = tarfile.TarInfo(member_name)
                member.type = tarfile.REGTYPE
                member.mode = 0o600
                member.size = 1
                archive, archive_sha = self._malicious_archive(archive_name, [member])
                destination = self.output_root / f"{archive_name}-output"
                destination.mkdir(mode=0o700)
                with self.assertRaisesRegex(builder.DependencySeedBuildError, message):
                    builder.extract_and_verify_dependency_seed(
                        repository_root=self.repository,
                        archive_path=archive,
                        expected_archive_sha256=archive_sha,
                        expected_aggregate_sha256="0" * 64,
                        seed_output=destination,
                    )
                self.assertEqual([], list(destination.iterdir()))

    def test_rehashed_trailing_data_and_concatenated_archive_are_not_canonical(self) -> None:
        _seed, archive, _receipt, document = self._build()
        original = archive.read_bytes()
        extra_stream = io.BytesIO()
        with tarfile.open(fileobj=extra_stream, mode="w", format=tarfile.GNU_FORMAT) as extra:
            info = tarfile.TarInfo("dependency-seed")
            info.type = tarfile.DIRTYPE
            info.mode = 0o700
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            extra.addfile(info)
        for suffix, tail in (("tail", b"non-zero-tail"), ("concat", extra_stream.getvalue())):
            with self.subTest(suffix=suffix):
                candidate = self.output_root / f"rehashed-{suffix}.tar"
                candidate.write_bytes(original + tail)
                candidate.chmod(0o600)
                expected = hashlib.sha256(candidate.read_bytes()).hexdigest()
                destination = self.output_root / f"rehashed-{suffix}-output"
                destination.mkdir(mode=0o700)
                with self.assertRaisesRegex(
                    builder.DependencySeedBuildError,
                    "serialization is not canonical",
                ):
                    builder.extract_and_verify_dependency_seed(
                        repository_root=self.repository,
                        archive_path=candidate,
                        expected_archive_sha256=expected,
                        expected_aggregate_sha256=str(document["aggregateSha256"]),
                        seed_output=destination,
                    )
                self.assertEqual([], list(destination.iterdir()))

    def test_stream_limits_exact_member_types_and_noncanonical_metadata_are_rejected(self) -> None:
        root = tarfile.TarInfo("dependency-seed")
        root.type = tarfile.DIRTYPE
        root.mode = 0o700
        root.size = 0
        child = tarfile.TarInfo("dependency-seed/manifest.json")
        child.type = tarfile.REGTYPE
        child.mode = 0o600
        child.size = 1
        archive, archive_sha = self._malicious_archive("member-limit.tar", [root, child])
        output = self.output_root / "member-limit-output"
        output.mkdir(mode=0o700)
        with mock.patch.object(builder, "MAX_ARCHIVE_MEMBERS", 1):
            with self.assertRaisesRegex(builder.DependencySeedBuildError, "member count"):
                builder.extract_and_verify_dependency_seed(
                    repository_root=self.repository,
                    archive_path=archive,
                    expected_archive_sha256=archive_sha,
                    expected_aggregate_sha256="0" * 64,
                    seed_output=output,
                )

        with mock.patch.object(builder, "MAX_SEED_PAYLOAD_BYTES", 0):
            with self.assertRaisesRegex(builder.DependencySeedBuildError, "size limit"):
                builder.extract_and_verify_dependency_seed(
                    repository_root=self.repository,
                    archive_path=archive,
                    expected_archive_sha256=archive_sha,
                    expected_aggregate_sha256="0" * 64,
                    seed_output=output,
                )

        contiguous = tarfile.TarInfo("dependency-seed")
        contiguous.type = tarfile.CONTTYPE
        contiguous.mode = 0o600
        contiguous.size = 1
        contiguous_archive, contiguous_sha = self._malicious_archive(
            "contiguous.tar", [contiguous]
        )
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "special or hard-link"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=contiguous_archive,
                expected_archive_sha256=contiguous_sha,
                expected_aggregate_sha256="0" * 64,
                seed_output=output,
            )

        noncanonical = tarfile.TarInfo("dependency-seed")
        noncanonical.type = tarfile.DIRTYPE
        noncanonical.mode = 0o700
        noncanonical.size = 0
        noncanonical.uid = 99
        noncanonical_archive = self.output_root / "noncanonical-metadata.tar"
        with noncanonical_archive.open("wb") as stream:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as packaged:
                packaged.addfile(noncanonical)
        noncanonical_archive.chmod(0o600)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "metadata is not canonical"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=noncanonical_archive,
                expected_archive_sha256=hashlib.sha256(noncanonical_archive.read_bytes()).hexdigest(),
                expected_aggregate_sha256="0" * 64,
                seed_output=output,
            )

        pax = tarfile.TarInfo("dependency-seed")
        pax.type = tarfile.DIRTYPE
        pax.mode = 0o700
        pax.size = 0
        pax.pax_headers = {"comment": "alternate serialization"}
        pax_archive, pax_sha = self._malicious_archive(
            "pax.tar",
            [pax],
            archive_format=tarfile.PAX_FORMAT,
        )
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "metadata is not canonical"):
            builder.extract_and_verify_dependency_seed(
                repository_root=self.repository,
                archive_path=pax_archive,
                expected_archive_sha256=pax_sha,
                expected_aggregate_sha256="0" * 64,
                seed_output=output,
            )

    def test_source_cache_credentials_and_noncentral_maven_artifacts_fail_closed(self) -> None:
        self._private_file(
            self.inputs.maven_home / "settings.xml",
            b"<settings><server><password>do-not-copy</password></server></settings>",
        )
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "sensitive configuration"):
            self._build("settings")
        (self.inputs.maven_home / "settings.xml").unlink()

        self._private_file(
            self.inputs.corepack_home / "v1" / "pnpm" / "10.0.0" / "auth.txt",
            b"_authToken=not-a-real-token-but-secret-material\n",
        )
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "credential material"):
            self._build("token")
        (self.inputs.corepack_home / "v1" / "pnpm" / "10.0.0" / "auth.txt").unlink()

        private_key_fixture = (
            self.inputs.corepack_home / "v1" / "pnpm" / "10.0.0" / "fixture.txt"
        )
        private_key_marker = b"-----BEGIN RSA " + b"PRIVATE KEY-----\n"
        self._private_file(
            private_key_fixture,
            private_key_marker + b"not-real-key-material\n",
        )
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "credential material"):
            self._build("private-key")
        private_key_fixture.unlink()

        artifact_directory = (
            self.inputs.maven_repository / "org" / "example" / "sample" / "1"
        )
        self._private_file(artifact_directory / "locally-installed.jar", b"local")
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "unknown or local"):
            self._build("local")
        (artifact_directory / "locally-installed.jar").unlink()

        marker = artifact_directory / "_remote.repositories"
        original_marker = marker.read_bytes()
        marker.write_bytes(original_marker.replace(b">central=", b">private-repository="))
        marker.chmod(0o600)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "central-only"):
            self._build("private-repository")
        marker.write_bytes(original_marker)
        marker.chmod(0o600)

        artifact = artifact_directory / "sample-1.jar"
        self._private_file(
            artifact_directory / "sample-1.jar.sha1",
            hashlib.sha1(artifact.read_bytes()).hexdigest().encode("ascii"),
        )
        artifact.write_bytes(b"tampered after checksum")
        artifact.chmod(0o600)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "checksum does not match"):
            self._build("checksum")

    def test_active_settings_inside_exact_wrapper_distribution_is_rejected(self) -> None:
        wrapper_home = builder._maven_wrapper_home(self.repository)
        settings = self.inputs.maven_home / wrapper_home / "conf" / "settings.xml"
        settings.write_text(
            "<settings><servers><server><id>private</id>"
            "<username>user</username><password>secret-value</password>"
            "</server></servers></settings>\n",
            encoding="utf-8",
        )
        settings.chmod(0o600)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "active repository"):
            self._build("active-settings")

    def test_output_parent_must_be_private_and_parent_replacement_is_detected(self) -> None:
        insecure = self.root / "insecure-output"
        insecure.mkdir(mode=0o755)
        insecure.chmod(0o755)
        with self.assertRaisesRegex(builder.DependencySeedBuildError, "mode 0700"):
            builder.build_dependency_seed(
                self.inputs,
                seed_output=insecure / "seed",
                archive_output=insecure / "seed.tar",
                receipt_output=insecure / "seed.receipt.json",
            )

        original_copy = builder._copy_component
        raced = False
        displaced = self.root / "outputs-before-race"

        def replace_parent(*args: object, **kwargs: object) -> None:
            nonlocal raced
            if not raced:
                raced = True
                os.rename(self.output_root, displaced)
                self.output_root.mkdir(mode=0o700)
                self._private_file(self.output_root / "attacker-marker", b"untouched")
            original_copy(*args, **kwargs)

        with mock.patch.object(builder, "_copy_component", side_effect=replace_parent):
            with self.assertRaisesRegex(builder.DependencySeedBuildError, "parent changed"):
                self._build("parent-race")
        self.assertEqual(b"untouched", (self.output_root / "attacker-marker").read_bytes())
        self.assertFalse((self.output_root / "seed-parent-race").exists())

    def test_extraction_parent_replacement_is_detected_without_touching_replacement(self) -> None:
        _seed, archive, _receipt, document = self._build("extract-race-source")
        extract_parent = self.root / "extract-parent"
        extract_parent.mkdir(mode=0o700)
        destination = extract_parent / "seed"
        displaced = self.root / "extract-parent-before-race"
        original_extract = builder._extract_members
        raced = False

        def replace_parent(*args: object, **kwargs: object) -> None:
            nonlocal raced
            if not raced:
                raced = True
                os.rename(extract_parent, displaced)
                extract_parent.mkdir(mode=0o700)
                self._private_file(extract_parent / "attacker-marker", b"untouched")
            original_extract(*args, **kwargs)

        with mock.patch.object(builder, "_extract_members", side_effect=replace_parent):
            with self.assertRaisesRegex(builder.DependencySeedBuildError, "parent changed"):
                builder.extract_and_verify_dependency_seed(
                    repository_root=self.repository,
                    archive_path=archive,
                    expected_archive_sha256=str(document["archiveSha256"]),
                    expected_aggregate_sha256=str(document["aggregateSha256"]),
                    seed_output=destination,
                )
        self.assertEqual(b"untouched", (extract_parent / "attacker-marker").read_bytes())
        self.assertFalse((extract_parent / "seed").exists())

    def test_non_playwright_source_link_is_rejected(self) -> None:
        target = self.inputs.maven_repository / "org" / "example" / "target.jar"
        self._private_file(target, b"target", 0o644)
        os.symlink("target.jar", target.parent / "linked.jar")
        with self.assertRaisesRegex(
            builder.DependencySeedBuildError,
            "central provenance|non-regular artifact|only Playwright",
        ):
            self._build()


if __name__ == "__main__":
    unittest.main()
