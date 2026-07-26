#!/usr/bin/env python3
"""Build and safely transport the private AC40 dependency seed.

The upgrade rehearsal deliberately consumes a caller-owned directory rather
than downloading dependencies.  This helper is the single supported way to
assemble that directory from explicit caches, bind it to the current candidate
sources, and package it as a deterministic tar archive.  It also provides a
fail-closed extractor so CI can verify an uploaded archive before using it.

No archive member is extracted through :mod:`tarfile`'s generic extraction
APIs.  Every path, type, mode and link is validated first, then materialized
with exclusive filesystem operations into an empty private directory.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import stat
import sys
import tarfile
from urllib.parse import unquote, urlparse
from typing import Any, Iterable, Mapping, Sequence
from xml.etree import ElementTree

try:
    from scripts import rehearse_v1_to_v2_upgrade as upgrade
except ModuleNotFoundError as exception:
    if exception.name != "scripts":
        raise
    import rehearse_v1_to_v2_upgrade as upgrade  # type: ignore[no-redef]


RECEIPT_KIND = "web-starter-ac40-dependency-seed-archive"
RECEIPT_SCHEMA_VERSION = 1
ARCHIVE_ROOT = "dependency-seed"
SHA256 = upgrade.SHA256
MAX_ARCHIVE_MEMBERS = 600_000
MAX_SEED_PAYLOAD_BYTES = 9 * 1024**3
# Tar headers, per-file block padding and the two end blocks are outside the
# producer's component byte counts.  Keep a separate bounded transport limit.
MAX_ARCHIVE_BYTES = 10 * 1024**3
COPY_BUFFER_BYTES = 1024 * 1024
SECRET_SCAN_OVERLAP = 8192
SENSITIVE_SOURCE_NAMES = {
    ".npmrc",
    ".netrc",
    "credentials",
    "id_dsa",
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    "known_hosts",
    "settings-security.xml",
    "settings.xml",
}
SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----",
        rb"(?:^|[\r\n])\s*(?:_authToken|npmAuthToken)\s*=\s*"
        rb"(?!\$\{|\{\{)[A-Za-z0-9._~+/=-]{16,}",
        rb"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,})",
        rb"(?:^|[\r\n])\s*(?:aws_secret_access_key|client_secret)\s*[:=]\s*"
        rb"[\"']?(?!\$\{|\{\{)[A-Za-z0-9._~+/=-]{16,}[\"']?",
        rb"<password>\s*(?!\{\{|\$\{)[^<\s][^<]{0,4096}</password>",
    )
)


class DependencySeedBuildError(RuntimeError):
    """A fail-closed, non-secret-bearing seed build or extraction error."""


@dataclass(frozen=True)
class BuildInputs:
    repository_root: Path
    maven_home: Path
    maven_repository: Path
    corepack_home: Path
    pnpm_store_root: Path
    playwright_browsers: Path

    def components(self) -> Mapping[str, Path]:
        return {
            "mavenHome": self.maven_home,
            "mavenRepository": self.maven_repository,
            "corepackHome": self.corepack_home,
            "pnpmStore": self.pnpm_store_root,
            "playwrightBrowsers": self.playwright_browsers,
        }


@dataclass(frozen=True)
class ArchiveMember:
    info: tarfile.TarInfo
    relative: PurePosixPath


@dataclass
class TrustedDirectory:
    """A directory pinned by descriptor and re-checkable by canonical path."""

    path: Path
    descriptor: int
    identity: os.stat_result

    def assert_stable(self, label: str) -> None:
        observed_descriptor, observed_path = _open_directory_chain(self.path, label)
        try:
            observed = os.fstat(observed_descriptor)
            current = os.fstat(self.descriptor)
            if (
                observed_path != self.path
                or not _same_inode(self.identity, observed)
                or not _same_inode(self.identity, current)
                or observed.st_uid != os.getuid()
                or current.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) != 0o700
                or stat.S_IMODE(current.st_mode) != 0o700
            ):
                raise DependencySeedBuildError(f"{label} changed during dependency seed processing")
        finally:
            os.close(observed_descriptor)

    def close(self) -> None:
        os.close(self.descriptor)


@dataclass
class PrivateDirectory:
    path: Path
    parent: TrustedDirectory
    name: str
    descriptor: int
    identity: os.stat_result
    created: bool

    def assert_stable(self, label: str = "dependency seed output") -> None:
        self.parent.assert_stable(f"{label} parent")
        try:
            observed = os.stat(self.name, dir_fd=self.parent.descriptor, follow_symlinks=False)
        except OSError as exception:
            raise DependencySeedBuildError(f"{label} changed during dependency seed processing") from exception
        current = os.fstat(self.descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or not _same_inode(self.identity, observed)
            or not _same_inode(self.identity, current)
            or observed.st_uid != os.getuid()
            or current.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            raise DependencySeedBuildError(f"{label} changed during dependency seed processing")

    def close(self) -> None:
        os.close(self.descriptor)
        self.parent.close()


@dataclass
class PrivateFileTarget:
    path: Path
    parent: TrustedDirectory
    name: str

    def assert_parent_stable(self, label: str) -> None:
        self.parent.assert_stable(f"{label} parent")

    def close(self) -> None:
        self.parent.close()


def _sha256_file_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, COPY_BUFFER_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_nlink,
        left.st_size,
        getattr(left, "st_mtime_ns", int(left.st_mtime * 1_000_000_000)),
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_nlink,
        right.st_size,
        getattr(right, "st_mtime_ns", int(right.st_mtime * 1_000_000_000)),
    )


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_uid) == (
        right.st_dev,
        right.st_ino,
        right.st_uid,
    )


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _canonical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _open_directory_chain(path: Path, label: str) -> tuple[int, Path]:
    """Open a resolved directory one component at a time without following links.

    macOS commonly spells private temporary paths through ``/var`` ->
    ``/private/var``.  Resolve that stable platform alias once, then pin every
    real component with ``openat(O_DIRECTORY|O_NOFOLLOW)``.  Callers retain the
    final descriptor and re-open the canonical chain to detect replacement.
    """

    try:
        canonical = _canonical_absolute(path).resolve(strict=True)
    except OSError as exception:
        raise DependencySeedBuildError(f"{label} must be an existing real directory") from exception
    if not canonical.is_absolute():
        raise DependencySeedBuildError(f"{label} must be an existing real directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for part in canonical.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise DependencySeedBuildError(f"{label} must be an existing real directory")
        return descriptor, canonical
    except Exception:
        os.close(descriptor)
        raise


def _trusted_directory(path: Path, label: str) -> TrustedDirectory:
    descriptor, canonical = _open_directory_chain(path, label)
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise DependencySeedBuildError(f"{label} must be caller-owned with mode 0700")
    return TrustedDirectory(canonical, descriptor, metadata)


def _real_directory(path: Path, label: str) -> Path:
    expanded = path.expanduser().absolute()
    try:
        metadata = expanded.lstat()
    except OSError as exception:
        raise DependencySeedBuildError(f"{label} must be an existing real directory") from exception
    if expanded.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise DependencySeedBuildError(f"{label} must be an existing real directory")
    return expanded.resolve(strict=True)


def _assert_external(path: Path, repository: Path, label: str) -> None:
    absolute = path.expanduser().absolute()
    resolved_parent = absolute.parent.resolve(strict=True)
    candidate = resolved_parent / absolute.name
    if (
        candidate == repository
        or _inside(candidate, repository)
        or _inside(repository, candidate)
    ):
        raise DependencySeedBuildError(f"{label} must stay outside the candidate repository")


def _output_name(path: Path, label: str) -> tuple[Path, str]:
    absolute = _canonical_absolute(path)
    name = absolute.name
    if (
        not name
        or name in {".", ".."}
        or not _safe_name(name)
        or "/" in name
        or "\\" in name
    ):
        raise DependencySeedBuildError(f"{label} has an unsafe output name")
    return absolute.parent, name


def _new_private_directory(path: Path, repository: Path, *, allow_empty: bool) -> PrivateDirectory:
    absolute = path.expanduser().absolute()
    _assert_external(absolute, repository, "dependency seed output")
    parent_path, name = _output_name(absolute, "dependency seed output")
    parent = _trusted_directory(parent_path, "dependency seed output parent")
    created = False
    descriptor = -1
    try:
        try:
            metadata = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir(name, mode=0o700, dir_fd=parent.descriptor)
            created = True
            metadata = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        if (
            (not created and not allow_empty)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise DependencySeedBuildError(
                "dependency seed output must be absent or an empty caller-owned mode-0700 directory"
            )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        opened = os.fstat(descriptor)
        if not _same_inode(metadata, opened):
            raise DependencySeedBuildError("dependency seed output changed while it was opened")
        if not created:
            with os.scandir(descriptor) as entries:
                if next(entries, None) is not None:
                    raise DependencySeedBuildError(
                        "dependency seed output must be absent or an empty caller-owned mode-0700 directory"
                    )
        anchored = PrivateDirectory(parent.path / name, parent, name, descriptor, opened, created)
        anchored.assert_stable()
        return anchored
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.rmdir(name, dir_fd=parent.descriptor)
            except OSError:
                pass
        parent.close()
        raise


def _new_private_file_path(path: Path, repository: Path, label: str) -> PrivateFileTarget:
    absolute = path.expanduser().absolute()
    _assert_external(absolute, repository, label)
    parent_path, name = _output_name(absolute, label)
    parent = _trusted_directory(parent_path, f"{label} parent")
    try:
        try:
            os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DependencySeedBuildError(f"{label} must not already exist")
        target = PrivateFileTarget(parent.path / name, parent, name)
        target.assert_parent_stable(label)
        return target
    except Exception:
        parent.close()
        raise


def _existing_private_file(
    path: Path,
    repository: Path,
    label: str,
) -> tuple[PrivateFileTarget, int, os.stat_result]:
    absolute = path.expanduser().absolute()
    _assert_external(absolute, repository, label)
    parent_path, name = _output_name(absolute, label)
    parent = _trusted_directory(parent_path, f"{label} parent")
    target = PrivateFileTarget(parent.path / name, parent, name)
    descriptor = -1
    try:
        metadata = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_ARCHIVE_BYTES
        ):
            raise DependencySeedBuildError(
                "dependency seed archive must be a caller-owned private regular file"
            )
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent.descriptor,
        )
        opened = os.fstat(descriptor)
        if not _same_file(metadata, opened):
            raise DependencySeedBuildError("dependency seed archive changed while it was opened")
        target.assert_parent_stable(label)
        return target, descriptor, opened
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        target.close()
        raise


def _unlink_target_if_same(target: PrivateFileTarget, expected: os.stat_result) -> None:
    try:
        observed = os.stat(target.name, dir_fd=target.parent.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISREG(observed.st_mode) and _same_inode(expected, observed):
        os.unlink(target.name, dir_fd=target.parent.descriptor)


def _unlink_at_if_same(directory_descriptor: int, name: str, expected: os.stat_result) -> None:
    try:
        observed = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISREG(observed.st_mode) and _same_inode(expected, observed):
        os.unlink(name, dir_fd=directory_descriptor)


def _write_private_at(directory_descriptor: int, name: str, payload: bytes) -> os.stat_result:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    except OSError as exception:
        raise DependencySeedBuildError("private output cannot be created exclusively") from exception
    created = os.fstat(descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        os.close(descriptor)
        try:
            _unlink_at_if_same(directory_descriptor, name, created)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    try:
        observed = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as exception:
        raise DependencySeedBuildError("private output changed after it was written") from exception
    if not stat.S_ISREG(observed.st_mode) or not _same_inode(created, observed):
        raise DependencySeedBuildError("private output changed after it was written")
    return observed


def _write_private(target: PrivateFileTarget, payload: bytes, label: str) -> os.stat_result:
    target.assert_parent_stable(label)
    observed = _write_private_at(target.parent.descriptor, target.name, payload)
    target.assert_parent_stable(label)
    return observed


def _safe_name(value: str) -> bool:
    if not value or not all(
        ord(character) >= 32 and ord(character) != 127 for character in value
    ):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _safe_relative_link(path: Path, raw_target: str, component_root: Path) -> None:
    if (
        not _safe_name(raw_target)
        or "\\" in raw_target
        or Path(raw_target).is_absolute()
    ):
        raise DependencySeedBuildError("Playwright links must use safe relative targets")
    depth = len(path.parent.relative_to(component_root).parts)
    for part in Path(raw_target).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if depth == 0:
                raise DependencySeedBuildError("Playwright link escapes its component")
            depth -= 1
        else:
            depth += 1
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exception:
        raise DependencySeedBuildError("Playwright link is dangling or cyclic") from exception
    root = component_root.resolve(strict=True)
    if not _inside(resolved, root):
        raise DependencySeedBuildError("Playwright link escapes its component")


def _excluded_maven_artifact(relative: Path) -> bool:
    parts = relative.parts
    return parts[:2] == ("dev", "webstarter")


def _maven_wrapper_home(repository: Path) -> Path:
    properties_path = repository / ".mvn" / "wrapper" / "maven-wrapper.properties"
    try:
        properties: dict[str, str] = {}
        for line in properties_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                properties[key.strip()] = value.strip()
    except (OSError, UnicodeDecodeError) as exception:
        raise DependencySeedBuildError("Maven Wrapper properties cannot be read safely") from exception
    distribution_url = properties.get("distributionUrl", "")
    parsed = urlparse(distribution_url)
    filename = Path(unquote(parsed.path)).name
    expected = "apache-maven-3.9.15-bin.zip"
    if parsed.scheme != "https" or filename != expected:
        raise DependencySeedBuildError("Maven Wrapper must use the frozen HTTPS 3.9.15 distribution")
    return (
        Path("wrapper")
        / "dists"
        / "apache-maven-3.9.15"
        / upgrade._java_string_hash(distribution_url)
    )


def _included_component_entry(
    component: str,
    relative: Path,
    *,
    maven_wrapper_home: Path | None = None,
) -> bool:
    """Keep only the cache generation consumed by the frozen tool versions."""
    parts = relative.parts
    if component == "pnpmStore":
        return bool(parts) and parts[0] == "v3"
    if component == "corepackHome":
        required = ("v1", "pnpm", upgrade.DEPENDENCY_SEED_VERSIONS["pnpm"])
        return (
            parts == required[:len(parts)]
            if len(parts) <= len(required)
            else parts[:len(required)] == required
        )
    if component == "mavenHome":
        if maven_wrapper_home is None:
            raise DependencySeedBuildError("exact Maven Wrapper home is unavailable")
        required = maven_wrapper_home.parts
        return (
            parts == required[:len(parts)]
            if len(parts) <= len(required)
            else parts[:len(required)] == required
        )
    if component == "playwrightBrowsers":
        # Playwright's .links files contain local node_modules paths used only
        # for cache garbage collection.  They are neither portable nor needed
        # when PLAYWRIGHT_BROWSERS_PATH points at the materialized seed.
        return bool(parts) and parts[0] != ".links"
    return True


def _source_name_is_sensitive(name: str) -> bool:
    folded = name.casefold()
    return (
        folded in SENSITIVE_SOURCE_NAMES
        or folded.endswith((".key", ".pem", ".p12", ".pfx", ".jks"))
        or folded.startswith(("id_rsa.", "id_ed25519."))
    )


def _is_stock_maven_settings(relative: Path, wrapper_home: Path | None) -> bool:
    return wrapper_home is not None and relative == wrapper_home / "conf" / "settings.xml"


def _assert_stock_maven_settings_safe(path: Path) -> None:
    """Allow Maven's commented template, never an active user settings file."""

    try:
        metadata = path.lstat()
        payload = _read_safe_regular_file(path, metadata, maximum_bytes=128 * 1024)
        if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
            raise DependencySeedBuildError("Maven distribution settings contains XML declarations")
        document = ElementTree.fromstring(payload)
    except (OSError, ElementTree.ParseError) as exception:
        raise DependencySeedBuildError("Maven distribution settings template is invalid") from exception
    sensitive_elements = {
        "username",
        "password",
        "privateKey",
        "passphrase",
        "proxy",
        "server",
        "profile",
        "activeProfile",
    }
    mirrors: list[dict[str, str]] = []
    for element in document.iter():
        local_name = element.tag.rsplit("}", 1)[-1] if isinstance(element.tag, str) else ""
        if local_name in sensitive_elements:
            raise DependencySeedBuildError(
                "Maven distribution settings contains active repository configuration"
            )
        if local_name == "mirror":
            mirrors.append(
                {
                    (
                        child.tag.rsplit("}", 1)[-1]
                        if isinstance(child.tag, str)
                        else ""
                    ): (child.text or "").strip()
                    for child in element
                }
            )
    if mirrors != [
        {
            "id": "maven-default-http-blocker",
            "mirrorOf": "external:http:*",
            "name": "Pseudo repository to mirror external repositories initially using HTTP.",
            "url": "http://0.0.0.0/",
            "blocked": "true",
        }
    ]:
        raise DependencySeedBuildError(
            "Maven distribution settings contains a non-stock mirror configuration"
        )


def _assert_no_secret_payload(source: Path, metadata: os.stat_result) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        if not _same_file(metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("dependency cache file changed before secret scanning")
        pending = b""
        while True:
            chunk = os.read(descriptor, COPY_BUFFER_BYTES)
            if not chunk:
                break
            candidate = pending + chunk
            if any(pattern.search(candidate) for pattern in SECRET_PATTERNS):
                raise DependencySeedBuildError("dependency cache contains credential material")
            pending = candidate[-SECRET_SCAN_OVERLAP:]
        if not _same_file(metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("dependency cache file changed during secret scanning")
    finally:
        os.close(descriptor)


def _read_safe_regular_file(
    path: Path,
    metadata: os.stat_result,
    *,
    maximum_bytes: int,
) -> bytes:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
    ):
        raise DependencySeedBuildError("dependency provenance file is not a bounded regular file")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if not _same_file(metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("dependency provenance file changed before reading")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(COPY_BUFFER_BYTES, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum_bytes:
                raise DependencySeedBuildError("dependency provenance file exceeds its size limit")
        if not _same_file(metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("dependency provenance file changed while reading")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _sha1_safe_regular_file(path: Path, metadata: os.stat_result) -> str:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if not _same_file(metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("Maven artifact changed before checksum validation")
        digest = hashlib.sha1()
        while chunk := os.read(descriptor, COPY_BUFFER_BYTES):
            digest.update(chunk)
        if not _same_file(metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("Maven artifact changed during checksum validation")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _maven_remote_entries(marker: Path) -> set[str]:
    try:
        metadata = marker.lstat()
        payload = _read_safe_regular_file(
            marker,
            metadata,
            maximum_bytes=1024 * 1024,
        ).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exception:
        raise DependencySeedBuildError("Maven repository provenance cannot be read") from exception
    names: set[str] = set()
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, repository_id = line.partition(">")
        if (
            not separator
            or repository_id != "central="
            or not name
            or name in names
            or "/" in name
            or "\\" in name
        ):
            raise DependencySeedBuildError("Maven repository is not an exact central-only cache")
        names.add(name)
    if not names:
        raise DependencySeedBuildError("Maven repository provenance is missing")
    return names


def _validate_maven_repository_provenance(root: Path) -> None:
    """Require every transported artifact to be independently marked central."""

    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort(key=os.fsencode)
        file_names.sort(key=os.fsencode)
        relative_directory = Path(directory).relative_to(root)
        if _excluded_maven_artifact(relative_directory):
            directory_names[:] = []
            continue
        if any(_source_name_is_sensitive(name) for name in (*directory_names, *file_names)):
            raise DependencySeedBuildError("dependency cache contains a sensitive configuration name")
        if not file_names:
            continue
        marker = Path(directory) / "_remote.repositories"
        if "_remote.repositories" not in file_names:
            raise DependencySeedBuildError("Maven repository artifact lacks central provenance")
        remote_names = _maven_remote_entries(marker)
        for name in file_names:
            path = Path(directory) / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise DependencySeedBuildError("Maven repository contains a non-regular artifact")
            _assert_no_secret_payload(path, metadata)
            if name == "_remote.repositories":
                continue
            if name.endswith(".sha1"):
                artifact_name = name[:-5]
                try:
                    checksum = _read_safe_regular_file(
                        path,
                        metadata,
                        maximum_bytes=128,
                    ).decode("ascii")
                except (OSError, UnicodeDecodeError) as exception:
                    raise DependencySeedBuildError("Maven Central checksum cannot be read") from exception
                if artifact_name not in remote_names or not re.fullmatch(r"[0-9a-fA-F]{40}", checksum):
                    raise DependencySeedBuildError("Maven repository checksum lacks central provenance")
                artifact = Path(directory) / artifact_name
                artifact_metadata = artifact.lstat()
                if not hmac.compare_digest(
                    _sha1_safe_regular_file(artifact, artifact_metadata),
                    checksum.casefold(),
                ):
                    raise DependencySeedBuildError("Maven Central checksum does not match its artifact")
            elif name not in remote_names:
                raise DependencySeedBuildError("Maven repository contains an unknown or local artifact")
        if any(not (Path(directory) / name).is_file() for name in remote_names):
            raise DependencySeedBuildError("Maven repository provenance references a missing artifact")


def _scan_source_cache(
    root: Path,
    *,
    component: str,
    maven_wrapper_home: Path,
) -> None:
    """Reject credential-bearing source material even when it would be filtered."""

    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        except OSError as exception:
            raise DependencySeedBuildError("dependency cache cannot be scanned safely") from exception
        child_directories: list[Path] = []
        for entry in entries:
            relative = Path(entry.path).relative_to(root)
            stock_settings = (
                component == "mavenHome"
                and _is_stock_maven_settings(relative, maven_wrapper_home)
            )
            if _source_name_is_sensitive(entry.name) and not stock_settings:
                raise DependencySeedBuildError("dependency cache contains a sensitive configuration name")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exception:
                raise DependencySeedBuildError("dependency cache entry cannot be inspected") from exception
            if stat.S_ISDIR(metadata.st_mode):
                child_directories.append(Path(entry.path))
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise DependencySeedBuildError("dependency cache contains a hard link")
                if stock_settings:
                    _assert_stock_maven_settings_safe(Path(entry.path))
                else:
                    _assert_no_secret_payload(Path(entry.path), metadata)
            elif not stat.S_ISLNK(metadata.st_mode):
                raise DependencySeedBuildError("dependency cache contains a special file")
        stack.extend(reversed(child_directories))


def _copy_regular_file(
    source: Path,
    target_directory_descriptor: int,
    target_name: str,
    metadata: os.stat_result,
) -> None:
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        source_descriptor = os.open(source, source_flags)
        target_descriptor = os.open(
            target_name,
            target_flags | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=target_directory_descriptor,
        )
    except OSError as exception:
        if "source_descriptor" in locals():
            os.close(source_descriptor)
        raise DependencySeedBuildError("dependency cache file cannot be copied safely") from exception
    try:
        opened = os.fstat(source_descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(metadata, opened):
            raise DependencySeedBuildError("dependency cache file changed before copying")
        while True:
            chunk = os.read(source_descriptor, COPY_BUFFER_BYTES)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                view = view[written:]
        if not _same_file(metadata, os.fstat(source_descriptor)):
            raise DependencySeedBuildError("dependency cache file changed while copying")
        destination_mode = 0o700 if metadata.st_mode & stat.S_IXUSR else 0o600
        os.fchmod(target_descriptor, destination_mode)
    except OSError as exception:
        raise DependencySeedBuildError("dependency cache file cannot be copied safely") from exception
    finally:
        os.close(source_descriptor)
        os.close(target_descriptor)


def _open_child_directory(parent_descriptor: int, name: str) -> int:
    return os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_descriptor,
    )


def _copy_component(
    source: Path,
    seed: PrivateDirectory,
    target_name: str,
    component: str,
    *,
    maven_wrapper_home: Path,
) -> None:
    os.mkdir(target_name, mode=0o700, dir_fd=seed.descriptor)
    component_descriptor = _open_child_directory(seed.descriptor, target_name)
    os.fchmod(component_descriptor, 0o700)
    stack: list[tuple[Path, int, Path]] = [(source, component_descriptor, Path())]
    try:
        while stack:
            source_directory, target_directory_descriptor, relative_directory = stack.pop()
            try:
                entries = sorted(os.scandir(source_directory), key=lambda entry: os.fsencode(entry.name))
            except OSError as exception:
                os.close(target_directory_descriptor)
                raise DependencySeedBuildError("dependency cache cannot be enumerated") from exception
            child_directories: list[tuple[Path, int, Path]] = []
            try:
                for entry in entries:
                    if (
                        not upgrade._safe_seed_name(entry.name)
                        or not _safe_name(entry.name)
                        or "\\" in entry.name
                        or upgrade._seed_incomplete_name(entry.name)
                    ):
                        raise DependencySeedBuildError("dependency cache contains an unsafe or incomplete marker")
                    source_path = Path(entry.path)
                    relative = relative_directory / entry.name
                    stock_settings = (
                        component == "mavenHome"
                        and _is_stock_maven_settings(relative, maven_wrapper_home)
                    )
                    if _source_name_is_sensitive(entry.name) and not stock_settings:
                        raise DependencySeedBuildError("dependency cache contains a sensitive configuration name")
                    if not _included_component_entry(
                        component,
                        relative,
                        maven_wrapper_home=maven_wrapper_home,
                    ):
                        continue
                    if component == "mavenRepository" and _excluded_maven_artifact(relative):
                        continue
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as exception:
                        raise DependencySeedBuildError("dependency cache entry cannot be inspected") from exception
                    if (
                        component == "mavenRepository"
                        and stat.S_ISREG(metadata.st_mode)
                        and entry.name.startswith("web-starter-")
                    ):
                        continue
                    if stat.S_ISLNK(metadata.st_mode):
                        if component != "playwrightBrowsers":
                            raise DependencySeedBuildError("only Playwright may contain symbolic links")
                        try:
                            raw_target = os.readlink(source_path)
                        except OSError as exception:
                            raise DependencySeedBuildError("Playwright link cannot be read") from exception
                        _safe_relative_link(source_path, raw_target, source)
                        os.symlink(raw_target, entry.name, dir_fd=target_directory_descriptor)
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        os.mkdir(entry.name, mode=0o700, dir_fd=target_directory_descriptor)
                        child_descriptor = _open_child_directory(target_directory_descriptor, entry.name)
                        os.fchmod(child_descriptor, 0o700)
                        child_directories.append((source_path, child_descriptor, relative))
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise DependencySeedBuildError("dependency cache contains a special file")
                    if metadata.st_nlink != 1:
                        raise DependencySeedBuildError("dependency cache contains a hard link")
                    if stock_settings:
                        _assert_stock_maven_settings_safe(source_path)
                    else:
                        _assert_no_secret_payload(source_path, metadata)
                    _copy_regular_file(
                        source_path,
                        target_directory_descriptor,
                        entry.name,
                        metadata,
                    )
            except Exception:
                for _source, descriptor, _relative in child_directories:
                    os.close(descriptor)
                os.close(target_directory_descriptor)
                for _source, descriptor, _relative in stack:
                    os.close(descriptor)
                raise
            os.close(target_directory_descriptor)
            stack.extend(reversed(child_directories))
    except Exception:
        raise


def _canonical_aggregate(
    source_hashes: Mapping[str, str],
    component_summaries: Mapping[str, Mapping[str, Any]],
) -> str:
    payload = {
        "kind": upgrade.DEPENDENCY_SEED_KIND,
        "schemaVersion": upgrade.DEPENDENCY_SEED_SCHEMA_VERSION,
        "platform": sys.platform,
        "architecture": platform.machine().lower(),
        "versions": dict(upgrade.DEPENDENCY_SEED_VERSIONS),
        "sourceSha256": dict(source_hashes),
        "components": dict(component_summaries),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _manifest_payload(repository: Path, seed_root: Path) -> tuple[dict[str, Any], str]:
    source_hashes = upgrade._manifest_source_hashes(repository)
    summaries = {
        component: upgrade._component_tree_summary(
            seed_root / relative,
            component=component,
        )
        for component, relative in upgrade.DEPENDENCY_SEED_COMPONENTS.items()
    }
    manifest = {
        "schemaVersion": upgrade.DEPENDENCY_SEED_SCHEMA_VERSION,
        "kind": upgrade.DEPENDENCY_SEED_KIND,
        "platform": sys.platform,
        "architecture": platform.machine().lower(),
        "versions": dict(upgrade.DEPENDENCY_SEED_VERSIONS),
        "sourceSha256": source_hashes,
        "components": {
            component: {
                "path": upgrade.DEPENDENCY_SEED_COMPONENTS[component],
                **summaries[component],
            }
            for component in upgrade.DEPENDENCY_SEED_COMPONENTS
        },
    }
    return manifest, _canonical_aggregate(source_hashes, summaries)


def _seed_entries(seed: PrivateDirectory) -> list[tuple[str, os.stat_result]]:
    entries: list[tuple[str, os.stat_result]] = []
    total_bytes = 0
    stack: list[tuple[int, PurePosixPath]] = [(os.dup(seed.descriptor), PurePosixPath())]
    while stack:
        directory_descriptor, relative_directory = stack.pop()
        child_directories: list[tuple[int, PurePosixPath]] = []
        try:
            children = sorted(os.scandir(directory_descriptor), key=lambda entry: os.fsencode(entry.name))
            for child in children:
                relative = relative_directory / child.name
                metadata = child.stat(follow_symlinks=False)
                entries.append((relative.as_posix(), metadata))
                if len(entries) + 1 > MAX_ARCHIVE_MEMBERS:
                    raise DependencySeedBuildError("dependency seed exceeds the archive member limit")
                if stat.S_ISREG(metadata.st_mode):
                    total_bytes += metadata.st_size
                    if total_bytes > MAX_SEED_PAYLOAD_BYTES:
                        raise DependencySeedBuildError("dependency seed exceeds the archive size limit")
                if stat.S_ISDIR(metadata.st_mode):
                    child_directories.append(
                        (_open_child_directory(directory_descriptor, child.name), relative)
                    )
        except Exception:
            for descriptor, _relative in child_directories:
                os.close(descriptor)
            os.close(directory_descriptor)
            for descriptor, _relative in stack:
                os.close(descriptor)
            raise
        os.close(directory_descriptor)
        stack.extend(reversed(child_directories))
    return sorted(entries, key=lambda item: os.fsencode(item[0]))


def _open_seed_file(seed: PrivateDirectory, relative: PurePosixPath) -> int:
    descriptor = os.dup(seed.descriptor)
    try:
        for part in relative.parts[:-1]:
            next_descriptor = _open_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            relative.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        return file_descriptor
    finally:
        os.close(descriptor)


def _read_seed_link(seed: PrivateDirectory, relative: PurePosixPath) -> str:
    descriptor = os.dup(seed.descriptor)
    try:
        for part in relative.parts[:-1]:
            next_descriptor = _open_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = next_descriptor
        return os.readlink(relative.name, dir_fd=descriptor)
    finally:
        os.close(descriptor)


def _tar_info(name: str, metadata: os.stat_result) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = stat.S_IMODE(metadata.st_mode)
    info.pax_headers = {}
    return info


def _create_deterministic_archive(
    seed: PrivateDirectory,
    archive_target: PrivateFileTarget,
) -> os.stat_result:
    seed.assert_stable()
    archive_target.assert_parent_stable("dependency seed archive")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(
            archive_target.name,
            flags,
            0o600,
            dir_fd=archive_target.parent.descriptor,
        )
    except OSError as exception:
        raise DependencySeedBuildError("dependency seed archive cannot be created privately") from exception
    created = os.fstat(descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
                root_metadata = os.fstat(seed.descriptor)
                root_info = _tar_info(ARCHIVE_ROOT, root_metadata)
                root_info.type = tarfile.DIRTYPE
                root_info.size = 0
                root_info.mode = 0o700
                archive.addfile(root_info)
                for relative, metadata in _seed_entries(seed):
                    info = _tar_info(f"{ARCHIVE_ROOT}/{relative}", metadata)
                    if stat.S_ISDIR(metadata.st_mode):
                        info.type = tarfile.DIRTYPE
                        info.size = 0
                        archive.addfile(info)
                    elif stat.S_ISLNK(metadata.st_mode):
                        info.type = tarfile.SYMTYPE
                        info.size = 0
                        info.mode = 0o777
                        info.linkname = _read_seed_link(seed, PurePosixPath(relative))
                        archive.addfile(info)
                    elif stat.S_ISREG(metadata.st_mode):
                        if metadata.st_nlink != 1:
                            raise DependencySeedBuildError("dependency seed archive source contains a hard link")
                        info.type = tarfile.REGTYPE
                        info.size = metadata.st_size
                        source_descriptor = _open_seed_file(seed, PurePosixPath(relative))
                        try:
                            if not _same_file(metadata, os.fstat(source_descriptor)):
                                raise DependencySeedBuildError("dependency seed changed before archiving")
                            with os.fdopen(source_descriptor, "rb", closefd=False) as source:
                                archive.addfile(info, source)
                            if not _same_file(metadata, os.fstat(source_descriptor)):
                                raise DependencySeedBuildError("dependency seed changed while archiving")
                        finally:
                            os.close(source_descriptor)
                    else:
                        raise DependencySeedBuildError("dependency seed archive source contains a special file")
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        os.close(descriptor)
        _unlink_target_if_same(archive_target, created)
        raise
    else:
        os.close(descriptor)
    try:
        observed = os.stat(
            archive_target.name,
            dir_fd=archive_target.parent.descriptor,
            follow_symlinks=False,
        )
    except OSError as exception:
        raise DependencySeedBuildError("dependency seed archive changed after creation") from exception
    if not stat.S_ISREG(observed.st_mode) or not _same_inode(created, observed):
        raise DependencySeedBuildError("dependency seed archive changed after creation")
    seed.assert_stable()
    archive_target.assert_parent_stable("dependency seed archive")
    return observed


def _receipt(archive_sha256: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "archiveSha256": archive_sha256,
        "aggregateSha256": evidence["aggregateSha256"],
        "manifestSha256": evidence["manifestSha256"],
        "platform": sys.platform,
        "architecture": platform.machine().lower(),
    }


def _receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_target(target: PrivateFileTarget, expected: os.stat_result) -> str:
    target.assert_parent_stable("dependency seed private file")
    descriptor = os.open(
        target.name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=target.parent.descriptor,
    )
    try:
        if not _same_file(expected, os.fstat(descriptor)):
            raise DependencySeedBuildError("private file changed before hashing")
        digest = _sha256_file_descriptor(descriptor)
        if not _same_file(expected, os.fstat(descriptor)):
            raise DependencySeedBuildError("private file changed while hashing")
        return digest
    finally:
        os.close(descriptor)


def _clear_directory_descriptor(descriptor: int) -> None:
    entries = list(os.scandir(descriptor))
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = _open_child_directory(descriptor, entry.name)
            try:
                _clear_directory_descriptor(child)
            finally:
                os.close(child)
            os.rmdir(entry.name, dir_fd=descriptor)
        else:
            os.unlink(entry.name, dir_fd=descriptor)


def _clear_directory(root: PrivateDirectory, *, remove_root: bool) -> None:
    try:
        _clear_directory_descriptor(root.descriptor)
        if remove_root:
            os.rmdir(root.name, dir_fd=root.parent.descriptor)
    except OSError as exception:
        raise DependencySeedBuildError("dependency seed output could not be rolled back safely") from exception


def build_dependency_seed(
    inputs: BuildInputs,
    *,
    seed_output: Path,
    archive_output: Path,
    receipt_output: Path,
) -> dict[str, Any]:
    """Build, validate, archive and receipt one exact dependency seed."""
    repository = _real_directory(inputs.repository_root, "candidate repository")
    sources = {
        component: _real_directory(path, f"{component} source")
        for component, path in inputs.components().items()
    }
    if not (sources["pnpmStore"] / "v3" / "files").is_dir():
        raise DependencySeedBuildError("pnpm store root must contain v3/files")
    if (sources["mavenHome"] / "repository").exists():
        raise DependencySeedBuildError("Maven home must not contain the separate Maven repository")
    wrapper_home = _maven_wrapper_home(repository)
    exact_wrapper = sources["mavenHome"] / wrapper_home
    if exact_wrapper.is_symlink() or not exact_wrapper.is_dir():
        raise DependencySeedBuildError("Maven home lacks the exact frozen Wrapper distribution")
    wrapper_binary = exact_wrapper / "bin" / "mvn"
    stock_settings = exact_wrapper / "conf" / "settings.xml"
    if (
        wrapper_binary.is_symlink()
        or not wrapper_binary.is_file()
        or not wrapper_binary.stat().st_mode & stat.S_IXUSR
        or stock_settings.is_symlink()
        or not stock_settings.is_file()
    ):
        raise DependencySeedBuildError("Maven home lacks the complete frozen Wrapper distribution")
    _assert_stock_maven_settings_safe(stock_settings)
    for component, source in sources.items():
        _scan_source_cache(
            source,
            component=component,
            maven_wrapper_home=wrapper_home,
        )
    _validate_maven_repository_provenance(sources["mavenRepository"])

    archive_target: PrivateFileTarget | None = None
    receipt_target: PrivateFileTarget | None = None
    seed: PrivateDirectory | None = None
    archive_metadata: os.stat_result | None = None
    receipt_metadata: os.stat_result | None = None
    try:
        archive_target = _new_private_file_path(
            archive_output, repository, "dependency seed archive"
        )
        receipt_target = _new_private_file_path(
            receipt_output, repository, "dependency seed receipt"
        )
        if archive_target.path == receipt_target.path:
            raise DependencySeedBuildError("archive and receipt outputs must be different files")
        seed = _new_private_directory(seed_output, repository, allow_empty=False)
        if _inside(archive_target.path, seed.path) or _inside(receipt_target.path, seed.path):
            raise DependencySeedBuildError("archive and receipt outputs must stay outside the seed directory")
        all_outputs = (seed.path, archive_target.path, receipt_target.path)
        for output in all_outputs:
            for source in sources.values():
                if _inside(output, source) or _inside(source, output):
                    raise DependencySeedBuildError("dependency seed outputs must not overlap input caches")

        for component, relative in upgrade.DEPENDENCY_SEED_COMPONENTS.items():
            seed.assert_stable()
            _copy_component(
                sources[component],
                seed,
                relative,
                component,
                maven_wrapper_home=wrapper_home,
            )
        seed.assert_stable()
        _validate_maven_repository_provenance(
            seed.path / upgrade.DEPENDENCY_SEED_COMPONENTS["mavenRepository"]
        )
        _assert_stock_maven_settings_safe(
            seed.path
            / upgrade.DEPENDENCY_SEED_COMPONENTS["mavenHome"]
            / wrapper_home
            / "conf"
            / "settings.xml"
        )
        seed.assert_stable()
        manifest, aggregate_sha256 = _manifest_payload(repository, seed.path)
        manifest_bytes = (
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        _write_private_at(seed.descriptor, "manifest.json", manifest_bytes)
        seed.assert_stable()
        validated = upgrade.validate_dependency_seed(
            seed.path,
            expected_aggregate_sha256=aggregate_sha256,
            source_root=repository,
        )
        seed.assert_stable()
        if not hmac.compare_digest(validated.evidence["aggregateSha256"], aggregate_sha256):
            raise DependencySeedBuildError("producer returned a non-canonical dependency seed aggregate")
        archive_metadata = _create_deterministic_archive(seed, archive_target)
        if archive_metadata.st_size > MAX_ARCHIVE_BYTES:
            raise DependencySeedBuildError("dependency seed archive exceeds the transport size limit")
        validated_after_archive = upgrade.validate_dependency_seed(
            seed.path,
            expected_aggregate_sha256=aggregate_sha256,
            source_root=repository,
        )
        seed.assert_stable()
        if validated_after_archive.evidence != validated.evidence:
            raise DependencySeedBuildError("dependency seed changed while it was archived")
        archive_sha256 = _sha256_target(archive_target, archive_metadata)
        receipt = _receipt(archive_sha256, validated.evidence)
        receipt_metadata = _write_private(
            receipt_target,
            _receipt_bytes(receipt),
            "dependency seed receipt",
        )
        return receipt
    except Exception:
        if receipt_target is not None and receipt_metadata is not None:
            _unlink_target_if_same(receipt_target, receipt_metadata)
        if archive_target is not None and archive_metadata is not None:
            _unlink_target_if_same(archive_target, archive_metadata)
        if seed is not None:
            _clear_directory(seed, remove_root=seed.created)
        raise
    finally:
        if seed is not None:
            seed.close()
        if archive_target is not None:
            archive_target.close()
        if receipt_target is not None:
            receipt_target.close()


def _validated_archive_path(name: str) -> PurePosixPath:
    if not _safe_name(name) or "\\" in name or name.startswith("/") or name.endswith("/"):
        raise DependencySeedBuildError("dependency seed archive contains an unsafe path")
    path = PurePosixPath(name)
    if not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise DependencySeedBuildError("dependency seed archive contains traversal")
    if path.as_posix() != name:
        raise DependencySeedBuildError("dependency seed archive path is not canonical")
    if path.parts[0] != ARCHIVE_ROOT:
        raise DependencySeedBuildError("dependency seed archive must have one dependency-seed root")
    if len(path.parts) > 1:
        expected_top = {"manifest.json", *upgrade.DEPENDENCY_SEED_COMPONENTS.values()}
        if path.parts[1] not in expected_top:
            raise DependencySeedBuildError("dependency seed archive has an extra root entry")
    return path


def _validate_archive_members(archive: tarfile.TarFile) -> list[ArchiveMember]:
    members: list[ArchiveMember] = []
    by_name: dict[str, tarfile.TarInfo] = {}
    total_bytes = 0
    while True:
        try:
            info = archive.next()
        except (tarfile.TarError, OSError) as exception:
            raise DependencySeedBuildError("dependency seed archive cannot be enumerated") from exception
        if info is None:
            break
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise DependencySeedBuildError("dependency seed archive member count is invalid")
        # Python's GNU tar writer may add a trailing slash to a directory name
        # that needs a GNU long-name record.  Treat exactly one such suffix as
        # the canonical directory spelling; files and repeated slashes remain
        # invalid.
        archive_name = (
            info.name[:-1]
            if info.type == tarfile.DIRTYPE
            and info.name.endswith("/")
            and not info.name.endswith("//")
            else info.name
        )
        relative = _validated_archive_path(archive_name)
        name = relative.as_posix()
        if name in by_name:
            raise DependencySeedBuildError("dependency seed archive repeats a path")
        by_name[name] = info
        if (
            info.uid != 0
            or info.gid != 0
            or info.uname != ""
            or info.gname != ""
            or info.mtime != 0
            or info.pax_headers
        ):
            raise DependencySeedBuildError("dependency seed archive metadata is not canonical")
        if info.type == tarfile.DIRTYPE:
            if info.mode != 0o700 or info.size != 0:
                raise DependencySeedBuildError("dependency seed archive directory mode is invalid")
        elif info.type == tarfile.REGTYPE:
            if info.mode not in {0o600, 0o700} or info.size < 0:
                raise DependencySeedBuildError("dependency seed archive file mode is invalid")
            total_bytes += info.size
            if total_bytes > MAX_SEED_PAYLOAD_BYTES:
                raise DependencySeedBuildError("dependency seed archive exceeds its size limit")
        elif info.type == tarfile.SYMTYPE:
            if (
                len(relative.parts) < 3
                or relative.parts[1]
                != upgrade.DEPENDENCY_SEED_COMPONENTS["playwrightBrowsers"]
            ):
                raise DependencySeedBuildError("only Playwright archive members may be symbolic links")
            if info.mode != 0o777 or info.size != 0:
                raise DependencySeedBuildError("Playwright archive link mode is invalid")
            if (
                not _safe_name(info.linkname)
                or "\\" in info.linkname
                or PurePosixPath(info.linkname).is_absolute()
            ):
                raise DependencySeedBuildError("Playwright archive link target is unsafe")
            # Count path depth below the Playwright component root.  A link at
            # that root may not consume even one ``..`` segment.
            depth = len(relative.parent.parts) - 2
            for part in PurePosixPath(info.linkname).parts:
                if part in ("", "."):
                    continue
                if part == "..":
                    if depth == 0:
                        raise DependencySeedBuildError("Playwright archive link escapes its component")
                    depth -= 1
                else:
                    depth += 1
            if depth < 1:
                raise DependencySeedBuildError("Playwright archive link escapes its component")
        else:
            raise DependencySeedBuildError("dependency seed archive contains a special or hard-link member")
        members.append(ArchiveMember(info=info, relative=relative))

    if not members:
        raise DependencySeedBuildError("dependency seed archive member count is invalid")

    root_info = by_name.get(ARCHIVE_ROOT)
    if root_info is None or root_info.type != tarfile.DIRTYPE or root_info.mode != 0o700:
        raise DependencySeedBuildError("dependency seed archive root is not an exact mode-0700 directory")
    expected_top = {"manifest.json", *upgrade.DEPENDENCY_SEED_COMPONENTS.values()}
    top_level = {
        member.relative.parts[1]
        for member in members
        if len(member.relative.parts) == 2
    }
    if top_level != expected_top:
        raise DependencySeedBuildError("dependency seed archive top-level layout is not exact")
    for name in upgrade.DEPENDENCY_SEED_COMPONENTS.values():
        if by_name[f"{ARCHIVE_ROOT}/{name}"].type != tarfile.DIRTYPE:
            raise DependencySeedBuildError("dependency seed archive component root is not a directory")
    if by_name[f"{ARCHIVE_ROOT}/manifest.json"].type != tarfile.REGTYPE:
        raise DependencySeedBuildError("dependency seed archive manifest is not a regular file")

    symbolic_names = {
        member.relative.as_posix()
        for member in members
        if member.info.type == tarfile.SYMTYPE
    }
    for member in members:
        parts = member.relative.parts
        for length in range(1, len(parts)):
            parent = "/".join(parts[:length])
            parent_info = by_name.get(parent)
            if (
                parent_info is None
                or parent_info.type != tarfile.DIRTYPE
                or parent in symbolic_names
            ):
                raise DependencySeedBuildError("dependency seed archive has an implicit or linked parent")

    canonical_order = [members[0]] + sorted(
        members[1:], key=lambda member: os.fsencode(member.relative.as_posix())
    )
    if members[0].relative.as_posix() != ARCHIVE_ROOT or [
        member.relative.as_posix() for member in members
    ] != [member.relative.as_posix() for member in canonical_order]:
        raise DependencySeedBuildError("dependency seed archive member order is not canonical")
    return members


def _canonical_info_for_member(member: ArchiveMember) -> tarfile.TarInfo:
    original = member.info
    info = tarfile.TarInfo(member.relative.as_posix())
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = original.mode
    info.type = original.type
    info.size = original.size if original.type == tarfile.REGTYPE else 0
    info.linkname = original.linkname if original.type == tarfile.SYMTYPE else ""
    info.pax_headers = {}
    return info


def _open_unlinked_private_temp(parent: TrustedDirectory) -> int:
    parent.assert_stable("canonical archive temporary parent")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(128):
        name = f".web-starter-ac40-canonical-{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent.descriptor)
        except FileExistsError:
            continue
        created = os.fstat(descriptor)
        try:
            os.fchmod(descriptor, 0o600)
            _unlink_at_if_same(parent.descriptor, name, created)
            try:
                os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise DependencySeedBuildError("canonical archive temporary name was replaced")
            return descriptor
        except Exception:
            os.close(descriptor)
            try:
                _unlink_at_if_same(parent.descriptor, name, created)
            except OSError:
                pass
            raise
    raise DependencySeedBuildError("canonical archive temporary file cannot be created")


def _assert_canonical_archive(
    archive: tarfile.TarFile,
    members: Sequence[ArchiveMember],
    original_descriptor: int,
    trusted_parent: TrustedDirectory,
) -> None:
    """Re-serialize the semantic archive and require byte-identical SHA/size.

    This rejects concatenated archives, trailing data, alternate GNU/PAX
    metadata encodings and any parser-only representation that the one
    supported builder would not have emitted.
    """

    temporary = _open_unlinked_private_temp(trusted_parent)
    try:
        with os.fdopen(os.dup(temporary), "wb") as output:
            with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as generated:
                for member in members:
                    info = _canonical_info_for_member(member)
                    if info.type == tarfile.REGTYPE:
                        try:
                            source = archive.extractfile(member.info)
                        except (tarfile.TarError, OSError) as exception:
                            raise DependencySeedBuildError(
                                "dependency seed archive file cannot be opened"
                            ) from exception
                        if source is None:
                            raise DependencySeedBuildError(
                                "dependency seed archive file payload is missing"
                            )
                        try:
                            generated.addfile(info, source)
                        finally:
                            source.close()
                    else:
                        generated.addfile(info)
            output.flush()
            os.fsync(output.fileno())
        generated_metadata = os.fstat(temporary)
        original_metadata = os.fstat(original_descriptor)
        if generated_metadata.st_size != original_metadata.st_size:
            raise DependencySeedBuildError("dependency seed archive serialization is not canonical")
        generated_sha256 = _sha256_file_descriptor(temporary)
        original_sha256 = _sha256_file_descriptor(original_descriptor)
        if not hmac.compare_digest(generated_sha256, original_sha256):
            raise DependencySeedBuildError("dependency seed archive serialization is not canonical")
    finally:
        os.close(temporary)


def _extract_members(
    archive: tarfile.TarFile,
    members: Iterable[ArchiveMember],
    destination: PrivateDirectory,
) -> None:
    ordered = tuple(members)
    directories = sorted(
        (member for member in ordered if member.info.type == tarfile.DIRTYPE),
        key=lambda member: (len(member.relative.parts), os.fsencode(member.relative.as_posix())),
    )
    files = [member for member in ordered if member.info.type == tarfile.REGTYPE]
    links = [member for member in ordered if member.info.type == tarfile.SYMTYPE]

    def open_parent(member: ArchiveMember) -> int:
        descriptor = os.dup(destination.descriptor)
        try:
            for part in member.relative.parts[1:-1]:
                next_descriptor = _open_child_directory(descriptor, part)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    for member in directories:
        if len(member.relative.parts) == 1:
            continue
        parent_descriptor = open_parent(member)
        try:
            os.mkdir(member.relative.name, mode=0o700, dir_fd=parent_descriptor)
            created = _open_child_directory(parent_descriptor, member.relative.name)
            try:
                os.fchmod(created, 0o700)
            finally:
                os.close(created)
        finally:
            os.close(parent_descriptor)
    for member in files:
        try:
            source = archive.extractfile(member.info)
        except (tarfile.TarError, OSError) as exception:
            raise DependencySeedBuildError("dependency seed archive file cannot be opened") from exception
        if source is None:
            raise DependencySeedBuildError("dependency seed archive file payload is missing")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = open_parent(member)
        try:
            descriptor = os.open(
                member.relative.name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
        copied = 0
        try:
            while True:
                chunk = source.read(COPY_BUFFER_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > member.info.size:
                    raise DependencySeedBuildError("dependency seed archive file exceeds declared size")
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
            if copied != member.info.size:
                raise DependencySeedBuildError("dependency seed archive file is truncated")
            os.fchmod(descriptor, member.info.mode)
        finally:
            source.close()
            os.close(descriptor)
    for member in links:
        parent_descriptor = open_parent(member)
        try:
            os.symlink(
                member.info.linkname,
                member.relative.name,
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    destination.assert_stable()


def extract_and_verify_dependency_seed(
    *,
    repository_root: Path,
    archive_path: Path,
    expected_archive_sha256: str,
    expected_aggregate_sha256: str,
    seed_output: Path,
    receipt_output: Path | None = None,
) -> dict[str, Any]:
    """Verify the archive first, safely extract it, then rerun producer validation."""
    if not isinstance(expected_archive_sha256, str) or not SHA256.fullmatch(expected_archive_sha256):
        raise DependencySeedBuildError("expected archive SHA-256 is invalid")
    if not isinstance(expected_aggregate_sha256, str) or not SHA256.fullmatch(expected_aggregate_sha256):
        raise DependencySeedBuildError("expected aggregate SHA-256 is invalid")
    repository = _real_directory(repository_root, "candidate repository")
    archive_target, descriptor, archive_metadata = _existing_private_file(
        archive_path,
        repository,
        "dependency seed archive",
    )
    seed: PrivateDirectory | None = None
    receipt_target: PrivateFileTarget | None = None
    receipt_metadata: os.stat_result | None = None
    try:
        if not _same_file(archive_metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("dependency seed archive changed before hashing")
        actual_archive_sha256 = _sha256_file_descriptor(descriptor)
        if not hmac.compare_digest(actual_archive_sha256, expected_archive_sha256):
            raise DependencySeedBuildError("dependency seed archive SHA-256 does not match the expected value")

        # Hash verification intentionally happens before tar parsing.
        seed = _new_private_directory(seed_output, repository, allow_empty=True)
        if receipt_output is not None:
            receipt_target = _new_private_file_path(
                receipt_output,
                repository,
                "dependency seed receipt",
            )
            if _inside(receipt_target.path, seed.path):
                raise DependencySeedBuildError("dependency seed receipt must stay outside the seed directory")
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as archive_stream:
            try:
                with tarfile.open(fileobj=archive_stream, mode="r:") as archive:
                    members = _validate_archive_members(archive)
                    _assert_canonical_archive(
                        archive,
                        members,
                        descriptor,
                        archive_target.parent,
                    )
                    _extract_members(archive, members, seed)
            except (tarfile.TarError, EOFError, OSError) as exception:
                raise DependencySeedBuildError("dependency seed archive is invalid") from exception

        if not _same_file(archive_metadata, os.fstat(descriptor)):
            raise DependencySeedBuildError("dependency seed archive changed during extraction")
        if not hmac.compare_digest(_sha256_file_descriptor(descriptor), expected_archive_sha256):
            raise DependencySeedBuildError("dependency seed archive changed during extraction")
        archive_target.assert_parent_stable("dependency seed archive")
        seed.assert_stable()
        validated = upgrade.validate_dependency_seed(
            seed.path,
            expected_aggregate_sha256=expected_aggregate_sha256,
            source_root=repository,
        )
        seed.assert_stable()
        receipt = _receipt(actual_archive_sha256, validated.evidence)
        if receipt_target is not None:
            receipt_metadata = _write_private(
                receipt_target,
                _receipt_bytes(receipt),
                "dependency seed receipt",
            )
        return receipt
    except Exception:
        if receipt_target is not None and receipt_metadata is not None:
            _unlink_target_if_same(receipt_target, receipt_metadata)
        if seed is not None:
            _clear_directory(seed, remove_root=seed.created)
        raise
    finally:
        os.close(descriptor)
        archive_target.close()
        if seed is not None:
            seed.close()
        if receipt_target is not None:
            receipt_target.close()


def _path(value: str) -> Path:
    return Path(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build or safely extract the private AC40 dependency seed archive."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a normalized seed and deterministic archive")
    build.add_argument("--repository-root", type=_path, default=upgrade.REPOSITORY_ROOT)
    build.add_argument("--maven-home", type=_path, required=True)
    build.add_argument("--maven-repository", type=_path, required=True)
    build.add_argument("--corepack-home", type=_path, required=True)
    build.add_argument("--pnpm-store-root", type=_path, required=True)
    build.add_argument("--playwright-browsers", type=_path, required=True)
    build.add_argument(
        "--seed-output", type=_path, required=True,
        help="exact output seed root (the archive itself always uses dependency-seed/)",
    )
    build.add_argument("--archive-output", type=_path, required=True)
    build.add_argument("--receipt-output", type=_path, required=True)

    extract = commands.add_parser(
        "extract-verify", help="verify, safely extract and producer-validate an archive"
    )
    extract.add_argument("--repository-root", type=_path, default=upgrade.REPOSITORY_ROOT)
    extract.add_argument("--archive", type=_path, required=True)
    extract.add_argument("--expected-archive-sha256", required=True)
    extract.add_argument("--expected-aggregate-sha256", required=True)
    extract.add_argument(
        "--seed-output", type=_path, required=True,
        help="exact empty mode-0700 seed root; dependency-seed/ is stripped into this root",
    )
    extract.add_argument("--receipt-output", type=_path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "build":
            receipt = build_dependency_seed(
                BuildInputs(
                    repository_root=arguments.repository_root,
                    maven_home=arguments.maven_home,
                    maven_repository=arguments.maven_repository,
                    corepack_home=arguments.corepack_home,
                    pnpm_store_root=arguments.pnpm_store_root,
                    playwright_browsers=arguments.playwright_browsers,
                ),
                seed_output=arguments.seed_output,
                archive_output=arguments.archive_output,
                receipt_output=arguments.receipt_output,
            )
        else:
            receipt = extract_and_verify_dependency_seed(
                repository_root=arguments.repository_root,
                archive_path=arguments.archive,
                expected_archive_sha256=arguments.expected_archive_sha256,
                expected_aggregate_sha256=arguments.expected_aggregate_sha256,
                seed_output=arguments.seed_output,
                receipt_output=arguments.receipt_output,
            )
    except (DependencySeedBuildError, upgrade.UpgradeRehearsalError) as exception:
        print(f"error: {exception}", file=sys.stderr)
        return 1
    print(_receipt_bytes(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
