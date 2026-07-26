#!/usr/bin/env python3
"""Repository policy checks for secrets and externally supplied forbidden terms.

The checks intentionally use only the Python standard library so the same
command can run on a developer workstation and in CI.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence


PASS = 0
FAIL = 1
SKIP = 2

FORBIDDEN_TERMS_ENV = "WEB_STARTER_FORBIDDEN_TERMS"
FORBIDDEN_TERMS_FILE_ENV = "WEB_STARTER_FORBIDDEN_TERMS_FILE"

FALLBACK_EXCLUDED_DIRECTORIES = {
    ".git",
    ".idea",
    ".vite",
    ".vscode",
    "coverage",
    "data",
    "dist",
    "logs",
    "node_modules",
    "playwright-report",
    "screenshots",
    "target",
    "test-results",
    "tmp",
}

PROHIBITED_CREDENTIAL_SUFFIXES = {
    ".cer",
    ".crt",
    ".der",
    ".jks",
    ".key",
    ".kdbx",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
}

PROHIBITED_CREDENTIAL_FILENAMES = {
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "service-account.json",
    "service_account.json",
}

CONFIG_SUFFIXES = {
    ".conf",
    ".config",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".xml",
    ".yaml",
    ".yml",
}

SECRET_PATTERNS = (
    (
        "private-key-material",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
    ),
    ("cloud-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "source-hosting-token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{70,}|glpat-[A-Za-z0-9_-]{20,})\b"
        ),
    ),
    (
        "chat-provider-token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    ),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "ai-provider-token",
        re.compile(
            r"\b(?:sk-(?:proj-|svcacct-|ant-api[0-9]{2}-)?[0-9A-Za-z_-]{20,}|hf_[0-9A-Za-z]{30,})\b"
        ),
    ),
    ("payment-live-secret", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    (
        "email-provider-token",
        re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b"),
    ),
    ("package-registry-token", re.compile(r"\bnpm_[0-9A-Za-z]{36,}\b")),
    ("communications-provider-token", re.compile(r"\bSK[0-9A-Fa-f]{32}\b")),
    (
        "jwt-or-bearer-token",
        re.compile(
            r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"
        ),
    ),
    (
        "credential-in-url",
        re.compile(
            r"https?://[^\s/:@]+:[^\s/@]{4,}@"
            r"(?!(?:[^/\s]+\.)?(?:example|test|invalid)(?::\d+)?(?:[/\s]|$))",
            re.IGNORECASE,
        ),
    ),
    (
        "literal-bearer-token",
        re.compile(
            r"\bBearer\s+(?!\$|\{|<|replace-|redacted)[0-9A-Za-z._~+/=-]{20,}",
            re.IGNORECASE,
        ),
    ),
)

ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:export\s+)?[\"']?([A-Za-z0-9_.-]+)[\"']?\s*(?:=|:)\s*(.*?)\s*$",
    re.IGNORECASE,
)

SENSITIVE_KEY_SUFFIXES = (
    "accesskey",
    "apikey",
    "authkey",
    "clientsecret",
    "credential",
    "encryptionkey",
    "masterkey",
    "passphrase",
    "passwd",
    "password",
    "pepper",
    "privatekey",
    "refreshtoken",
    "secret",
    "signingkey",
    "token",
)

PLACEHOLDER_PREFIXES = (
    "change-me",
    "changeme",
    "dummy-",
    "example-",
    "fake-",
    "placeholder-",
    "redacted",
    "replace-with-",
    "sample-",
    "test-only",
    "testing-only",
    "validation-only",
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int | None
    rule: str


@dataclass(frozen=True)
class ScanInput:
    relative_path: str
    path: Path


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _git_candidates(root: Path) -> list[ScanInput] | None:
    if not (root / ".git").exists():
        return None
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return None

    candidates: list[ScanInput] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative_path = raw_path.decode("utf-8", errors="surrogateescape")
        path = root / relative_path
        if path.is_file() and not path.is_symlink():
            candidates.append(ScanInput(relative_path, path))
    return sorted(candidates, key=lambda candidate: candidate.relative_path)


def _filesystem_candidates(root: Path) -> list[ScanInput]:
    candidates: list[ScanInput] = []
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in FALLBACK_EXCLUDED_DIRECTORIES
        )
        current_path = Path(current_root)
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative_path = path.relative_to(root).as_posix()
            candidates.append(ScanInput(relative_path, path))
    return candidates


def repository_candidates(root: Path) -> list[ScanInput]:
    """Return files eligible for commit, including currently untracked files."""

    git_candidates = _git_candidates(root)
    return git_candidates if git_candidates is not None else _filesystem_candidates(root)


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _is_config_file(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in CONFIG_SUFFIXES


def _normalise_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def _is_sensitive_key(key: str) -> bool:
    normalised = _normalise_sensitive_key(key)
    return any(normalised.endswith(suffix) for suffix in SENSITIVE_KEY_SUFFIXES)


def _clean_assignment_value(raw_value: str) -> str:
    value = raw_value.strip().rstrip(",;").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def _is_placeholder_or_reference(value: str) -> bool:
    if not value:
        return True
    lowered = value.casefold().strip()
    if lowered in {"false", "none", "null", "off", "true", "unset"}:
        return True
    # Line-oriented config scanning must not mistake a JSON/YAML mapping or
    # sequence opener for a literal credential. Nested scalar assignments are
    # still scanned on their own lines. JSON Schema references are structural
    # metadata too, but keep this allowance exact rather than accepting every
    # object-shaped value.
    if value in {"{", "[", "{}", "[]"}:
        return True
    if re.fullmatch(r'\{\s*"\$ref"\s*:\s*"[^"\r\n]+"\s*\}', value):
        return True
    if value.startswith(("$", "{{", "<")):
        return True
    if value.endswith(">") and value.startswith("<"):
        return True
    if lowered.startswith(PLACEHOLDER_PREFIXES):
        return True
    if re.fullmatch(r"[_*xX-]+", value):
        return True
    return False


def scan_secrets(candidates: Sequence[ScanInput]) -> list[Finding]:
    findings: list[Finding] = []
    for candidate in candidates:
        path = candidate.path
        lowered_name = path.name.casefold()
        if (
            path.suffix.casefold() in PROHIBITED_CREDENTIAL_SUFFIXES
            or lowered_name in PROHIBITED_CREDENTIAL_FILENAMES
        ):
            findings.append(Finding(candidate.relative_path, None, "credential-file"))

        text = _read_text(path)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(candidate.relative_path, line_number, rule))
            if not _is_config_file(path):
                continue
            assignment = ASSIGNMENT_PATTERN.match(line)
            if assignment is None or not _is_sensitive_key(assignment.group(1)):
                continue
            value = _clean_assignment_value(assignment.group(2))
            if not _is_placeholder_or_reference(value):
                findings.append(
                    Finding(candidate.relative_path, line_number, "literal-sensitive-value")
                )
    return _deduplicate_findings(findings)


def _deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        set(findings),
        key=lambda finding: (finding.path, finding.line or 0, finding.rule),
    )


def _parse_terms(raw_terms: str) -> list[str]:
    terms: list[str] = []
    seen: set[str] = set()
    for raw_line in raw_terms.splitlines():
        term = raw_line.strip()
        if not term or term.startswith("#"):
            continue
        folded = term.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        terms.append(term)
    return terms


def load_forbidden_terms(
    root: Path,
    terms_file_argument: str | None,
    environment: dict[str, str] | os._Environ[str],
) -> tuple[list[str] | None, str | None]:
    root = root.resolve()
    direct_terms = environment.get(FORBIDDEN_TERMS_ENV, "")
    environment_file = environment.get(FORBIDDEN_TERMS_FILE_ENV, "")
    sources = [
        bool(direct_terms.strip()),
        bool(environment_file.strip()),
        bool(terms_file_argument and terms_file_argument.strip()),
    ]
    if sum(sources) > 1:
        return None, "configure exactly one forbidden-term source"
    if not any(sources):
        return None, None

    if direct_terms.strip():
        terms = _parse_terms(direct_terms)
    else:
        configured_path = terms_file_argument or environment_file
        terms_path = Path(configured_path).expanduser().resolve()
        if _inside(terms_path, root):
            return None, "forbidden-term files must remain outside the repository"
        try:
            terms = _parse_terms(terms_path.read_text(encoding="utf-8"))
        except OSError:
            return None, "the configured forbidden-term file could not be read"

    if not terms:
        return None, "the configured forbidden-term source contains no terms"
    return terms, None


def scan_forbidden_terms(
    candidates: Sequence[ScanInput], terms: Sequence[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for candidate in candidates:
        for index, term in enumerate(terms, start=1):
            if _contains_forbidden_term(candidate.relative_path, term):
                findings.append(
                    Finding(candidate.relative_path, None, f"forbidden-term-{index}")
                )

        text = _read_text(candidate.path)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for index, term in enumerate(terms, start=1):
                if _contains_forbidden_term(line, term):
                    findings.append(
                        Finding(
                            candidate.relative_path,
                            line_number,
                            f"forbidden-term-{index}",
                        )
                    )
    return _deduplicate_findings(findings)


def _contains_forbidden_term(value: str, term: str) -> bool:
    """Match short uppercase acronyms as words, other terms as case-insensitive text.

    This prevents a three-letter business acronym from matching the middle of
    an unrelated identifier while retaining broad matching for names and
    natural-language phrases.
    """

    if re.fullmatch(r"[A-Z0-9]{2,5}", term):
        return re.search(
            rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", value
        ) is not None
    return term.casefold() in value.casefold()


def _print_findings(label: str, findings: Sequence[Finding]) -> None:
    print(f"FAIL {label}: {len(findings)} finding(s)")
    for finding in findings:
        location = finding.path
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        print(f"  {location} [{finding.rule}]")


def run_secret_check(candidates: Sequence[ScanInput]) -> int:
    findings = scan_secrets(candidates)
    if findings:
        _print_findings("repository-secret-scan", findings)
        return FAIL
    print(f"PASS repository-secret-scan: {len(candidates)} file(s), zero findings")
    return PASS


def run_forbidden_check(
    root: Path,
    candidates: Sequence[ScanInput],
    terms_file_argument: str | None,
    environment: dict[str, str] | os._Environ[str],
) -> int:
    terms, error = load_forbidden_terms(root, terms_file_argument, environment)
    if terms is None:
        if error is None:
            print(
                "SKIP forbidden-business-term-scan: configure "
                f"{FORBIDDEN_TERMS_ENV} or {FORBIDDEN_TERMS_FILE_ENV}"
            )
        else:
            print(f"SKIP forbidden-business-term-scan: {error}")
        return SKIP

    findings = scan_forbidden_terms(candidates, terms)
    if findings:
        _print_findings("forbidden-business-term-scan", findings)
        return FAIL
    print(
        "PASS forbidden-business-term-scan: "
        f"{len(terms)} externally supplied term(s), {len(candidates)} file(s), zero findings"
    )
    return PASS


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("secrets", "forbidden", "all"))
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[1]),
        help="repository root; defaults to the parent of this script directory",
    )
    parser.add_argument(
        "--forbidden-terms-file",
        help="UTF-8 term file outside the repository; one term per line",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_arguments(arguments if arguments is not None else sys.argv[1:])
    root = Path(options.root).expanduser().resolve()
    if not root.is_dir():
        print("SKIP repository-policy: repository root does not exist")
        return SKIP

    candidates = repository_candidates(root)
    results: list[int] = []
    if options.check in {"secrets", "all"}:
        results.append(run_secret_check(candidates))
    if options.check in {"forbidden", "all"}:
        results.append(
            run_forbidden_check(
                root,
                candidates,
                options.forbidden_terms_file,
                os.environ,
            )
        )

    if FAIL in results:
        return FAIL
    if SKIP in results:
        return SKIP
    return PASS


if __name__ == "__main__":
    raise SystemExit(main())
