#!/usr/bin/env python3
"""Build a private acceptance JWK Set from two PKCS#1 RSA keys.

The active JWK retains private signing material. The retiring JWK contains only
the public modulus and exponent plus an explicit standard ``exp`` NumericDate,
proving that an application can verify old tokens for a bounded window without
continuing to distribute the old private key.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys


class JwkSetError(RuntimeError):
    """Raised when an acceptance key cannot be parsed or written safely."""


KID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _read_length(document: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(document):
        raise JwkSetError("truncated DER length")
    first = document[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(document):
        raise JwkSetError("invalid DER length")
    length = int.from_bytes(document[offset:offset + count], "big")
    if length < 0x80:
        raise JwkSetError("non-minimal DER length")
    return length, offset + count


def _read_value(document: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(document) or document[offset] != expected_tag:
        raise JwkSetError("unexpected DER tag")
    length, value_offset = _read_length(document, offset + 1)
    end = value_offset + length
    if end > len(document):
        raise JwkSetError("truncated DER value")
    return document[value_offset:end], end


def _unsigned_integer(encoded: bytes) -> int:
    if not encoded or encoded[0] & 0x80:
        raise JwkSetError("invalid RSA DER integer")
    if len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80:
        raise JwkSetError("non-minimal RSA DER integer")
    return int.from_bytes(encoded, "big")


def _parse_pkcs1(document: bytes) -> tuple[int, ...]:
    sequence, end = _read_value(document, 0, 0x30)
    if end != len(document):
        raise JwkSetError("trailing data after RSA private key")
    values: list[int] = []
    offset = 0
    while offset < len(sequence):
        encoded, offset = _read_value(sequence, offset, 0x02)
        values.append(_unsigned_integer(encoded))
    if len(values) != 9 or values[0] != 0:
        raise JwkSetError("expected a two-prime PKCS#1 RSA private key")
    return tuple(values[1:])


def _base64url_integer(value: int) -> str:
    if value <= 0:
        raise JwkSetError("RSA integer must be positive")
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _private_jwk(pkcs1: tuple[int, ...], kid: str) -> dict[str, str]:
    n, e, d, p, q, dp, dq, qi = pkcs1
    return {
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": _base64url_integer(n), "e": _base64url_integer(e),
        "d": _base64url_integer(d), "p": _base64url_integer(p),
        "q": _base64url_integer(q), "dp": _base64url_integer(dp),
        "dq": _base64url_integer(dq), "qi": _base64url_integer(qi),
    }


def _public_jwk(
        pkcs1: tuple[int, ...], kid: str,
        retain_until_epoch_seconds: int) -> dict[str, str | int]:
    n, e, *_ = pkcs1
    return {
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": _base64url_integer(n), "e": _base64url_integer(e),
        "exp": retain_until_epoch_seconds,
    }


def _private_key(path: Path, label: str) -> tuple[int, ...]:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise JwkSetError(f"{label} must be a real regular file")
    resolved = expanded.resolve()
    if not resolved.is_file():
        raise JwkSetError(f"{label} must be a real regular file")
    if os.name == "posix" and resolved.stat().st_mode & 0o077:
        raise JwkSetError(f"{label} must be private (chmod 600)")
    return _parse_pkcs1(resolved.read_bytes())


def write_jwk_set(
        active_path: Path, retiring_path: Path, output_path: Path,
        active_kid: str, retiring_kid: str,
        retiring_retain_until_epoch_seconds: int) -> None:
    if not KID_PATTERN.fullmatch(active_kid) or not KID_PATTERN.fullmatch(retiring_kid):
        raise JwkSetError("kid must be a stable 1-64 character identifier")
    if active_kid == retiring_kid:
        raise JwkSetError("active and retiring kid values must differ")
    if (
        isinstance(retiring_retain_until_epoch_seconds, bool)
        or retiring_retain_until_epoch_seconds <= 0
        or retiring_retain_until_epoch_seconds > 253402300799
    ):
        raise JwkSetError("retiring retain-until must be a valid positive NumericDate")
    document = {
        "keys": [
            _private_jwk(_private_key(active_path, "active key"), active_kid),
            _public_jwk(
                _private_key(retiring_path, "retiring key"),
                retiring_kid,
                retiring_retain_until_epoch_seconds,
            ),
        ]
    }
    expanded_output = output_path.expanduser()
    if expanded_output.exists() or expanded_output.is_symlink():
        raise JwkSetError("output JWK Set must not already exist")
    output = expanded_output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--active-private-der", required=True, type=Path)
    parser.add_argument("--retiring-private-der", required=True, type=Path)
    parser.add_argument("--active-kid", required=True)
    parser.add_argument("--retiring-kid", required=True)
    parser.add_argument(
        "--retiring-retain-until-epoch-seconds", required=True, type=int,
        help="exclusive standard JWK exp NumericDate for the retiring key",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        write_jwk_set(
            args.active_private_der, args.retiring_private_der, args.output,
            args.active_kid, args.retiring_kid,
            args.retiring_retain_until_epoch_seconds,
        )
    except (JwkSetError, OSError, ValueError) as error:
        print(f"FAIL acceptance-jwk-set: {error}", file=sys.stderr)
        return 1
    print("PASS acceptance-jwk-set: active signing key and public-only retiring key written privately")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
