from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

import acceptance_jwk_set as jwks


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\0" + encoded
    return b"\x02" + _der_length(len(encoded)) + encoded


def _pkcs1(seed: int) -> bytes:
    values = [0, 3233 + seed, 17, 2753, 61, 53, 53, 49, 38]
    body = b"".join(_der_integer(value) for value in values)
    return b"\x30" + _der_length(len(body)) + body


class AcceptanceJwkSetTest(unittest.TestCase):
    def test_writer_keeps_only_active_private_material_and_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "active.der"
            retiring = root / "retiring.der"
            active.write_bytes(_pkcs1(0))
            retiring.write_bytes(_pkcs1(2))
            active.chmod(0o600)
            retiring.chmod(0o600)
            output = root / "jwks.json"

            jwks.write_jwk_set(
                active, retiring, output,
                "active-2026", "retiring-2025", 1784541600,
            )

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(["active-2026", "retiring-2025"], [key["kid"] for key in document["keys"]])
            self.assertIn("d", document["keys"][0])
            self.assertNotIn("d", document["keys"][1])
            self.assertNotIn("exp", document["keys"][0])
            self.assertEqual(1784541600, document["keys"][1]["exp"])
            self.assertEqual(0, stat.S_IMODE(output.stat().st_mode) & 0o077)

    def test_writer_rejects_duplicate_kid_and_non_private_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "active.der"
            retiring = root / "retiring.der"
            active.write_bytes(_pkcs1(0))
            retiring.write_bytes(_pkcs1(2))
            active.chmod(0o644)
            retiring.chmod(0o600)
            with self.assertRaisesRegex(jwks.JwkSetError, "differ"):
                jwks.write_jwk_set(
                    active, retiring, root / "one.json", "same", "same", 1784541600,
                )
            with self.assertRaisesRegex(jwks.JwkSetError, "private"):
                jwks.write_jwk_set(
                    active, retiring, root / "two.json",
                    "active", "retiring", 1784541600,
                )

    def test_writer_rejects_invalid_retiring_numeric_date(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "active.der"
            retiring = root / "retiring.der"
            active.write_bytes(_pkcs1(0))
            retiring.write_bytes(_pkcs1(2))
            active.chmod(0o600)
            retiring.chmod(0o600)

            for index, invalid in enumerate((0, -1, 253402300800)):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(jwks.JwkSetError, "NumericDate"):
                        jwks.write_jwk_set(
                            active, retiring, root / f"invalid-{index}.json",
                            "active", "retiring", invalid,
                        )

    def test_parser_rejects_trailing_data(self) -> None:
        with self.assertRaisesRegex(jwks.JwkSetError, "trailing"):
            jwks._parse_pkcs1(_pkcs1(0) + b"unexpected")


if __name__ == "__main__":
    unittest.main()
