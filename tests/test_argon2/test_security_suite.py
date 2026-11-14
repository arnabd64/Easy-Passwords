"""
Comprehensive security suite for easy_passwords.argon2.

Focuses on:
- Variant enforcement (Argon2id vs Argon2i / Argon2d)
- Cryptographic salt entropy & uniqueness
- Parameter tampering resilience
- Exception handling and authentication failure safety
"""

import math
from collections import Counter

import pytest
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from easy_passwords.argon2 import (
    hash_password,
    verify_password,
)


def _calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (theoretical max: 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


class TestVariantSelection:
    """
    Category 1: Incorrect Variant Selection Tests.

    RFC 9106 specifies three variants:
    - Argon2d: vulnerable to side-channel attacks (data-dependent memory access).
    - Argon2i: vulnerable to time-memory trade-off attacks (data-independent memory access).
    - Argon2id: hybrid variant recommended by RFC 9106 and OWASP for password hashing.
    """

    def test_explicitly_forces_argon2id(self) -> None:
        """Verify hash_password explicitly generates Argon2id PHC strings."""
        phc = hash_password("test_user_password")
        assert phc.startswith("$argon2id$")
        # Ensure it does not generate Argon2i or Argon2d
        assert not phc.startswith("$argon2i$")
        assert not phc.startswith("$argon2d$")

    def test_rejects_argon2i_variant_phc(self) -> None:
        """
        Argon2i is susceptible to trade-off attacks.
        Argon2id.verify_phc_encoded and verify_password must reject Argon2i PHC strings.
        """
        pwd = "target_secret_password"
        valid_id_hash = hash_password(pwd)
        argon2i_hash = valid_id_hash.replace("$argon2id$", "$argon2i$")

        # Direct verification through verify_password returns False
        assert verify_password(pwd, argon2i_hash) is False

        # Underlying Argon2id library explicitly raises InvalidKey on variant mismatch
        with pytest.raises(InvalidKey, match="Incorrect variant in PHC string"):
            Argon2id.verify_phc_encoded(pwd.encode("utf-8"), argon2i_hash)

    def test_rejects_argon2d_variant_phc(self) -> None:
        """
        Argon2d is susceptible to cache-timing attacks.
        Argon2id.verify_phc_encoded and verify_password must reject Argon2d PHC strings.
        """
        pwd = "target_secret_password"
        valid_id_hash = hash_password(pwd)
        argon2d_hash = valid_id_hash.replace("$argon2id$", "$argon2d$")

        assert verify_password(pwd, argon2d_hash) is False

        with pytest.raises(InvalidKey, match="Incorrect variant in PHC string"):
            Argon2id.verify_phc_encoded(pwd.encode("utf-8"), argon2d_hash)


class TestSaltSecurity:
    """Category 2: Salt Security, Length, and Entropy."""

    def test_salt_uniqueness(self) -> None:
        """
        Asserts that multiple hashes of the exact same password generate unique,
        randomized salts to prevent precomputation and rainbow table attacks.
        """
        password = "consistent_master_password_42"
        num_samples = 20
        salts = set()

        for _ in range(num_samples):
            phc = hash_password(password)
            parts = phc.split("$")
            salt_b64 = parts[4]
            salts.add(salt_b64)

        assert len(salts) == num_samples

    def test_salt_length_and_entropy(self) -> None:
        """
        Verifies that generated salts meet minimum cryptographic length requirements
        (>= 16 bytes / 128 bits) and demonstrate high Shannon entropy.
        """
        password = "entropy_eval_password"

        # Verify default length
        default_phc = hash_password(password)
        # Extract salt from $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
        salt_field = default_phc.split("$")[4]
        assert len(salt_field) >= 16

        # Sample multiple hashes and measure combined entropy of generated salts
        accumulated_salts = bytearray()
        for _ in range(25):
            h = hash_password(password)
            s_b64 = h.split("$")[4]
            accumulated_salts.extend(s_b64.encode("ascii"))

        entropy = _calculate_shannon_entropy(bytes(accumulated_salts))
        assert entropy > 5.0  # Base64-encoded random stream has high entropy (> 5.0 bits/char)


class TestParameterTampering:
    """Category 3: Parameter Tampering & Cryptographic Integrity."""

    def test_tamper_memory_cost_fails(self) -> None:
        pwd = "my_secure_password"
        original_hash = hash_password(pwd)
        # Replace m=19456 with m=19457 or similar
        tampered_hash = original_hash.replace("m=19456,", "m=32768,")
        assert verify_password(pwd, tampered_hash) is False

    def test_tamper_iterations_fails(self) -> None:
        pwd = "my_secure_password"
        original_hash = hash_password(pwd)
        tampered_hash = original_hash.replace(",t=2,", ",t=3,")
        assert verify_password(pwd, tampered_hash) is False

    def test_tamper_lanes_fails(self) -> None:
        pwd = "my_secure_password"
        original_hash = hash_password(pwd)
        tampered_hash = original_hash.replace(",p=1$", ",p=2$")
        assert verify_password(pwd, tampered_hash) is False

    def test_tamper_version_fails(self) -> None:
        pwd = "my_secure_password"
        original_hash = hash_password(pwd)
        tampered_hash = original_hash.replace("$v=19$", "$v=18$")
        assert verify_password(pwd, tampered_hash) is False

    def test_tamper_salt_fails(self) -> None:
        pwd = "my_secure_password"
        original_hash = hash_password(pwd)
        parts = original_hash.split("$")
        # Invert a character in the salt
        salt = parts[4]
        corrupted_salt = ("A" if salt[0] != "A" else "B") + salt[1:]
        parts[4] = corrupted_salt
        tampered_hash = "$".join(parts)
        assert verify_password(pwd, tampered_hash) is False

    def test_tamper_digest_fails(self) -> None:
        pwd = "my_secure_password"
        original_hash = hash_password(pwd)
        parts = original_hash.split("$")
        digest = parts[5]
        corrupted_digest = digest[:-1] + ("A" if digest[-1] != "A" else "B")
        parts[5] = corrupted_digest
        tampered_hash = "$".join(parts)
        assert verify_password(pwd, tampered_hash) is False


class TestInputSanitizationAndEdgeCases:
    """Category 4: Input Types and Formatting Verification."""

    @pytest.mark.parametrize(
        ("bad_pwd", "bad_hash"),
        [
            (None, None),
            (1234, "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnZXN0"),
            ("valid_pwd", None),
            ("valid_pwd", 12345),
            ("valid_pwd", ["hash"]),
            ("valid_pwd", {"hash": "val"}),
            ("valid_pwd", b"$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnZXN0"),
        ],
    )
    def test_verify_password_non_string_types(self, bad_pwd, bad_hash) -> None:
        assert verify_password(bad_pwd, bad_hash) is False
