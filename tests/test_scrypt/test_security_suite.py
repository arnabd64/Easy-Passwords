"""
Security test suite for easy_passwords.scrypt covering the full 11-test specification.

Categories:
1. Salt Security & Uniqueness
   - test_salt_uniqueness
   - test_salt_length_and_entropy
2. Timing & Comparison Safety
   - test_constant_time_verification
3. Parameter Bounds & Resource Limits
   - test_parameter_bounds_minimum
   - test_parameter_bounds_maximum
   - test_maxmem_enforcement
4. Input Sanitization & Edge Cases
   - test_empty_or_null_inputs
   - test_unicode_and_multibyte_passwords
5. Robustness & Malformed Data Parsing
   - test_malformed_hash_structure
   - test_scheme_mismatch
   - test_derived_key_length_mismatch
"""

import math
from collections import Counter
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from easy_passwords.scrypt import (
    MAX_HASH_LENGTH,
    MAX_LOG2_N,
    MAX_P,
    MAX_PASSWORD_LENGTH,
    MAX_R,
    MAX_SALT_LENGTH,
    MIN_HASH_LENGTH,
    MIN_LOG2_N,
    MIN_P,
    MIN_R,
    MIN_SALT_LENGTH,
    OPENSSL_MAX_MEMORY,
    SALT_LENGTH,
    _encode,
    _parse_hashed_password,
    _validate_params,
    hash_password,
    verify_password,
)


def _calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte for the given byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


class TestSaltSecurity:
    """Category 1: Salt Security & Uniqueness."""

    def test_salt_uniqueness(self) -> None:
        """
        Asserts that multiple hashes of the exact same password generate unique,
        randomized salts to prevent precomputation and rainbow table attacks.
        """
        password = "consistent-master-password-123!"
        num_samples = 30
        salts = set()

        for _ in range(num_samples):
            # Using fast ln=10 for test performance while maintaining cryptographic salt generation
            phc_hash = hash_password(password, ln=10, r=4, p=1)
            salt, _, _ = _parse_hashed_password(phc_hash)
            salts.add(salt)

        # Every single generated salt must be distinct (zero collisions)
        assert len(salts) == num_samples

        # Also verify with default parameters
        default_hash_1 = hash_password(password)
        default_hash_2 = hash_password(password)
        salt_1, _, _ = _parse_hashed_password(default_hash_1)
        salt_2, _, _ = _parse_hashed_password(default_hash_2)
        assert salt_1 != salt_2

    def test_salt_length_and_entropy(self) -> None:
        """
        Verifies that generated salts meet minimum cryptographic length requirements
        (at least 16 bytes / 128 bits of randomness) and demonstrate high entropy.
        """
        password = "entropy-check-password"

        # 1. Verify default salt length meets/exceeds 16 bytes (128 bits)
        default_hash = hash_password(password, ln=10, r=4, p=1)
        default_salt, _, _ = _parse_hashed_password(default_hash)
        assert len(default_salt) >= 16
        assert len(default_salt) == SALT_LENGTH  # Default is 32 bytes (256 bits)

        # 2. Verify custom salt lengths adhere to bounds
        custom_hash_16 = hash_password(password, salt_length=16, ln=10, r=4, p=1)
        salt_16, _, _ = _parse_hashed_password(custom_hash_16)
        assert len(salt_16) == 16

        with pytest.raises(ValueError, match="salt_length should be within"):
            hash_password(password, salt_length=MIN_SALT_LENGTH - 1)

        # 3. Verify entropy of generated salts approaches uniform randomness (8.0 bits/byte)
        # Sample 50 salts of 32 bytes each (1600 bytes total)
        accumulated_salt_bytes = bytearray()
        for _ in range(50):
            h = hash_password(password, ln=10, r=4, p=1)
            s, _, _ = _parse_hashed_password(h)
            accumulated_salt_bytes.extend(s)

        entropy = _calculate_shannon_entropy(bytes(accumulated_salt_bytes))
        # For high-quality CSPRNG bytes, entropy should comfortably exceed 7.3 bits/byte
        assert entropy > 7.3, f"Salt entropy too low: {entropy:.2f} bits/byte"


class TestTimingAndComparisonSafety:
    """Category 2: Timing & Comparison Safety."""

    def test_constant_time_verification(self) -> None:
        """
        Ensures that password verification uses constant-time comparison methods
        (such as cryptography KDF Scrypt.verify which invokes OpenSSL CRYPTO_memcmp)
        rather than standard short-circuit equality operators (==) to mitigate side-channel timing attacks.
        """
        password = "timing-safe-password"
        original_hash = hash_password(password, ln=10, r=4, p=1)
        salt, digest, params = _parse_hashed_password(original_hash)

        # 1. Architectural assertion: verify that Scrypt.verify is invoked by verify_password
        orig_verify = Scrypt.verify
        call_log = []

        def tracking_verify(self, key_material, expected_key):
            call_log.append((key_material, expected_key))
            return orig_verify(self, key_material, expected_key)

        with patch.object(Scrypt, "verify", tracking_verify):
            assert verify_password(password, original_hash) is True
        assert len(call_log) == 1
        assert call_log[0][0] == password.encode("utf-8")
        assert call_log[0][1] == digest

        # 2. Tampered digests at different byte positions (first, middle, last)
        # All must fail securely without short-circuiting or crashing
        for offset in (0, len(digest) // 2, len(digest) - 1):
            tampered_digest = bytearray(digest)
            tampered_digest[offset] ^= 0xFF
            tampered_hash = f"$scrypt$ln={params['ln']},r={params['r']},p={params['p']}${_encode(salt)}${_encode(bytes(tampered_digest))}"
            assert verify_password(password, tampered_hash) is False


class TestParameterBoundsAndResourceLimits:
    """Category 3: Parameter Bounds & Resource Limits."""

    def test_parameter_bounds_minimum(self) -> None:
        """
        Validates that sub-minimum or invalid cost parameters
        (N < 2 or non-power-of-two values where restricted) are correctly rejected.
        """
        password = "bounds-minimum-password"

        # The implementation uses ln (log2(N)), ensuring N = 2^ln is always a power of 2.
        # Sub-minimum ln (< MIN_LOG2_N) must be rejected
        with pytest.raises(ValueError, match="ln should be within"):
            hash_password(password, ln=MIN_LOG2_N - 1, r=MIN_R, p=MIN_P)

        # Sub-minimum block size r (< MIN_R) must be rejected
        with pytest.raises(ValueError, match="r should be within"):
            hash_password(password, ln=MIN_LOG2_N, r=MIN_R - 1, p=MIN_P)

        # Sub-minimum parallelism p (< MIN_P) must be rejected
        with pytest.raises(ValueError, match="p should be within"):
            hash_password(password, ln=MIN_LOG2_N, r=MIN_R, p=MIN_P - 1)

        # Sub-minimum salt length and hash length
        with pytest.raises(ValueError, match="salt_length should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH - 1,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )

        with pytest.raises(ValueError, match="dklen should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH - 1,
            )

        # Sub-minimum parameters in PHC hash string must fail verification
        sub_min_hash = "$scrypt$ln=9,r=3,p=0$c2FsdHNhbHQ=$ZGlnZXN0ZGlnZXN0"
        assert verify_password(password, sub_min_hash) is False

    def test_parameter_bounds_maximum(self) -> None:
        """
        Ensures that excessively high CPU/memory cost parameters (N, r, p)
        trigger proper validation limits.
        """
        password = "bounds-maximum-password"

        # Excessively high ln (> MAX_LOG2_N)
        with pytest.raises(ValueError, match="ln should be within"):
            hash_password(password, ln=MAX_LOG2_N + 1, r=MIN_R, p=MIN_P)

        # Excessively high block size r (> MAX_R)
        with pytest.raises(ValueError, match="r should be within"):
            hash_password(password, ln=MIN_LOG2_N, r=MAX_R + 1, p=MIN_P)

        # Excessively high parallelism p (> MAX_P)
        with pytest.raises(ValueError, match="p should be within"):
            hash_password(password, ln=MIN_LOG2_N, r=MIN_R, p=MAX_P + 1)

        # Excessively high salt and hash lengths
        with pytest.raises(ValueError, match="salt_length should be within"):
            _validate_params(
                salt_length=MAX_SALT_LENGTH + 1,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MAX_HASH_LENGTH,
            )

        with pytest.raises(ValueError, match="dklen should be within"):
            _validate_params(
                salt_length=MAX_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MAX_HASH_LENGTH + 1,
            )

        # Excessive values in PHC string must be safely rejected without memory allocation
        exorbitant_hash = (
            "$scrypt$ln=999999999,r=999999,p=999999$c2FsdHNhbHQ=$ZGlnZXN0ZGlnZXN0"
        )
        assert verify_password(password, exorbitant_hash) is False

    def test_maxmem_enforcement(self) -> None:
        """
        Asserts that requests exceeding the defined maxmem threshold safely raise
        resource exhaustion errors rather than crashing the worker or locking up system RAM.
        """
        # ln=20, r=16, p=1 results in maxmem > OPENSSL_MAX_MEMORY (2^31 - 1)
        expected_mem = 128 * 16 * ((1 << 20) + 1 + 2) + (1 << 20)
        assert expected_mem > OPENSSL_MAX_MEMORY

        with pytest.raises(ValueError, match="combined is more than OpenSSL allows"):
            _validate_params(
                salt_length=32,
                ln=20,
                r=16,
                p=1,
                hash_length=32,
            )

        # Verification of a hash exceeding maxmem must safely return False
        high_mem_hash = (
            "$scrypt$ln=20,r=16,p=1$c2FsdHNhbHQxMjM0c2FsdA$ZGlnZXN0MTIzNGRpZ2VzdA"
        )
        assert verify_password("test_pwd", high_mem_hash) is False


class TestInputSanitizationAndEdgeCases:
    """Category 4: Input Sanitization & Edge Cases."""

    @pytest.mark.parametrize(
        "empty_or_null",
        [
            "",
            " ",
            "   ",
            "\t",
            "\n",
            "\r\n",
            "\u00a0",  # non-breaking space
            "\u3000",  # ideographic space
        ],
    )
    def test_empty_or_null_inputs(self, empty_or_null) -> None:
        """
        Verifies that empty strings, whitespace-only strings, or None inputs
        are handled securely without unhandled exceptions.
        """
        # Empty and whitespace passwords must raise ValueError on hashing
        with pytest.raises(
            ValueError, match="found an empty string in plain_text_password"
        ):
            hash_password(empty_or_null, ln=10, r=4, p=1)

        # None or non-string passwords must raise TypeError on hashing
        with pytest.raises(
            TypeError, match="expected type str from plain_text_password"
        ):
            hash_password(None, ln=10, r=4, p=1)  # type: ignore[arg-type]

        # In verify_password, empty, whitespace, and None passwords must return False without crashing
        valid_hash = hash_password("valid-password", ln=10, r=4, p=1)
        assert verify_password(empty_or_null, valid_hash) is False
        assert verify_password(None, valid_hash) is False  # type: ignore[arg-type]

        # None or empty hash inputs must also safely return False
        assert verify_password("valid-password", None) is False  # type: ignore[arg-type]
        assert verify_password("valid-password", "") is False

    def test_unicode_and_multibyte_passwords(self) -> None:
        """
        Tests proper UTF-8 encoding handling for international characters, emojis,
        and null-byte injection attempts.
        """
        # 1. Complex multibyte international characters and emojis
        multilingual_pwd = "Pässwörd-пароль-パスワード-كلمةالسر-🔐🛡️🔑"
        hashed = hash_password(multilingual_pwd, ln=10, r=4, p=1)
        assert verify_password(multilingual_pwd, hashed) is True
        assert verify_password("WrongPassword123!", hashed) is False

        # 2. Maximum length boundary with 4-byte astral characters (emojis)
        # 1024 characters * 4 bytes/char = 4096 bytes UTF-8
        emoji_1024 = "🚀" * MAX_PASSWORD_LENGTH
        hashed_emoji = hash_password(emoji_1024, ln=10, r=4, p=1)
        assert verify_password(emoji_1024, hashed_emoji) is True

        # Exceeding MAX_PASSWORD_LENGTH by 1 character must raise ValueError
        with pytest.raises(ValueError, match="password is too long"):
            hash_password(emoji_1024 + "🚀", ln=10, r=4, p=1)

        # 3. Null-byte injection resistance (prevent C-string null termination truncation)
        prefix = "admin_password"
        injected = "admin_password\x00suffix_injection"
        h_prefix = hash_password(prefix, ln=10, r=4, p=1)
        h_injected = hash_password(injected, ln=10, r=4, p=1)

        assert verify_password(prefix, h_prefix) is True
        assert verify_password(injected, h_injected) is True
        # Cross-verification must strictly fail
        assert verify_password(prefix, h_injected) is False
        assert verify_password(injected, h_prefix) is False


class TestRobustnessAndMalformedDataParsing:
    """Category 5: Robustness & Malformed Data Parsing."""

    @pytest.mark.parametrize(
        "malformed_hash",
        [
            "",
            "not-a-valid-hash",
            "scrypt$ln=10,r=4,p=1$c2FsdA$ZGlnZXN0",  # missing leading $
            "$scrypt$ln=10,r=4$c2FsdA$ZGlnZXN0",  # missing p parameter
            "$scrypt$ln=10,r=4,p=1$c2FsdA",  # missing digest
            "$scrypt$ln=10,r=4,p=1$c2FsdA$ZGlnZXN0$extra",  # extra segment
            "$scrypt$ln=ten,r=4,p=1$c2FsdA$ZGlnZXN0",  # non-numeric ln
            "$scrypt$ln=10,r=4,p=1$invalid!base64$ZGlnZXN0",  # invalid base64 characters
            "$scrypt$ln=10,r=4,p=1$c2FsdA==$ZGlnZXN0",  # invalid padding in salt
            "$scrypt$ln=10,r=4,p=1$c2FsdA$ZGlnZXN0====",  # excess padding in digest
        ],
    )
    def test_malformed_hash_structure(self, malformed_hash: str) -> None:
        """
        Tests verification behavior against tampered hashes, missing delimiter sections,
        incorrect token counts, or invalid base64-encoded segments.
        """
        assert verify_password("test_password", malformed_hash) is False

    @pytest.mark.parametrize(
        "foreign_hash",
        [
            # Argon2id
            "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0",
            # Argon2i
            "$argon2i$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0",
            # Bcrypt ($2a$, $2b$, $2y$)
            "$2b$12$e8O0K9aGZ7Qx0v6vYd3gCeYFwP9YnF3fL7mXyW1kF5kO1x4q9d7Zy",
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
            # PBKDF2-HMAC-SHA256
            "$pbkdf2-sha256$i=10000$c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0",
            # SHA-512 crypt
            "$6$rounds=5000$usesomesillystri$k4yUkIOMThWDGoAkx6uKDREghqKHzOJFuUkxBngAmZs5v",
            # Unknown custom scheme
            "$customscheme$v=1$salt$hash",
        ],
    )
    def test_scheme_mismatch(self, foreign_hash: str) -> None:
        """
        Asserts that passing a hash from a different scheme (e.g., Argon2, bcrypt, PBKDF2)
        to the scrypt verification function fails securely without throwing unhandled exceptions.
        """
        assert verify_password("target_password_123", foreign_hash) is False

    def test_derived_key_length_mismatch(self) -> None:
        """
        Validates that unexpected derived key lengths (dklen) do not bypass authentication checks.
        """
        password = "test-dklen-mismatch-pwd"
        # Generate valid hash with standard 32-byte digest
        valid_hash = hash_password(password, hash_length=32, ln=10, r=4, p=1)
        salt, digest, params = _parse_hashed_password(valid_hash)
        assert len(digest) == 32
        assert verify_password(password, valid_hash) is True

        # 1. Truncate digest to sub-minimum dklen (< MIN_HASH_LENGTH 8 bytes)
        # An attacker attempts to pass a tiny digest (e.g. 1 or 4 bytes) to facilitate brute-forcing
        for tiny_len in (1, 4, 7):
            tiny_digest = digest[:tiny_len]
            hash_tiny = f"$scrypt$ln={params['ln']},r={params['r']},p={params['p']}${_encode(salt)}${_encode(tiny_digest)}"
            assert verify_password(password, hash_tiny) is False

        # 2. Extend digest beyond MAX_HASH_LENGTH (> 64 bytes)
        extended_70 = digest + digest + b"123456"
        assert len(extended_70) == 70
        hash_extended_70 = f"$scrypt$ln={params['ln']},r={params['r']},p={params['p']}${_encode(salt)}${_encode(extended_70)}"
        assert verify_password(password, hash_extended_70) is False

        # 3. Mismatched digests of various lengths (replacing with arbitrary bytes of lengths 4, 8, 16, 24, 48, 64, 72)
        # Authentication must never succeed
        for fake_len in (4, 8, 16, 24, 48, 64, 72):
            fake_digest = b"\xaa" * fake_len
            tampered_hash = f"$scrypt$ln={params['ln']},r={params['r']},p={params['p']}${_encode(salt)}${_encode(fake_digest)}"
            assert verify_password(password, tampered_hash) is False

        # 4. Wrong password verification attempts across all valid derived key lengths (8, 16, 24, 32, 64 bytes)
        for valid_len in (8, 16, 24, 32, 64):
            valid_len_hash = hash_password(
                password, hash_length=valid_len, ln=10, r=4, p=1
            )
            assert verify_password("wrong-password", valid_len_hash) is False

        # 5. Cross-hash mismatch: pairing salt from one run with a digest from a different run/length
        hash_alt = hash_password("other-pwd", hash_length=16, ln=10, r=4, p=1)
        salt_alt, _, _ = _parse_hashed_password(hash_alt)
        cross_hash = f"$scrypt$ln={params['ln']},r={params['r']},p={params['p']}${_encode(salt_alt)}${_encode(digest)}"
        assert verify_password(password, cross_hash) is False
