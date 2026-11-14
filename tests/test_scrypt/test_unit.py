"""
Unit tests for easy_passwords.scrypt.

Covers internal helper functions, parameter validation, PHC formatting,
hash generation, and verification to achieve 100% line and branch coverage.
"""

import binascii
import re

import pytest

from easy_passwords.scrypt import (
    BLOCK_SIZE,
    HASH_LENGTH,
    LOG2_N,
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
    PARALLELISM,
    PHC_REGEX,
    SALT_LENGTH,
    _decode,
    _encode,
    _parse_hashed_password,
    _validate_params,
    _validate_plain_text_password,
    hash_password,
    verify_password,
)


class TestBase64Helpers:
    """Tests for _encode and _decode functions."""

    @pytest.mark.parametrize(
        "raw_bytes",
        [
            b"",
            b"a",
            b"ab",
            b"abc",
            b"hello world",
            b"\x00\xff\xfe\x01" * 8,
        ],
    )
    def test_encode_decode_roundtrip(self, raw_bytes: bytes) -> None:
        encoded = _encode(raw_bytes)
        assert "=" not in encoded
        assert _decode(encoded) == raw_bytes

    def test_decode_with_explicit_padding(self) -> None:
        # A payload whose standard base64 representation ends with padding
        raw = b"scrypt1"
        encoded = _encode(raw)  # stripped of padding, length is 10
        assert len(encoded) % 4 != 0
        # Passing canonical standard padding ('==') decodes properly
        assert _decode(encoded + "==") == raw
        # Passing partial padding ('=') will have another '=' added by _decode and also decodes properly
        assert _decode(encoded + "=") == raw

    def test_decode_invalid_padding_raises(self) -> None:
        # A payload whose base64 length is already a multiple of 4 (needs 0 padding)
        raw = b"scrypt"
        encoded = _encode(raw)  # length is 8
        assert len(encoded) % 4 == 0
        # Appending '=' creates length 9; _decode appends 3 more '=', producing '====' excess padding
        with pytest.raises(binascii.Error, match="Excess padding not allowed"):
            _decode(encoded + "=")

    def test_decode_invalid_base64_raises(self) -> None:
        with pytest.raises(binascii.Error):
            _decode("!@#$%^&*()")


class TestPasswordValidation:
    """Tests for _validate_plain_text_password."""

    @pytest.mark.parametrize(
        "invalid_type",
        [
            None,
            12345,
            12.34,
            b"byte_password",
            ["list_password"],
            {"password": "test"},
        ],
    )
    def test_rejects_non_string_password(self, invalid_type) -> None:
        with pytest.raises(
            TypeError, match="expected type str from plain_text_password"
        ):
            _validate_plain_text_password(invalid_type)

    @pytest.mark.parametrize(
        "empty_or_whitespace",
        [
            "",
            " ",
            "    ",
            "\t",
            "\n",
            "\r\n",
            "  \t\n  ",
        ],
    )
    def test_rejects_empty_or_whitespace_only_password(
        self, empty_or_whitespace: str
    ) -> None:
        with pytest.raises(
            ValueError, match="found an empty string in plain_text_password"
        ):
            _validate_plain_text_password(empty_or_whitespace)

    def test_rejects_password_exceeding_max_length(self) -> None:
        long_password = "a" * (MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(
            ValueError,
            match=f"password is too long. max allowed length: {MAX_PASSWORD_LENGTH}",
        ):
            _validate_plain_text_password(long_password)

    def test_accepts_valid_boundary_passwords(self) -> None:
        # Minimum valid length (1 character)
        _validate_plain_text_password("a")
        # Maximum allowed length
        _validate_plain_text_password("a" * MAX_PASSWORD_LENGTH)
        # Complex characters
        _validate_plain_text_password("CorrectHorseBatteryStaple!@#$123\u2764")


class TestParamValidation:
    """Tests for _validate_params."""

    @pytest.mark.parametrize(
        ("salt_length", "ln", "r", "p", "hash_length"),
        [
            (MIN_SALT_LENGTH, MIN_LOG2_N, MIN_R, MIN_P, MIN_HASH_LENGTH),
            (MAX_SALT_LENGTH, 14, MAX_R, MAX_P, MAX_HASH_LENGTH),
            (SALT_LENGTH, LOG2_N, BLOCK_SIZE, PARALLELISM, HASH_LENGTH),
        ],
    )
    def test_valid_parameters(
        self, salt_length: int, ln: int, r: int, p: int, hash_length: int
    ) -> None:
        # Should not raise
        _validate_params(
            salt_length=salt_length,
            ln=ln,
            r=r,
            p=p,
            hash_length=hash_length,
        )

    def test_salt_length_out_of_bounds(self) -> None:
        with pytest.raises(ValueError, match="salt_length should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH - 1,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )
        with pytest.raises(ValueError, match="salt_length should be within"):
            _validate_params(
                salt_length=MAX_SALT_LENGTH + 1,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )

    def test_ln_out_of_bounds(self) -> None:
        with pytest.raises(ValueError, match="ln should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N - 1,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )
        with pytest.raises(ValueError, match="ln should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MAX_LOG2_N + 1,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )

    def test_r_out_of_bounds(self) -> None:
        with pytest.raises(ValueError, match="r should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R - 1,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )
        with pytest.raises(ValueError, match="r should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MAX_R + 1,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH,
            )

    def test_p_out_of_bounds(self) -> None:
        with pytest.raises(ValueError, match="p should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P - 1,
                hash_length=MIN_HASH_LENGTH,
            )
        with pytest.raises(ValueError, match="p should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MAX_P + 1,
                hash_length=MIN_HASH_LENGTH,
            )

    def test_hash_length_out_of_bounds(self) -> None:
        with pytest.raises(ValueError, match="dklen should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MIN_HASH_LENGTH - 1,
            )
        with pytest.raises(ValueError, match="dklen should be within"):
            _validate_params(
                salt_length=MIN_SALT_LENGTH,
                ln=MIN_LOG2_N,
                r=MIN_R,
                p=MIN_P,
                hash_length=MAX_HASH_LENGTH + 1,
            )

    def test_openssl_max_memory_exceeded(self) -> None:
        # ln=20, r=16, p=1 results in maxmem > OPENSSL_MAX_MEMORY
        calculated_mem = 128 * 16 * ((1 << 20) + 1 + 2) + (1 << 20)
        assert calculated_mem > OPENSSL_MAX_MEMORY

        with pytest.raises(ValueError, match="combined is more than OpenSSL allows"):
            _validate_params(
                salt_length=32,
                ln=20,
                r=16,
                p=1,
                hash_length=32,
            )


class TestPHCParsing:
    """Tests for _parse_hashed_password."""

    def test_parse_valid_phc_hash(self) -> None:
        salt_bytes = b"salt1234salt1234"
        digest_bytes = b"digest1234digest1234"
        phc = f"$scrypt$ln=14,r=8,p=1${_encode(salt_bytes)}${_encode(digest_bytes)}"

        parsed_salt, parsed_digest, params = _parse_hashed_password(phc)
        assert parsed_salt == salt_bytes
        assert parsed_digest == digest_bytes
        assert params == {"ln": 14, "r": 8, "p": 1}

    @pytest.mark.parametrize(
        "invalid_hash",
        [
            "",
            "plain_text",
            "$argon2id$v=19$m=65536,t=2,p=1$salt$hash",
            "$scrypt$ln=14,r=8$salt$hash",
            "$scrypt$ln=14,r=8,p=1$salt",
            "$scrypt$ln=14,r=8,p=1$salt$digest$extra",
            "scrypt$ln=14,r=8,p=1$salt$digest",
            "$scrypt$ln=foo,r=8,p=1$salt$digest",
            "$scrypt$ln=-14,r=8,p=1$salt$digest",
        ],
    )
    def test_parse_invalid_phc_hash_raises_value_error(self, invalid_hash: str) -> None:
        with pytest.raises(ValueError, match="invalid phc hash format"):
            _parse_hashed_password(invalid_hash)


class TestHashAndVerifyPassword:
    """Tests for hash_password and verify_password."""

    def test_hash_password_default_params(self) -> None:
        password = "super-secret-password-123"
        hashed = hash_password(password)

        assert hashed.startswith("$scrypt$ln=17,r=8,p=1$")
        assert re.match(PHC_REGEX, hashed)
        assert verify_password(password, hashed) is True

    def test_hash_password_custom_parameters(self) -> None:
        password = "custom-param-password"
        hashed = hash_password(
            password,
            salt_length=16,
            hash_length=24,
            ln=10,
            r=4,
            p=1,
        )

        assert hashed.startswith("$scrypt$ln=10,r=4,p=1$")
        salt, digest, params = _parse_hashed_password(hashed)
        assert len(salt) == 16
        assert len(digest) == 24
        assert params == {"ln": 10, "r": 4, "p": 1}
        assert verify_password(password, hashed) is True

    def test_hash_uniqueness(self) -> None:
        password = "identical-password"
        hash1 = hash_password(password, ln=10, r=4, p=1)
        hash2 = hash_password(password, ln=10, r=4, p=1)

        assert hash1 != hash2
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True

    def test_verify_password_wrong_password_returns_false(self) -> None:
        hashed = hash_password("correct_password", ln=10, r=4, p=1)
        assert verify_password("wrong_password", hashed) is False

    @pytest.mark.parametrize(
        "invalid_password",
        [
            "",
            "   ",
            None,
            12345,
            "a" * (MAX_PASSWORD_LENGTH + 1),
        ],
    )
    def test_verify_password_invalid_plain_text_returns_false(
        self, invalid_password
    ) -> None:
        valid_hash = hash_password("valid_password", ln=10, r=4, p=1)
        assert verify_password(invalid_password, valid_hash) is False

    @pytest.mark.parametrize(
        "corrupted_hash",
        [
            "",
            "not-a-hash",
            "$scrypt$ln=9,r=8,p=1$c2FsdHNhbHQ=$ZGlnZXN0ZGlnZXN0",  # ln=9 is below MIN_LOG2_N
            "$scrypt$ln=21,r=8,p=1$c2FsdHNhbHQ=$ZGlnZXN0ZGlnZXN0",  # ln=21 is above MAX_LOG2_N
            "$scrypt$ln=10,r=3,p=1$c2FsdHNhbHQ=$ZGlnZXN0ZGlnZXN0",  # r=3 is below MIN_R
            "$scrypt$ln=10,r=8,p=0$c2FsdHNhbHQ=$ZGlnZXN0ZGlnZXN0",  # p=0 is below MIN_P
            "$scrypt$ln=10,r=8,p=1$dG9vc2hvcnQ=$ZGlnZXN0ZGlnZXN0",  # salt < 8 bytes
            "$scrypt$ln=20,r=16,p=1$c2FsdHNhbHQxMjM0c2FsdA==$ZGlnZXN0MTIzNGRpZ2VzdA==",  # exceeds maxmem
            "$scrypt$ln=10,r=8,p=1$invalid!!!base64$ZGlnZXN0ZGlnZXN0",
        ],
    )
    def test_verify_password_malformed_hash_returns_false(
        self, corrupted_hash: str
    ) -> None:
        assert verify_password("any_password", corrupted_hash) is False
