"""
Unit tests for easy_passwords.argon2.

Covers internal helper functions, parameter validation, defaults,
hash generation, and verification to achieve 100% line and branch coverage.
"""

import pytest

from easy_passwords.argon2 import (
    HASH_LENGTH,
    ITERATIONS,
    LANES,
    MAX_HASH_LENGTH,
    MAX_ITERATIONS,
    MAX_LANES,
    MAX_MEMORY_COST,
    MAX_PASSWORD_LENGTH,
    MAX_SALT_LENGTH,
    MEMORY_COST,
    MIN_HASH_LENGTH,
    MIN_ITERATIONS,
    MIN_LANES,
    MIN_MEMORY_COST,
    MIN_SALT_LENGTH,
    SALT_LENGTH,
    _validate_params,
    _validate_plain_text_password,
    hash_password,
    verify_password,
)


class TestConstantsAndDefaults:
    """Verify default configurations comply with RFC 9106 and OWASP recommendations."""

    def test_default_constants(self) -> None:
        assert SALT_LENGTH == 32
        assert HASH_LENGTH == 32
        assert ITERATIONS == 2
        assert LANES == 1
        assert MEMORY_COST == 19456
        assert MAX_PASSWORD_LENGTH == 1024

    def test_boundary_constants(self) -> None:
        assert MIN_SALT_LENGTH == 16
        assert MAX_SALT_LENGTH == 64
        assert MIN_ITERATIONS == 2
        assert MAX_ITERATIONS == 100
        assert MIN_LANES == 1
        assert MAX_LANES == 64
        assert MIN_MEMORY_COST == 19456
        assert MAX_MEMORY_COST == 2097152
        assert MIN_HASH_LENGTH == 16
        assert MAX_HASH_LENGTH == 64


class TestValidatePlainTextPassword:
    """Tests password input type and constraint validation."""

    def test_valid_passwords(self) -> None:
        _validate_plain_text_password("valid_password")
        _validate_plain_text_password("a" * MAX_PASSWORD_LENGTH)

    @pytest.mark.parametrize(
        "invalid_password",
        [123, None, ["password"], b"password", {"pass": "word"}, True],
    )
    def test_invalid_type_raises_type_error(self, invalid_password) -> None:
        with pytest.raises(
            TypeError, match="expected type str from plain_text_password"
        ):
            _validate_plain_text_password(invalid_password)

    @pytest.mark.parametrize("empty_password", ["", "   ", "\t\n  "])
    def test_empty_or_whitespace_raises_value_error(self, empty_password: str) -> None:
        with pytest.raises(
            ValueError, match="found an empty string in plain_text_password"
        ):
            _validate_plain_text_password(empty_password)

    def test_password_exceeding_max_length_raises_value_error(self) -> None:
        too_long = "a" * (MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(
            ValueError, match=f"password is too long. max allowed length: {MAX_PASSWORD_LENGTH}"
        ):
            _validate_plain_text_password(too_long)


class TestValidateParams:
    """Tests parameter boundary and type validations."""

    def test_valid_params(self) -> None:
        _validate_params(
            salt_length=32,
            hash_length=32,
            iterations=2,
            lanes=1,
            memory_cost=19456,
        )

    @pytest.mark.parametrize(
        "param_name, invalid_val",
        [
            ("salt_length", "32"),
            ("salt_length", True),
            ("hash_length", 32.5),
            ("hash_length", False),
            ("iterations", None),
            ("lanes", [1]),
            ("memory_cost", "19456"),
        ],
    )
    def test_parameter_type_errors(self, param_name: str, invalid_val) -> None:
        params = {
            "salt_length": 32,
            "hash_length": 32,
            "iterations": 2,
            "lanes": 1,
            "memory_cost": 19456,
        }
        params[param_name] = invalid_val
        with pytest.raises(TypeError, match=f"expected type int from {param_name}"):
            _validate_params(**params)

    @pytest.mark.parametrize(
        "salt_length",
        [MIN_SALT_LENGTH - 1, 0, -1, MAX_SALT_LENGTH + 1],
    )
    def test_salt_length_boundaries(self, salt_length: int) -> None:
        with pytest.raises(
            ValueError,
            match=f"salt_length must be between {MIN_SALT_LENGTH} and {MAX_SALT_LENGTH}",
        ):
            _validate_params(
                salt_length=salt_length,
                hash_length=32,
                iterations=2,
                lanes=1,
                memory_cost=19456,
            )

    @pytest.mark.parametrize(
        "hash_length",
        [MIN_HASH_LENGTH - 1, 0, -1, MAX_HASH_LENGTH + 1],
    )
    def test_hash_length_boundaries(self, hash_length: int) -> None:
        with pytest.raises(
            ValueError,
            match=f"hash_length must be between {MIN_HASH_LENGTH} and {MAX_HASH_LENGTH}",
        ):
            _validate_params(
                salt_length=32,
                hash_length=hash_length,
                iterations=2,
                lanes=1,
                memory_cost=19456,
            )

    @pytest.mark.parametrize(
        "iterations",
        [MIN_ITERATIONS - 1, 0, -1, MAX_ITERATIONS + 1],
    )
    def test_iterations_boundaries(self, iterations: int) -> None:
        with pytest.raises(
            ValueError,
            match=f"iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}",
        ):
            _validate_params(
                salt_length=32,
                hash_length=32,
                iterations=iterations,
                lanes=1,
                memory_cost=19456,
            )

    @pytest.mark.parametrize(
        "lanes",
        [MIN_LANES - 1, 0, -1, MAX_LANES + 1],
    )
    def test_lanes_boundaries(self, lanes: int) -> None:
        with pytest.raises(
            ValueError, match=f"lanes must be between {MIN_LANES} and {MAX_LANES}"
        ):
            _validate_params(
                salt_length=32,
                hash_length=32,
                iterations=2,
                lanes=lanes,
                memory_cost=19456,
            )

    @pytest.mark.parametrize(
        "memory_cost",
        [MIN_MEMORY_COST - 1, 0, -1, MAX_MEMORY_COST + 1],
    )
    def test_memory_cost_boundaries(self, memory_cost: int) -> None:
        with pytest.raises(
            ValueError,
            match=f"memory_cost must be between {MIN_MEMORY_COST} and {MAX_MEMORY_COST} KiB",
        ):
            _validate_params(
                salt_length=32,
                hash_length=32,
                iterations=2,
                lanes=1,
                memory_cost=memory_cost,
            )



class TestHashPassword:
    """Tests password hashing functionality."""

    def test_hash_password_default(self) -> None:
        phc = hash_password("my_secure_password")
        assert phc.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
        assert len(phc.split("$")) == 6

    def test_hash_password_custom_parameters(self) -> None:
        phc = hash_password(
            "custom_params_pass",
            salt_length=16,
            hash_length=24,
            iterations=3,
            lanes=2,
            memory_cost=20000,
        )
        assert phc.startswith("$argon2id$v=19$m=20000,t=3,p=2$")

    def test_hash_password_unique_salts(self) -> None:
        phc1 = hash_password("same_password")
        phc2 = hash_password("same_password")
        assert phc1 != phc2


class TestVerifyPassword:
    """Tests password verification functionality."""

    def test_verify_password_success(self) -> None:
        pwd = "correct_horse_battery_staple"
        phc = hash_password(pwd)
        assert verify_password(pwd, phc) is True

    def test_verify_password_mismatch(self) -> None:
        pwd = "correct_password"
        wrong_pwd = "wrong_password"
        phc = hash_password(pwd)
        assert verify_password(wrong_pwd, phc) is False

    @pytest.mark.parametrize(
        "invalid_password",
        [123, None, "", "   ", "a" * (MAX_PASSWORD_LENGTH + 1)],
    )
    def test_verify_password_invalid_password_input(self, invalid_password) -> None:
        phc = hash_password("sample_password")
        assert verify_password(invalid_password, phc) is False

    @pytest.mark.parametrize(
        "invalid_phc",
        [123, None, ["hash"], b"$argon2id$", {}],
    )
    def test_verify_password_invalid_phc_type(self, invalid_phc) -> None:
        assert verify_password("sample_password", invalid_phc) is False

    def test_verify_password_corrupted_phc(self) -> None:
        phc = hash_password("sample_password")
        # Corrupt salt/hash parts
        corrupted_phc = phc[:-5] + "XXXXX"
        assert verify_password("sample_password", corrupted_phc) is False
