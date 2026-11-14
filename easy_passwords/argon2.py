"""
Module: easy_passwords.argon2

Description:
    - Implements Argon2id to hash a password
    - Outputs a password in PHC string format
    - Parameter validation enabled (RFC 9106 / OWASP recommended defaults)
"""

import secrets

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Parameters
SALT_LENGTH: int = 32
HASH_LENGTH: int = 32
ITERATIONS: int = 2
LANES: int = 1
MEMORY_COST: int = 19456  # 19 MiB in KiB

# Constraints & Limits
MAX_PASSWORD_LENGTH: int = 1024
MIN_SALT_LENGTH: int = 16  # RFC 9106 recommended minimum
MAX_SALT_LENGTH: int = 64
MIN_ITERATIONS: int = 2  # RFC 9106 / OWASP recommended minimum
MAX_ITERATIONS: int = 100
MIN_LANES: int = 1
MAX_LANES: int = 64
MIN_MEMORY_COST: int = 19456  # 19 MiB (RFC 9106 / OWASP minimum)
MAX_MEMORY_COST: int = 2097152  # 2 GiB in KiB (DoS protection)
MIN_HASH_LENGTH: int = 16
MAX_HASH_LENGTH: int = 64


def _validate_plain_text_password(plain_text_password: str) -> None:
    if not isinstance(plain_text_password, str):
        raise TypeError("expected type str from plain_text_password")
    if not plain_text_password.strip():
        raise ValueError("found an empty string in plain_text_password")
    if len(plain_text_password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"password is too long. max allowed length: {MAX_PASSWORD_LENGTH}"
        )


def _validate_params(
    *,
    salt_length: int,
    hash_length: int,
    iterations: int,
    lanes: int,
    memory_cost: int,
) -> None:
    for name, val in [
        ("salt_length", salt_length),
        ("hash_length", hash_length),
        ("iterations", iterations),
        ("lanes", lanes),
        ("memory_cost", memory_cost),
    ]:
        if not isinstance(val, int) or isinstance(val, bool):
            raise TypeError(f"expected type int from {name}")

    if not (MIN_SALT_LENGTH <= salt_length <= MAX_SALT_LENGTH):
        raise ValueError(
            f"salt_length must be between {MIN_SALT_LENGTH} and {MAX_SALT_LENGTH}"
        )

    if not (MIN_HASH_LENGTH <= hash_length <= MAX_HASH_LENGTH):
        raise ValueError(
            f"hash_length must be between {MIN_HASH_LENGTH} and {MAX_HASH_LENGTH}"
        )

    if not (MIN_ITERATIONS <= iterations <= MAX_ITERATIONS):
        raise ValueError(
            f"iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}"
        )

    if not (MIN_LANES <= lanes <= MAX_LANES):
        raise ValueError(f"lanes must be between {MIN_LANES} and {MAX_LANES}")

    if not (MIN_MEMORY_COST <= memory_cost <= MAX_MEMORY_COST):
        raise ValueError(
            f"memory_cost must be between {MIN_MEMORY_COST} and {MAX_MEMORY_COST} KiB"
        )


def hash_password(
    plain_text_password: str,
    *,
    salt_length: int = SALT_LENGTH,
    hash_length: int = HASH_LENGTH,
    iterations: int = ITERATIONS,
    lanes: int = LANES,
    memory_cost: int = MEMORY_COST,
) -> str:
    """
    Hashes a plain_text_password using Argon2id algorithm.
    Enforces RFC 9106 / OWASP recommended defaults and parameter limits.

    Args:
        plain_text_password (str): Password to hash.
        salt_length (int): Size of salt in bytes (>= 16).
        hash_length (int): Size of hash digest in bytes (>= 16).
        iterations (int): Time cost / number of iterations (>= 2).
        lanes (int): Parallelism / number of lanes (>= 1).
        memory_cost (int): Memory cost in KiB (>= 19456 KiB).

    Returns:
        str: PHC-encoded password hash string.
    """
    _validate_plain_text_password(plain_text_password)
    _validate_params(
        salt_length=salt_length,
        hash_length=hash_length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )

    salt: bytes = secrets.token_bytes(salt_length)

    hasher = Argon2id(
        salt=salt,
        length=hash_length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return hasher.derive_phc_encoded(plain_text_password.encode("utf-8"))


def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """
    Matches a plain text password with an Argon2id PHC-encoded hashed password.

    Args:
        plain_text_password (str): Plain text password.
        hashed_password (str): PHC string hashed password.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    try:
        _validate_plain_text_password(plain_text_password)
        if not isinstance(hashed_password, str):
            raise TypeError("expected type str from hashed_password")

        _ = Argon2id.verify_phc_encoded(
            plain_text_password.encode("utf-8"), hashed_password
        )
        return True
    except (InvalidKey, TypeError, ValueError, Exception):  # noqa: BLE001
        return False
