"""
Module: easy_passwords.scrypt

Description:
    - Implements Scrypt to hash a password
    - Outputs a password in PHC string format
    - parameter validation enabled
    - OWASP recommended defaults
"""

import base64
import re
import secrets

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Parameters
SALT_LENGTH: int = 32
LOG2_N: int = 17
BLOCK_SIZE: int = 8
PARALLELISM: int = 1
HASH_LENGTH: int = 32

# Constraints & Limits
MAX_PASSWORD_LENGTH: int = 1024
MIN_SALT_LENGTH: int = 8
MAX_SALT_LENGTH: int = 64
MIN_LOG2_N: int = 10
MAX_LOG2_N: int = 20
MIN_R: int = 4
MAX_R: int = 16
MIN_P: int = 1
MAX_P: int = 4
MIN_HASH_LENGTH: int = 8
MAX_HASH_LENGTH: int = 64
OPENSSL_MAX_MEMORY: int = (1 << 31) - 1

# Regex
PHC_REGEX: str = (
    r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$"
)


def _encode(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _decode(data: str) -> bytes:
    return base64.b64decode(data + "=" * (-len(data) % 4), validate=True)


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
    *, salt_length: int, ln: int, r: int, p: int, hash_length: int
) -> None:
    if not (MIN_SALT_LENGTH <= salt_length <= MAX_SALT_LENGTH):
        raise ValueError(
            f"salt_length should be within [{MIN_SALT_LENGTH}, {MAX_SALT_LENGTH}]. Found: {salt_length}"
        )

    if not (MIN_LOG2_N <= ln <= MAX_LOG2_N):
        raise ValueError(
            f"ln should be within [{MIN_LOG2_N}, {MAX_LOG2_N}]. Found: {ln}"
        )

    if not (MIN_R <= r <= MAX_R):
        raise ValueError(f"r should be within [{MIN_R}, {MAX_R}]. Found: {r}")

    if not (MIN_P <= p <= MAX_P):
        raise ValueError(f"p should be within [{MIN_P}, {MAX_P}]. Found: {p}")

    if not (MIN_HASH_LENGTH <= hash_length <= MAX_HASH_LENGTH):
        raise ValueError(
            f"dklen should be within [{MIN_HASH_LENGTH}, {MAX_HASH_LENGTH}]. Found: {hash_length}"
        )

    # compute maxmem
    maxmem: int = 128 * r * ((1 << ln) + p + 2) + (1 << 20)

    if maxmem > OPENSSL_MAX_MEMORY:
        raise ValueError(f"ln={ln},r={p},p={p} combined is more than OpenSSL allows")


def _parse_hashed_password(hashed_password: str):
    matched = re.match(PHC_REGEX, hashed_password)
    if not matched:
        raise ValueError("invalid phc hash format")

    ln, r, p, b64_salt, b64_digest = matched.groups()

    return (
        _decode(b64_salt),
        _decode(b64_digest),
        {"ln": int(ln), "r": int(r), "p": int(p)},
    )


def hash_password(
    plain_text_password: str,
    *,
    salt_length: int = SALT_LENGTH,
    hash_length: int = HASH_LENGTH,
    ln: int = LOG2_N,
    r: int = BLOCK_SIZE,
    p: int = PARALLELISM,
) -> str:
    """
    Hashes a plain_text_password using Scrypt algorithm.
    DON'T CHANGE DEFAULT SETTINGS unless needed.

    Args:
        - plain_text_password (str) : password to hash
        - salt_length (int) Size of salt in bytes
        - ln (int) : Log2 of Compute + memory cost
        - r (int) : Block Size
        - p (int) : Parallelism factor
        - dklen (int) : Size of the hash in bytes

    Returns:
        - PHC string: $scrypt$ln=l,r=r,p=p$<salt>$<hash>
    """
    # validation
    _validate_plain_text_password(plain_text_password)
    _validate_params(salt_length=salt_length, hash_length=hash_length, ln=ln, r=r, p=p)

    # generate the salt
    salt: bytes = secrets.token_bytes(salt_length)

    # hashing
    hasher = Scrypt(salt, n=(1 << ln), r=r, p=p, length=hash_length)
    digest: bytes = hasher.derive(plain_text_password.encode("utf-8"))

    # convert to PHC
    return f"$scrypt$ln={ln},r={r},p={p}${_encode(salt)}${_encode(digest)}"


def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """
    Matches a plain text password with a hashed password

    Args:
        - plain_text_password (str) : Plain Text Password
        - hashed_password (str) : PHC string hashed password

    Returns:
        - bool : Whether the hash matches the password
    """
    try:
        _validate_plain_text_password(plain_text_password)

        salt, digest, params = _parse_hashed_password(hashed_password)

        # extract params
        ln = params["ln"]
        r = params["r"]
        p = params["p"]

        # validate params
        _validate_params(
            salt_length=len(salt), hash_length=len(digest), ln=ln, r=r, p=p
        )

        # generate hash
        hasher = Scrypt(salt=salt, length=len(digest), n=(1 << ln), r=r, p=p)
        hasher.verify(plain_text_password.encode("utf-8"), digest)

    except Exception:
        return False

    return True
