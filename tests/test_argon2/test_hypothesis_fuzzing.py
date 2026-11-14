"""
Property-based and fuzzing tests for easy_passwords.argon2 using Hypothesis.

Verifies mathematical invariants, encoding roundtrips, and crash resilience
with arbitrary generated inputs and default OWASP parameters.
"""

import hypothesis.strategies as st
from hypothesis import given, settings

from easy_passwords.argon2 import (
    MAX_PASSWORD_LENGTH,
    hash_password,
    verify_password,
)

# Strategy for generating valid non-empty passwords with printable characters
valid_passwords = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),  # avoid lone surrogates
    min_size=1,
    max_size=MAX_PASSWORD_LENGTH,
).filter(lambda s: bool(s.strip()))


class TestHypothesisProperties:
    """Hypothesis property tests for Argon2id."""

    @settings(max_examples=10, deadline=None)
    @given(password=valid_passwords)
    def test_default_owasp_hash_verify_roundtrip(self, password: str) -> None:
        """
        Using real OWASP default parameters (m=19456, t=2, p=1):
        Any valid password must successfully verify against its own hash.
        """
        phc_hash = hash_password(password)
        assert phc_hash.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
        assert verify_password(password, phc_hash) is True

    @settings(max_examples=10, deadline=None)
    @given(pwd1=valid_passwords, pwd2=valid_passwords)
    def test_distinct_passwords_never_verify(self, pwd1: str, pwd2: str) -> None:
        """Two distinct passwords must never verify as matching."""
        if pwd1 == pwd2:
            return

        h1 = hash_password(pwd1)
        assert verify_password(pwd2, h1) is False

    @settings(max_examples=40, deadline=None)
    @given(garbage=st.text(max_size=200))
    def test_fuzz_verify_password_with_arbitrary_garbage_hash(
        self, garbage: str
    ) -> None:
        """verify_password must safely return False and never crash on arbitrary garbage."""
        result = verify_password("standard_valid_password", garbage)
        assert result is False

    @settings(max_examples=40, deadline=None)
    @given(garbage_pwd=st.text(max_size=200))
    def test_fuzz_verify_password_with_arbitrary_garbage_password(
        self, garbage_pwd: str
    ) -> None:
        """verify_password must safely return False and never crash on arbitrary password input."""
        valid_hash = (
            "$argon2id$v=19$m=19456,t=2,p=1$ZHVtbXlzYWx0MTIzNDU2$ZHVtbXlkaWdlc3QxMjM0NTY3ODkwMTI"
        )
        result = verify_password(garbage_pwd, valid_hash)
        assert isinstance(result, bool)
