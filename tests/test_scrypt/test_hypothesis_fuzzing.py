"""
Property-based and fuzzing tests for easy_passwords.scrypt using Hypothesis.

Verifies mathematical invariants, encoding roundtrips, and crash resilience
with arbitrary generated inputs and default OWASP parameters.
"""

import re

import hypothesis.strategies as st
from hypothesis import given, settings

from easy_passwords.scrypt import (
    MAX_PASSWORD_LENGTH,
    PHC_REGEX,
    _decode,
    _encode,
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
    """Hypothesis property tests."""

    @given(data=st.binary(min_size=0, max_size=512))
    def test_encode_decode_invariant(self, data: bytes) -> None:
        """Any arbitrary byte string must roundtrip perfectly through _encode and _decode."""
        assert _decode(_encode(data)) == data

    @settings(max_examples=15, deadline=None)
    @given(password=valid_passwords)
    def test_default_owasp_hash_verify_roundtrip(self, password: str) -> None:
        """
        Using real OWASP default parameters (ln=17, r=8, p=1):
        Any valid password must successfully verify against its own hash.
        """
        phc_hash = hash_password(password)
        assert phc_hash.startswith("$scrypt$ln=17,r=8,p=1$")
        assert re.match(PHC_REGEX, phc_hash) is not None
        assert verify_password(password, phc_hash) is True

    @settings(max_examples=15, deadline=None)
    @given(pwd1=valid_passwords, pwd2=valid_passwords)
    def test_distinct_passwords_never_verify(self, pwd1: str, pwd2: str) -> None:
        """Two distinct passwords must never verify as matching."""
        if pwd1 == pwd2:
            return

        # Use fast parameters for pairwise differential checks to avoid compounding runtimes
        h1 = hash_password(pwd1, ln=10, r=4, p=1)
        assert verify_password(pwd2, h1) is False

    @settings(max_examples=50, deadline=None)
    @given(garbage=st.text(max_size=200))
    def test_fuzz_verify_password_with_arbitrary_garbage_hash(
        self, garbage: str
    ) -> None:
        """verify_password must safely return False and never crash on arbitrary garbage."""
        result = verify_password("standard_valid_password", garbage)
        assert result is False

    @settings(max_examples=50, deadline=None)
    @given(garbage_pwd=st.text(max_size=200))
    def test_fuzz_verify_password_with_arbitrary_garbage_password(
        self, garbage_pwd: str
    ) -> None:
        """verify_password must safely return False and never crash on arbitrary password input."""
        valid_hash = (
            "$scrypt$ln=10,r=4,p=1$dGVzdHNhbHQxMjM0$dGVzdGRpZ2VzdDEyMzR0ZXN0ZGlnZXN0"
        )
        result = verify_password(garbage_pwd, valid_hash)
        assert isinstance(result, bool)
