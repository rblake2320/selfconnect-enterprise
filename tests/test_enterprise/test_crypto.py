"""tests/test_enterprise/test_crypto.py — Integration tests for enterprise.crypto

On Windows without the portable override, these tests call BCrypt/NCrypt. Other
environments exercise the explicitly identified portable test backend. Each
test creates a unique key name and deletes it in teardown.

SHA-384 test vectors from NIST FIPS 180-4 / NIST CAVP:
    SHA-384("")  = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
"""
from __future__ import annotations

import uuid

import pytest
from enterprise.crypto import CNG_BACKEND_AVAILABLE, CRYPTO_BACKEND_ID

from enterprise.crypto import (


    ALGO_ID,
    P384_COORD_BYTES,
    P384_SIG_BYTES,
    SHA384_BYTES,
    CngSigner,
    cng_delete_key,
    cng_key_exists,
    cng_sha384,
    cng_verify,
)

pytestmark = pytest.mark.skipif(
    not CNG_BACKEND_AVAILABLE,
    reason='No ECDSA-P384 signing backend available (CNG or portable)'
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def key_name():
    """Unique NCrypt key name — auto-deleted after each test."""
    name = f"sc-test-{uuid.uuid4().hex[:12]}"
    yield name
    # Cleanup: remove key even if the test failed mid-way
    cng_delete_key(name)


@pytest.fixture
def signer(key_name):
    """CngSigner backed by a freshly created test key."""
    s = CngSigner.create(key_name)
    yield s
    s.close()


# ── SHA-384 ────────────────────────────────────────────────────────────────────

class TestSha384:
    def test_empty_string_produces_known_vector(self):
        result = cng_sha384(b"")
        expected = bytes.fromhex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b"
        )
        assert result == expected

    def test_output_is_48_bytes(self):
        assert len(cng_sha384(b"hello")) == SHA384_BYTES

    def test_different_inputs_produce_different_hashes(self):
        assert cng_sha384(b"message one") != cng_sha384(b"message two")

    def test_same_input_produces_same_hash(self):
        data = b"deterministic input"
        assert cng_sha384(data) == cng_sha384(data)

    def test_large_input(self):
        data = b"x" * 100_000
        result = cng_sha384(data)
        assert len(result) == SHA384_BYTES


# ── Key lifecycle ──────────────────────────────────────────────────────────────

class TestKeyLifecycle:
    def test_backend_is_explicit(self):
        assert CRYPTO_BACKEND_ID in {"windows-cng", "portable-test"}

    def test_create_returns_96_byte_public_key(self, key_name):
        with CngSigner.create(key_name) as s:
            assert len(s.public_key_bytes) == P384_COORD_BYTES * 2

    def test_key_exists_after_create(self, key_name):
        with CngSigner.create(key_name):
            assert cng_key_exists(key_name) is True

    def test_key_not_exists_before_create(self, key_name):
        assert cng_key_exists(key_name) is False

    def test_create_twice_raises(self, key_name):
        with CngSigner.create(key_name):
            with pytest.raises(OSError):
                CngSigner.create(key_name)  # no overwrite

    def test_create_overwrite_replaces_key(self, key_name):
        with CngSigner.create(key_name) as s1:
            pub1 = s1.public_key_bytes
        with CngSigner.create(key_name, overwrite=True) as s2:
            pub2 = s2.public_key_bytes
        # Key was replaced — new key pair, different public key (probabilistically)
        assert isinstance(pub2, bytes)
        assert len(pub2) == P384_COORD_BYTES * 2
        # pub1 != pub2 with overwhelming probability (ed25519/ECDSA key uniqueness)
        assert pub1 != pub2

    def test_load_returns_same_public_key(self, key_name):
        with CngSigner.create(key_name) as s_create:
            pub_create = s_create.public_key_bytes

        with CngSigner.load(key_name) as s_load:
            pub_load = s_load.public_key_bytes

        assert pub_create == pub_load

    def test_load_nonexistent_raises_file_not_found(self, key_name):
        with pytest.raises(FileNotFoundError):
            CngSigner.load(key_name)

    def test_delete_key_removes_it(self, key_name):
        CngSigner.create(key_name).close()
        assert cng_key_exists(key_name) is True
        cng_delete_key(key_name)
        assert cng_key_exists(key_name) is False

    def test_delete_nonexistent_key_returns_false(self, key_name):
        assert cng_delete_key(key_name) is False

    def test_algo_id_is_correct(self, signer):
        assert signer.algo_id == ALGO_ID
        assert "P384" in signer.algo_id

    def test_key_name_property(self, key_name, signer):
        assert signer.key_name == key_name

    def test_context_manager_closes_handles(self, key_name):
        with CngSigner.create(key_name) as s:
            pub = s.public_key_bytes
        # After exit, close() was called — handles should be None
        assert s._h_key is None
        assert s._h_prov is None
        # Public key bytes still readable after close
        assert pub is not None


# ── Sign and verify ────────────────────────────────────────────────────────────

class TestSignVerify:
    def test_sign_returns_96_bytes(self, signer):
        sig = signer.sign(b"test payload")
        assert len(sig) == P384_SIG_BYTES

    def test_valid_signature_verifies(self, signer):
        data = b"agent executed action X"
        sig  = signer.sign(data)
        assert cng_verify(data, sig, signer.public_key_bytes) is True

    def test_tampered_data_fails_verify(self, signer):
        sig = signer.sign(b"original data")
        assert cng_verify(b"tampered data", sig, signer.public_key_bytes) is False

    def test_wrong_public_key_fails_verify(self, key_name, signer):
        # Create a second signer with a different key
        other_name = key_name + "-other"
        try:
            with CngSigner.create(other_name) as other:
                sig = signer.sign(b"some data")
                assert cng_verify(b"some data", sig, other.public_key_bytes) is False
        finally:
            cng_delete_key(other_name)

    def test_zero_signature_fails_verify(self, signer):
        assert cng_verify(b"data", b"\x00" * P384_SIG_BYTES, signer.public_key_bytes) is False

    def test_truncated_signature_fails_verify(self, signer):
        sig = signer.sign(b"data")[:P384_SIG_BYTES // 2]
        assert cng_verify(b"data", sig, signer.public_key_bytes) is False

    def test_verify_with_garbage_never_raises(self):
        # All combinations of garbage input must return False, never raise
        assert cng_verify(b"", b"", b"") is False
        assert cng_verify(b"x", b"\xde\xad" * 48, b"\xbe\xef" * 48) is False
        assert cng_verify(b"x", b"not-96-bytes", b"not-96-bytes") is False

    def test_different_messages_produce_different_sigs(self, signer):
        sig1 = signer.sign(b"message one")
        sig2 = signer.sign(b"message two")
        # ECDSA uses a random nonce — sigs will differ even for same message,
        # but different messages must produce different sigs (with overwhelming probability)
        assert sig1 != sig2

    def test_load_and_sign_matches_create_pubkey(self, key_name):
        """Signature from a loaded signer verifies against the originally created pubkey."""
        with CngSigner.create(key_name) as s_create:
            pub_original = s_create.public_key_bytes

        with CngSigner.load(key_name) as s_load:
            sig = s_load.sign(b"cross-instance payload")

        assert cng_verify(b"cross-instance payload", sig, pub_original) is True

    def test_sign_empty_bytes(self, signer):
        sig = signer.sign(b"")
        assert cng_verify(b"", sig, signer.public_key_bytes) is True
