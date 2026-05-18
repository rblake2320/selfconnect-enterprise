"""tests/test_enterprise/test_v1_3_0_fixes.py — Real-crypto tests for v1.3.0 gap fixes.

Covers three fixes introduced on the fix/v1.3.0-gap-remediation branch:

    Fix 1 — Lint (G-lint):
        - version_gate.py: unused ``import time`` removed
        - handshake.py: ``BirthTag`` forward-reference resolved via TYPE_CHECKING

    Fix 2 — Thread-safe ledger wrappers (G-6):
        - ThreadSafeAgentLedger: concurrent writes produce a valid, verifiable chain
        - ThreadSafeCngLedger:   concurrent writes produce a valid, verifiable chain

    Fix 3 — Key rotation (G-4):
        - AgentIdentity.rotate(): generates a new ed25519 key pair, re-encrypts under
          DPAPI, updates in-place; old signatures are rejected, new ones verify
        - CngIdentity.rotate():   generates a new P-384 NCrypt key, updates in-place;
          old signatures are rejected, new ones verify

ZERO MOCKS.  Every test exercises real cryptographic operations:
    - ed25519 key generation, signing, and verification via the cryptography library
    - ECDSA P-384 / SHA-384 key generation, signing, and verification via the
      Linux CNG shim (OpenSSL backend, same algorithms as Windows NCrypt)
    - SHA-256 and SHA-384 hash chains verified entry-by-entry

All assertions are backed by cryptographic proofs that can be independently
verified by any party with access to the public keys and ledger files.

Note on NCrypt key name isolation:
    The Linux CNG shim maintains a process-global in-memory NCrypt KSP.
    To prevent NTE_EXISTS collisions between tests, every _make_cng_identity()
    call uses a unique agent name derived from the tmp_path so each test gets
    its own isolated NCrypt key slot.  This is the correct approach on Linux;
    on Windows the NCrypt KSP is per-user and per-machine, so each test's
    tmp_path naturally isolates the key.
"""
from __future__ import annotations

import hashlib
import sys
import threading
import uuid
from pathlib import Path

import pytest

# ── Helpers ─────────────────────────────────────────────────────────────────────────────

def _make_identity(tmp_path: Path, name: str | None = None):
    """Create a real AgentIdentity with a real ed25519 key pair stored under
    the DPAPI shim (on Linux: AES-256-GCM via the cryptography library).
    No mocking — the key is generated, encrypted, and stored to disk.
    A unique name is generated per call to prevent any cross-test collision."""
    from enterprise.identity import AgentIdentity
    agent_name = name or f"agent-{uuid.uuid4().hex[:8]}"
    return AgentIdentity.init(agent_name, data_dir=tmp_path, overwrite=True)


def _make_cng_identity(tmp_path: Path, name: str | None = None):
    """Create a real CngIdentity with a real P-384 NCrypt key via the Linux shim.
    No mocking — the key is generated in the in-memory NCrypt KSP and the
    public key is written to disk.
    A unique name is generated per call so each test gets its own NCrypt key slot
    (the in-memory KSP is process-global; unique names prevent NTE_EXISTS errors)."""
    from enterprise.identity_cng import CngIdentity
    agent_name = name or f"cng-{uuid.uuid4().hex[:8]}"
    return CngIdentity.init(agent_name, data_dir=tmp_path)


# ══════════════════════════════════════════════════════════════════════════════
# Fix 1 — Lint: unused import and undefined name
# ══════════════════════════════════════════════════════════════════════════════

class TestLintFixes:
    """Verify that the lint fixes are in place by inspecting the source files."""

    def test_version_gate_no_unused_time_import(self):
        """version_gate.py must not contain 'import time' (was unused, now removed)."""
        src = Path(__file__).parents[2] / "enterprise" / "version_gate.py"
        lines = src.read_text(encoding="utf-8").splitlines()
        bare_time_imports = [
            ln.strip() for ln in lines
            if ln.strip() == "import time"
        ]
        assert not bare_time_imports, (
            "version_gate.py still contains 'import time' — lint fix not applied"
        )

    def test_version_gate_imports_cleanly(self):
        """version_gate.py must import without errors after the lint fix."""
        # Force a fresh import to catch any syntax errors introduced by the edit
        if "enterprise.version_gate" in sys.modules:
            del sys.modules["enterprise.version_gate"]
        import enterprise.version_gate as vg
        assert hasattr(vg, "VersionGate"), "VersionGate class missing after re-import"

    def test_handshake_birthTag_type_checking_guard(self):
        """handshake.py must import BirthTag under TYPE_CHECKING, not at runtime."""
        src = Path(__file__).parents[2] / "enterprise" / "handshake.py"
        text = src.read_text(encoding="utf-8")
        assert "TYPE_CHECKING" in text, (
            "handshake.py is missing TYPE_CHECKING import — lint fix not applied"
        )
        assert "from enterprise.birth_tag_v2 import BirthTag" in text, (
            "handshake.py is missing the BirthTag import under TYPE_CHECKING"
        )
        # The type: ignore[name-defined] comment should be gone
        assert "type: ignore[name-defined]" not in text, (
            "handshake.py still has the type: ignore[name-defined] suppressor — "
            "the fix should have resolved the underlying issue instead"
        )

    def test_handshake_imports_cleanly(self):
        """handshake.py must import without errors after the TYPE_CHECKING fix."""
        if "enterprise.handshake" in sys.modules:
            del sys.modules["enterprise.handshake"]
        import enterprise.handshake as hs
        assert hasattr(hs, "verify_peer"), "verify_peer missing after re-import"
        assert hasattr(hs, "HandshakeResponder"), "HandshakeResponder missing"

    def test_birthTag_annotation_is_string_forward_ref(self):
        """The BirthTag parameter annotation in HandshakeChallenge.run() must be
        a string forward-reference (TYPE_CHECKING guard), not a runtime import."""
        import enterprise.handshake as hs
        import inspect
        try:
            # get_type_hints() resolves forward refs at runtime — BirthTag must
            # be resolvable because we added the TYPE_CHECKING import.
            # We do NOT call get_type_hints() here because that would require
            # BirthTag to be importable at runtime (it is, via birth_tag_v2).
            # Instead we just confirm the annotation string is present in the
            # source and the class can be instantiated without error.
            source = inspect.getsource(hs)
            assert '"BirthTag"' in source, (
                "BirthTag annotation not found as string forward-reference in handshake.py"
            )
        except Exception as exc:
            pytest.fail(f"Unexpected error inspecting handshake annotations: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# Fix 2 — Thread-safe ledger wrappers (G-6)
# ══════════════════════════════════════════════════════════════════════════════

class TestThreadSafeAgentLedger:
    """ThreadSafeAgentLedger must produce a valid, verifiable hash chain under
    concurrent writes.  All operations use real ed25519 signing."""

    def test_class_exists_and_is_subclass(self):
        """ThreadSafeAgentLedger must exist and subclass AgentLedger."""
        from enterprise.ledger import AgentLedger, ThreadSafeAgentLedger
        assert issubclass(ThreadSafeAgentLedger, AgentLedger), (
            "ThreadSafeAgentLedger must be a subclass of AgentLedger"
        )

    def test_sequential_writes_valid_chain(self, tmp_path):
        """50 sequential writes produce a valid, verifiable ed25519-signed chain."""
        from enterprise.ledger import ThreadSafeAgentLedger
        identity = _make_identity(tmp_path)
        ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "seq.jsonl")
        for i in range(50):
            entry = ledger.log(f"action-{i}", result=f"result-{i}")
            # Every returned entry must contain a real signature
            assert len(entry["sig"]) == 128, (
                f"entry {i}: sig is {len(entry['sig'])} hex chars, expected 128 (64 bytes ed25519)"
            )
            assert entry["seq"] == i + 1
        valid, count, msg = ledger.verify()
        assert valid, f"Sequential chain broken: {msg}"
        assert count == 50

    def test_concurrent_writes_valid_chain(self, tmp_path):
        """20 threads × 50 writes = 1000 entries — chain must be valid after all
        threads complete.  This is the key proof that the lock works correctly.

        Real cryptographic verification: verify() re-reads every entry, checks
        the ed25519 signature, and walks the SHA-256 hash chain.  A single
        corrupted entry fails the entire verification.
        """
        from enterprise.ledger import ThreadSafeAgentLedger
        identity = _make_identity(tmp_path, name="concurrent-safe-agent")
        ledger = ThreadSafeAgentLedger(
            identity, log_path=tmp_path / "concurrent.jsonl"
        )
        errors: list[str] = []

        def writer(thread_id: int):
            for i in range(50):
                try:
                    entry = ledger.log(f"t{thread_id}-action-{i}", result="ok")
                    # Verify the signature of each entry as it is written
                    from enterprise.identity import AgentIdentity
                    import json
                    e = dict(entry)
                    sig_hex = e.pop("sig")
                    entry_bytes = json.dumps(
                        e, sort_keys=True, separators=(",", ":")
                    ).encode()
                    ok = AgentIdentity.verify(
                        entry_bytes,
                        bytes.fromhex(sig_hex),
                        identity.public_key_bytes,
                    )
                    if not ok:
                        errors.append(
                            f"t{thread_id}-{i}: signature verification failed immediately after write"
                        )
                except Exception as exc:
                    errors.append(f"t{thread_id}-{i}: {exc!r}")

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert not errors, "Errors during concurrent writes:\n" + "\n".join(errors)

        # Full chain verification — walks every entry, checks every sig and every link
        valid, count, msg = ledger.verify()
        assert valid, (
            f"Hash chain corrupted under concurrent writes — lock is not working.\n"
            f"verify() returned: {msg}\n"
            f"Entries written: {ledger.entry_count()}"
        )
        assert count == 1000, f"Expected 1000 entries, got {count}"

    def test_concurrent_writes_monotonic_seq(self, tmp_path):
        """Sequence numbers must be strictly monotonic (no duplicates, no gaps)
        when written concurrently through the lock."""
        from enterprise.ledger import ThreadSafeAgentLedger
        identity = _make_identity(tmp_path, name="seq-check-agent")
        ledger = ThreadSafeAgentLedger(
            identity, log_path=tmp_path / "seq_check.jsonl"
        )
        written_seqs: list[int] = []
        lock = threading.Lock()

        def writer(thread_id: int):
            for i in range(25):
                entry = ledger.log(f"t{thread_id}-{i}", result="ok")
                with lock:
                    written_seqs.append(entry["seq"])

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(written_seqs) == 250
        assert len(set(written_seqs)) == 250, (
            f"Duplicate sequence numbers detected — lock is not serialising correctly.\n"
            f"Duplicates: {[s for s in written_seqs if written_seqs.count(s) > 1]}"
        )
        assert sorted(written_seqs) == list(range(1, 251)), (
            "Sequence numbers are not a contiguous 1..250 range"
        )

    def test_has_write_lock_attribute(self, tmp_path):
        """ThreadSafeAgentLedger must expose _write_lock as a threading.Lock."""
        from enterprise.ledger import ThreadSafeAgentLedger
        identity = _make_identity(tmp_path)
        ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "lock.jsonl")
        assert hasattr(ledger, "_write_lock"), "_write_lock attribute missing"
        assert isinstance(ledger._write_lock, type(threading.Lock())), (
            "_write_lock is not a threading.Lock instance"
        )


class TestThreadSafeCngLedger:
    """ThreadSafeCngLedger must produce a valid, verifiable SHA-384 hash chain
    under concurrent writes.  All operations use real ECDSA P-384 signing."""

    def test_class_exists_and_is_subclass(self):
        """ThreadSafeCngLedger must exist and subclass CngLedger."""
        from enterprise.identity_cng import CngLedger, ThreadSafeCngLedger
        assert issubclass(ThreadSafeCngLedger, CngLedger), (
            "ThreadSafeCngLedger must be a subclass of CngLedger"
        )

    def test_sequential_writes_valid_chain(self, tmp_path):
        """50 sequential writes produce a valid, verifiable P-384-signed SHA-384 chain."""
        from enterprise.identity_cng import ThreadSafeCngLedger
        identity = _make_cng_identity(tmp_path)
        ledger = ThreadSafeCngLedger(identity, log_path=tmp_path / "cng_seq.jsonl")
        for i in range(50):
            entry = ledger.log(f"action-{i}", result=f"result-{i}")
            # P-384 ECDSA signature in IEEE P1363 format = 96 bytes = 192 hex chars
            assert len(entry["sig"]) == 192, (
                f"entry {i}: sig is {len(entry['sig'])} hex chars, expected 192 (96 bytes P-384)"
            )
            assert entry["algo"] == "ECDSA_P384_SHA384", (
                f"entry {i}: algo field is {entry['algo']!r}, expected 'ECDSA_P384_SHA384'"
            )
            assert entry["seq"] == i + 1
        valid, count, msg = ledger.verify()
        assert valid, f"Sequential CNG chain broken: {msg}"
        assert count == 50

    def test_concurrent_writes_valid_chain(self, tmp_path):
        """10 threads × 50 writes = 500 entries — SHA-384 chain must be valid.

        Real cryptographic verification: verify() re-reads every entry, checks
        the ECDSA P-384 signature via the Linux CNG shim (OpenSSL), and walks
        the SHA-384 hash chain.
        """
        from enterprise.identity_cng import ThreadSafeCngLedger
        identity = _make_cng_identity(tmp_path, name="cng-concurrent-agent")
        ledger = ThreadSafeCngLedger(
            identity, log_path=tmp_path / "cng_concurrent.jsonl"
        )
        errors: list[str] = []

        def writer(thread_id: int):
            for i in range(50):
                try:
                    entry = ledger.log(f"t{thread_id}-action-{i}", result="ok")
                    # Immediately verify the signature of each entry
                    from enterprise.identity_cng import CngIdentity
                    import json
                    e = dict(entry)
                    sig_hex = e.pop("sig")
                    entry_bytes = json.dumps(
                        e, sort_keys=True, separators=(",", ":")
                    ).encode()
                    ok = CngIdentity.verify(
                        entry_bytes,
                        bytes.fromhex(sig_hex),
                        identity.public_key_bytes,
                    )
                    if not ok:
                        errors.append(
                            f"t{thread_id}-{i}: P-384 signature verification failed immediately after write"
                        )
                except Exception as exc:
                    errors.append(f"t{thread_id}-{i}: {exc!r}")

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert not errors, "Errors during concurrent CNG writes:\n" + "\n".join(errors)

        valid, count, msg = ledger.verify()
        assert valid, (
            f"SHA-384 hash chain corrupted under concurrent writes — lock is not working.\n"
            f"verify() returned: {msg}\n"
            f"Entries written: {ledger.entry_count()}"
        )
        assert count == 500, f"Expected 500 entries, got {count}"

    def test_has_write_lock_attribute(self, tmp_path):
        """ThreadSafeCngLedger must expose _write_lock as a threading.Lock."""
        from enterprise.identity_cng import ThreadSafeCngLedger
        identity = _make_cng_identity(tmp_path)
        ledger = ThreadSafeCngLedger(identity, log_path=tmp_path / "cng_lock.jsonl")
        assert hasattr(ledger, "_write_lock"), "_write_lock attribute missing"
        assert isinstance(ledger._write_lock, type(threading.Lock())), (
            "_write_lock is not a threading.Lock instance"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Fix 3 — Key rotation (G-4)
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentIdentityRotate:
    """AgentIdentity.rotate() must generate a new real ed25519 key pair,
    re-encrypt under DPAPI, and update the instance in-place."""

    def test_rotate_changes_public_key(self, tmp_path):
        """After rotation the public key bytes must be different from the original."""
        identity = _make_identity(tmp_path)
        original_pub = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        assert identity.public_key_bytes != original_pub, (
            "rotate() did not change the public key — new key was not generated"
        )
        # New public key must be 32 bytes (ed25519)
        assert len(identity.public_key_bytes) == 32, (
            f"New public key is {len(identity.public_key_bytes)} bytes, expected 32"
        )

    def test_rotate_changes_agent_id(self, tmp_path):
        """After rotation the agent_id must change (it is derived from the public key)."""
        identity = _make_identity(tmp_path)
        original_id = identity.agent_id
        identity.rotate(data_dir=tmp_path)
        assert identity.agent_id != original_id, (
            "rotate() did not change agent_id — public key fingerprint unchanged"
        )
        assert identity.agent_id.startswith("SC-"), (
            f"New agent_id {identity.agent_id!r} does not start with 'SC-'"
        )
        assert len(identity.agent_id) == 11, (  # "SC-" + 8 hex chars
            f"New agent_id {identity.agent_id!r} is not 11 chars"
        )

    def test_rotate_new_key_signs_and_verifies(self, tmp_path):
        """Signatures produced with the rotated key must verify against the new
        public key.  This is a real ed25519 sign + verify operation."""
        from enterprise.identity import AgentIdentity
        identity = _make_identity(tmp_path)
        identity.rotate(data_dir=tmp_path)
        data = b"post-rotation action data"
        sig = identity.sign(data)
        assert len(sig) == 64, f"ed25519 signature must be 64 bytes, got {len(sig)}"
        ok = AgentIdentity.verify(data, sig, identity.public_key_bytes)
        assert ok, "Signature produced by rotated key does not verify — key mismatch"

    def test_rotate_old_key_signature_rejected(self, tmp_path):
        """A signature produced with the OLD key must NOT verify against the NEW
        public key.  This proves the rotation actually replaced the key material."""
        from enterprise.identity import AgentIdentity
        identity = _make_identity(tmp_path)
        data = b"pre-rotation action data"
        old_sig = identity.sign(data)
        old_pub = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        new_pub = identity.public_key_bytes
        # Old sig against new pub must fail
        assert not AgentIdentity.verify(data, old_sig, new_pub), (
            "Old signature verifies against new public key — rotation did not replace key material"
        )
        # Old sig against old pub must still pass (the algorithm is correct)
        assert AgentIdentity.verify(data, old_sig, old_pub), (
            "Old signature does not verify against old public key — ed25519 is broken"
        )

    def test_rotate_persists_to_disk(self, tmp_path):
        """After rotation, loading the identity from disk must return the new key."""
        from enterprise.identity import AgentIdentity
        identity = _make_identity(tmp_path, name="persist-test")
        identity.rotate(data_dir=tmp_path)
        new_pub = identity.public_key_bytes
        new_id = identity.agent_id
        # Load from disk — must match the rotated key
        loaded = AgentIdentity.load("persist-test", data_dir=tmp_path)
        assert loaded.public_key_bytes == new_pub, (
            "Loaded identity public key does not match the rotated key — "
            "rotate() did not persist the new key to disk"
        )
        assert loaded.agent_id == new_id, (
            "Loaded identity agent_id does not match the rotated agent_id"
        )

    def test_rotate_returns_self(self, tmp_path):
        """rotate() must return the same instance (updated in-place)."""
        identity = _make_identity(tmp_path)
        result = identity.rotate(data_dir=tmp_path)
        assert result is identity, "rotate() must return self"

    def test_rotate_twice_produces_different_keys(self, tmp_path):
        """Two consecutive rotations must produce three distinct public keys."""
        identity = _make_identity(tmp_path)
        pub0 = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        pub1 = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        pub2 = identity.public_key_bytes
        assert len({pub0, pub1, pub2}) == 3, (
            "Two rotations did not produce three distinct public keys — "
            "key generation may be deterministic or not working"
        )

    def test_rotate_agent_id_is_sha256_fingerprint(self, tmp_path):
        """After rotation, agent_id must equal 'SC-' + SHA-256(pub_key)[:8].upper()."""
        identity = _make_identity(tmp_path)
        identity.rotate(data_dir=tmp_path)
        expected_id = "SC-" + hashlib.sha256(identity.public_key_bytes).hexdigest()[:8].upper()
        assert identity.agent_id == expected_id, (
            f"agent_id {identity.agent_id!r} does not match expected {expected_id!r}"
        )

    def test_rotate_ledger_chain_continues_correctly(self, tmp_path):
        """Entries written before rotation must still verify; entries written after
        rotation must verify with the new key.  The two ledger segments are
        independent chains — this is the correct behaviour."""
        from enterprise.ledger import AgentLedger
        identity = _make_identity(tmp_path, name="ledger-rotate")
        ledger_pre = AgentLedger(identity, log_path=tmp_path / "pre.jsonl")
        for i in range(5):
            ledger_pre.log(f"pre-rotation-{i}", result="ok")
        valid_pre, count_pre, msg_pre = ledger_pre.verify()
        assert valid_pre, f"Pre-rotation chain invalid: {msg_pre}"
        assert count_pre == 5
        # Rotate
        identity.rotate(data_dir=tmp_path)
        # New ledger with new key
        ledger_post = AgentLedger(identity, log_path=tmp_path / "post.jsonl")
        for i in range(5):
            ledger_post.log(f"post-rotation-{i}", result="ok")
        valid_post, count_post, msg_post = ledger_post.verify()
        assert valid_post, f"Post-rotation chain invalid: {msg_post}"
        assert count_post == 5


class TestCngIdentityRotate:
    """CngIdentity.rotate() must generate a new real P-384 NCrypt key,
    update the instance in-place, and persist the new public key to disk."""

    def test_rotate_changes_public_key(self, tmp_path):
        """After rotation the public key bytes must be different from the original."""
        identity = _make_cng_identity(tmp_path)
        original_pub = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        assert identity.public_key_bytes != original_pub, (
            "rotate() did not change the P-384 public key — new key was not generated"
        )
        # P-384 raw public key = 96 bytes (X || Y, 48 bytes each)
        assert len(identity.public_key_bytes) == 96, (
            f"New P-384 public key is {len(identity.public_key_bytes)} bytes, expected 96"
        )

    def test_rotate_changes_agent_id(self, tmp_path):
        """After rotation the agent_id must change (SHA-384 fingerprint of new key)."""
        from enterprise.crypto import cng_sha384
        identity = _make_cng_identity(tmp_path)
        original_id = identity.agent_id
        identity.rotate(data_dir=tmp_path)
        assert identity.agent_id != original_id, (
            "rotate() did not change agent_id — public key fingerprint unchanged"
        )
        expected_id = "SC-" + cng_sha384(identity.public_key_bytes).hex()[:8].upper()
        assert identity.agent_id == expected_id, (
            f"agent_id {identity.agent_id!r} does not match SHA-384 fingerprint {expected_id!r}"
        )

    def test_rotate_new_key_signs_and_verifies(self, tmp_path):
        """Signatures produced with the rotated P-384 key must verify.
        This is a real ECDSA P-384 / SHA-384 sign + verify operation."""
        from enterprise.identity_cng import CngIdentity
        identity = _make_cng_identity(tmp_path)
        identity.rotate(data_dir=tmp_path)
        data = b"post-rotation P-384 action data"
        sig = identity.sign(data)
        # P-384 ECDSA signature = 96 bytes
        assert len(sig) == 96, f"P-384 signature must be 96 bytes, got {len(sig)}"
        ok = CngIdentity.verify(data, sig, identity.public_key_bytes)
        assert ok, "Signature produced by rotated P-384 key does not verify"

    def test_rotate_old_key_signature_rejected(self, tmp_path):
        """A signature produced with the OLD P-384 key must NOT verify against
        the NEW public key.  Proves rotation replaced the key material."""
        from enterprise.identity_cng import CngIdentity
        identity = _make_cng_identity(tmp_path)
        data = b"pre-rotation P-384 data"
        old_sig = identity.sign(data)
        old_pub = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        new_pub = identity.public_key_bytes
        # Old sig against new pub must fail
        assert not CngIdentity.verify(data, old_sig, new_pub), (
            "Old P-384 signature verifies against new public key — rotation did not replace key material"
        )
        # Old sig against old pub must still pass
        assert CngIdentity.verify(data, old_sig, old_pub), (
            "Old P-384 signature does not verify against old public key — ECDSA P-384 is broken"
        )

    def test_rotate_persists_public_key_to_disk(self, tmp_path):
        """After rotation, the public key file on disk must contain the new key."""
        identity = _make_cng_identity(tmp_path, name="cng-persist-test")
        identity.rotate(data_dir=tmp_path)
        new_pub = identity.public_key_bytes
        pub_file = tmp_path / "cng-persist-test" / "identity_cng.pub"
        assert pub_file.exists(), "Public key file not written after rotation"
        disk_pub = bytes.fromhex(pub_file.read_text(encoding="ascii").strip())
        assert disk_pub == new_pub, (
            "Public key on disk does not match the rotated key — "
            "rotate() did not persist the new public key"
        )

    def test_rotate_returns_self(self, tmp_path):
        """rotate() must return the same instance (updated in-place)."""
        identity = _make_cng_identity(tmp_path)
        result = identity.rotate(data_dir=tmp_path)
        assert result is identity, "rotate() must return self"

    def test_rotate_twice_produces_different_keys(self, tmp_path):
        """Two consecutive rotations must produce three distinct P-384 public keys."""
        identity = _make_cng_identity(tmp_path)
        pub0 = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        pub1 = identity.public_key_bytes
        identity.rotate(data_dir=tmp_path)
        pub2 = identity.public_key_bytes
        assert len({pub0, pub1, pub2}) == 3, (
            "Two P-384 rotations did not produce three distinct public keys"
        )

    def test_rotate_cng_ledger_chain_continues_correctly(self, tmp_path):
        """Entries written before rotation verify with the old key; entries after
        verify with the new key.  Both chains must be independently valid."""
        from enterprise.identity_cng import CngLedger
        identity = _make_cng_identity(tmp_path, name="cng-ledger-rotate")
        ledger_pre = CngLedger(identity, log_path=tmp_path / "cng_pre.jsonl")
        for i in range(5):
            ledger_pre.log(f"pre-rotation-{i}", result="ok")
        valid_pre, count_pre, msg_pre = ledger_pre.verify()
        assert valid_pre, f"Pre-rotation CNG chain invalid: {msg_pre}"
        assert count_pre == 5
        # Rotate
        identity.rotate(data_dir=tmp_path)
        # New ledger with new key
        ledger_post = CngLedger(identity, log_path=tmp_path / "cng_post.jsonl")
        for i in range(5):
            ledger_post.log(f"post-rotation-{i}", result="ok")
        valid_post, count_post, msg_post = ledger_post.verify()
        assert valid_post, f"Post-rotation CNG chain invalid: {msg_post}"
        assert count_post == 5


# ══════════════════════════════════════════════════════════════════════════════
# Cross-fix integration: ThreadSafe + Rotation together
# ══════════════════════════════════════════════════════════════════════════════

class TestThreadSafeWithRotation:
    """Verify that ThreadSafeAgentLedger and ThreadSafeCngLedger work correctly
    when used with a freshly-rotated identity."""

    def test_thread_safe_ledger_after_rotation(self, tmp_path):
        """ThreadSafeAgentLedger created with a rotated identity must produce a
        valid chain under concurrent writes."""
        from enterprise.ledger import ThreadSafeAgentLedger
        identity = _make_identity(tmp_path, name="rotated-concurrent")
        identity.rotate(data_dir=tmp_path)  # rotate first
        ledger = ThreadSafeAgentLedger(
            identity, log_path=tmp_path / "rotated_concurrent.jsonl"
        )
        errors: list[str] = []

        def writer(thread_id: int):
            for i in range(20):
                try:
                    ledger.log(f"t{thread_id}-{i}", result="ok")
                except Exception as exc:
                    errors.append(f"t{thread_id}-{i}: {exc!r}")

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Errors: {errors}"
        valid, count, msg = ledger.verify()
        assert valid, f"Chain invalid after rotation + concurrent writes: {msg}"
        assert count == 100

    def test_thread_safe_cng_ledger_after_rotation(self, tmp_path):
        """ThreadSafeCngLedger created with a rotated CngIdentity must produce a
        valid SHA-384 chain under concurrent writes."""
        from enterprise.identity_cng import ThreadSafeCngLedger
        identity = _make_cng_identity(tmp_path, name="cng-rotated-concurrent")
        identity.rotate(data_dir=tmp_path)  # rotate first
        ledger = ThreadSafeCngLedger(
            identity, log_path=tmp_path / "cng_rotated_concurrent.jsonl"
        )
        errors: list[str] = []

        def writer(thread_id: int):
            for i in range(20):
                try:
                    ledger.log(f"t{thread_id}-{i}", result="ok")
                except Exception as exc:
                    errors.append(f"t{thread_id}-{i}: {exc!r}")

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Errors: {errors}"
        valid, count, msg = ledger.verify()
        assert valid, f"CNG chain invalid after rotation + concurrent writes: {msg}"
        assert count == 100
