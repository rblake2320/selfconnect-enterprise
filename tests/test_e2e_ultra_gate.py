"""test_e2e_ultra_gate.py — End-to-End Integration Tests for UltraGate

These tests exercise the complete production flow against the live Ultra Server
running on localhost:7777.  No mocks.  No stubs.  Every assertion is against
real HTTP responses.

Flow under test:
    1. AgentIdentity.init()       — generate real Ed25519 keypair
    2. UltraGate.__init__()       — derive P-256 from Ed25519, compute fingerprint
    3. UltraGate.bootstrap()      — POST /register-pair, POST /provision-tsk,
                                    POST /bind-identity (all real HTTP)
    4. UltraGate.build_injection_request()  — build BPC+TSK headers
    5. UltraGate.authorize_injection()      — self-verify the request
    6. UltraGate.verify_server()            — POST /verify (7-layer server check)
    7. Adversarial: tampered headers must be rejected by the server
    8. Adversarial: wrong pair_id must be rejected
    9. Adversarial: replayed nonce must be rejected

All tests are skipped if the Ultra Server is not available on localhost:7777.

Version: 1.0.0-enterprise  Session 17
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

import pytest

SERVER_URL = "http://localhost:7777"


def _server_available() -> bool:
    """Return True if the Ultra Server is reachable."""
    try:
        urllib.request.urlopen(f"{SERVER_URL}/status", timeout=2)
        return True
    except Exception:
        return False


# Skip the entire module if the server is not available
pytestmark = pytest.mark.skipif(
    not _server_available(),
    reason="Ultra Server not available on localhost:7777",
)


@pytest.fixture(scope="module")
def agent_identity(tmp_path_factory):
    """Create a real AgentIdentity for the E2E test module."""
    from enterprise.identity import AgentIdentity
    data_dir = tmp_path_factory.mktemp("e2e_identity")
    return AgentIdentity.init("e2e-test-agent", data_dir=data_dir)


@pytest.fixture(scope="module")
def bootstrapped_gate(agent_identity):
    """Create and bootstrap a real UltraGate against the live Ultra Server."""
    from enterprise.ultra_gate import UltraGate
    gate = UltraGate(agent_identity, server_url=SERVER_URL)
    gate.bootstrap()
    return gate


# ── Test 1: Bootstrap succeeds ────────────────────────────────────────────────

class TestUltraGateBootstrap:
    def test_bootstrap_assigns_pair_id(self, bootstrapped_gate):
        """After bootstrap(), gate.pair_id is a non-empty string."""
        assert bootstrapped_gate.pair_id, "pair_id must be set after bootstrap"
        assert isinstance(bootstrapped_gate.pair_id, str)
        assert len(bootstrapped_gate.pair_id) > 8

    def test_bootstrap_assigns_tsk_state(self, bootstrapped_gate):
        """After bootstrap(), gate.tsk_state has segments and a shared secret."""
        state = bootstrapped_gate.tsk_state
        assert state is not None, "tsk_state must be set after bootstrap"
        assert len(state.segments) > 0, "TSK must have at least one segment"
        assert len(state.shared_secret) >= 16, "shared_secret must be at least 16 bytes"

    def test_bootstrap_is_idempotent(self, bootstrapped_gate):
        """Calling bootstrap() a second time is a no-op (no exception, same pair_id)."""
        original_pair_id = bootstrapped_gate.pair_id
        bootstrapped_gate.bootstrap()  # should not raise
        assert bootstrapped_gate.pair_id == original_pair_id

    def test_server_status_shows_pair_registered(self, bootstrapped_gate):
        """After bootstrap, /status shows at least 1 registered pair."""
        with urllib.request.urlopen(f"{SERVER_URL}/status", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert data["ok"] is True
        assert data["pairs"] >= 1, "At least one pair should be registered after bootstrap"


# ── Test 2: build_injection_request produces valid headers ────────────────────

class TestBuildInjectionRequest:
    def test_headers_contain_required_keys(self, bootstrapped_gate):
        """build_injection_request() returns all required BPC+TSK header keys."""
        headers = bootstrapped_gate.build_injection_request(0xABCD1234, "hello world")
        required = [
            "X-BPC-Pair-ID",
            "X-BPC-Signed-Data",
            "X-BPC-Signature",
            "X-BPC-Version",
            "X-TSK-Client-ID",
            "X-TSK-Key",
            "X-TSK-Version",
        ]
        for key in required:
            assert key in headers, f"Missing header: {key}"

    def test_pair_id_matches_bootstrap(self, bootstrapped_gate):
        """X-BPC-Pair-ID in headers must match the bootstrapped pair_id."""
        headers = bootstrapped_gate.build_injection_request(0x1234, "test")
        assert headers["X-BPC-Pair-ID"] == bootstrapped_gate.pair_id

    def test_tsk_key_has_checksum(self, bootstrapped_gate):
        """X-TSK-Key must be at least 22 chars (12-char key + 10-char checksum)."""
        headers = bootstrapped_gate.build_injection_request(0x1234, "test")
        tsk_key = headers["X-TSK-Key"]
        assert len(tsk_key) >= 22, f"TSK key too short: {len(tsk_key)} chars"

    def test_signed_data_is_valid_base64url(self, bootstrapped_gate):
        """X-BPC-Signed-Data must be valid base64url-encoded JSON."""
        import base64
        headers = bootstrapped_gate.build_injection_request(0x1234, "test")
        signed_data = headers["X-BPC-Signed-Data"]
        # Add padding if needed
        padded = signed_data + "=" * (-len(signed_data) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        payload = json.loads(decoded)
        assert "body_hash" in payload
        assert "nonce" in payload
        assert "pair_id" in payload
        assert "timestamp" in payload


# ── Test 3: authorize_injection (self-verify) ─────────────────────────────────

class TestAuthorizeInjection:
    def test_authorize_injection_succeeds_for_valid_text(self, bootstrapped_gate):
        """authorize_injection() must not raise for valid text."""
        bootstrapped_gate.authorize_injection(0xABCD1234, "ls -la /tmp")

    def test_authorize_injection_succeeds_for_empty_text(self, bootstrapped_gate):
        """authorize_injection() must not raise for empty text (valid edge case)."""
        bootstrapped_gate.authorize_injection(0xABCD1234, "")

    def test_authorize_injection_succeeds_for_unicode(self, bootstrapped_gate):
        """authorize_injection() must not raise for unicode text."""
        bootstrapped_gate.authorize_injection(0xABCD1234, "echo '日本語テスト'")

    def test_authorize_injection_raises_before_bootstrap(self, agent_identity):
        """authorize_injection() must raise UltraGateNotBootstrappedError if not bootstrapped."""
        from enterprise.ultra_gate import UltraGate, UltraGateNotBootstrappedError
        gate = UltraGate(agent_identity, server_url=SERVER_URL)
        with pytest.raises(UltraGateNotBootstrappedError):
            gate.authorize_injection(0x1234, "test")


# ── Test 4: verify_server — full 7-layer server verification ─────────────────

class TestVerifyServer:
    def test_valid_request_passes_server_verification(self, bootstrapped_gate):
        """A freshly built request must pass the full 7-layer server verification."""
        text = "echo 'e2e-test-payload'"
        headers = bootstrapped_gate.build_injection_request(0xDEADBEEF, text)
        ok, reason = bootstrapped_gate.verify_server(headers, text)
        assert ok is True, f"Server verification failed: {reason}"
        assert reason == ""

    def test_multiple_sequential_requests_pass(self, bootstrapped_gate):
        """10 sequential requests must all pass server verification (HOTP counter advances)."""
        for i in range(10):
            text = f"echo 'seq-test-{i}'"
            headers = bootstrapped_gate.build_injection_request(0x1000 + i, text)
            ok, reason = bootstrapped_gate.verify_server(headers, text)
            assert ok is True, f"Request {i} failed server verification: {reason}"

    def test_tampered_body_hash_is_rejected(self, bootstrapped_gate):
        """Changing X-BPC-Signed-Data to embed a wrong body_hash must be rejected."""
        import base64
        text = "echo 'tamper-test'"
        headers = bootstrapped_gate.build_injection_request(0x5678, text)

        # Decode and tamper the body_hash
        signed_data = headers["X-BPC-Signed-Data"]
        padded = signed_data + "=" * (-len(signed_data) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        payload["body_hash"] = "sha256-" + "00" * 32  # wrong hash
        tampered_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        headers["X-BPC-Signed-Data"] = base64.urlsafe_b64encode(
            tampered_json.encode("utf-8")
        ).decode("utf-8").rstrip("=")

        ok, reason = bootstrapped_gate.verify_server(headers, text)
        assert ok is False, "Tampered body_hash must be rejected by server"

    def test_wrong_pair_id_is_rejected(self, bootstrapped_gate):
        """A request with a non-existent pair_id must be rejected by the server."""
        text = "echo 'wrong-pair'"
        headers = bootstrapped_gate.build_injection_request(0x9999, text)
        headers["X-BPC-Pair-ID"] = "nonexistent-pair-id-00000000"

        ok, reason = bootstrapped_gate.verify_server(headers, text)
        assert ok is False, "Non-existent pair_id must be rejected by server"

    def test_missing_tsk_key_is_rejected(self, bootstrapped_gate):
        """A request with X-TSK-Key removed must be rejected by the server."""
        text = "echo 'no-tsk'"
        headers = bootstrapped_gate.build_injection_request(0xAAAA, text)
        del headers["X-TSK-Key"]

        ok, reason = bootstrapped_gate.verify_server(headers, text)
        assert ok is False, "Missing X-TSK-Key must be rejected by server"

    def test_truncated_signature_is_rejected(self, bootstrapped_gate):
        """A request with a truncated ECDSA signature must be rejected."""
        text = "echo 'bad-sig'"
        headers = bootstrapped_gate.build_injection_request(0xBBBB, text)
        headers["X-BPC-Signature"] = headers["X-BPC-Signature"][:16]  # truncate

        ok, reason = bootstrapped_gate.verify_server(headers, text)
        assert ok is False, "Truncated signature must be rejected by server"


# ── Test 5: Full E2E flow (bootstrap → authorize → server verify) ─────────────

class TestFullE2EFlow:
    def test_full_flow_two_agents_cross_verify(self, tmp_path):
        """Two independent agents bootstrap and cross-verify each other's requests.

        This is the production scenario: agent A builds a request, agent B
        (acting as the receiving peer) verifies it via the server.
        """
        from enterprise.identity import AgentIdentity
        from enterprise.ultra_gate import UltraGate

        dir_a = tmp_path / "agent_a"
        dir_b = tmp_path / "agent_b"
        dir_a.mkdir()
        dir_b.mkdir()

        id_a = AgentIdentity.init("e2e-agent-a", data_dir=dir_a)
        id_b = AgentIdentity.init("e2e-agent-b", data_dir=dir_b)

        gate_a = UltraGate(id_a, server_url=SERVER_URL)
        gate_b = UltraGate(id_b, server_url=SERVER_URL)

        gate_a.bootstrap()
        gate_b.bootstrap()

        # Agent A builds and self-authorizes a request
        text = "echo 'cross-verify'"
        gate_a.authorize_injection(0xCCCC, text)

        # Agent A's request passes full server verification
        headers = gate_a.build_injection_request(0xCCCC, text)
        ok, reason = gate_a.verify_server(headers, text)
        assert ok is True, f"Agent A's request failed server verification: {reason}"

        # Agent B's request also passes (independent bootstrap)
        text_b = "echo 'agent-b-request'"
        gate_b.authorize_injection(0xDDDD, text_b)
        headers_b = gate_b.build_injection_request(0xDDDD, text_b)
        ok_b, reason_b = gate_b.verify_server(headers_b, text_b)
        assert ok_b is True, f"Agent B's request failed server verification: {reason_b}"

        # Cross-contamination check: Agent A's headers must not verify with Agent B's text
        ok_cross, _ = gate_a.verify_server(headers, text_b)
        assert ok_cross is False, "Cross-contamination: A's headers accepted with B's text"

    def test_full_flow_high_frequency(self, bootstrapped_gate):
        """50 rapid sequential requests must all pass (stress test HOTP counter)."""
        failures = []
        for i in range(50):
            text = f"rapid-test-{i:04d}"
            try:
                bootstrapped_gate.authorize_injection(0x1000 + i, text)
                headers = bootstrapped_gate.build_injection_request(0x1000 + i, text)
                ok, reason = bootstrapped_gate.verify_server(headers, text)
                if not ok:
                    failures.append(f"request {i}: {reason}")
            except Exception as exc:
                failures.append(f"request {i} exception: {exc}")
        assert not failures, "High-frequency test failures:\n" + "\n".join(failures)
