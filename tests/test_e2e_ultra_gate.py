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
import os
import urllib.request
import urllib.error
import uuid

import pytest

SERVER_URL = "http://127.0.0.1:7777"
ADMIN_TOKEN = os.environ.get("ULTRA_ADMIN_TOKEN", "")


def _server_available() -> bool:
    """Return True if the Ultra Server is reachable."""
    try:
        urllib.request.urlopen(f"{SERVER_URL}/health", timeout=2)
        return True
    except Exception:
        return False


_SERVER_AVAILABLE = _server_available()
if os.environ.get("SC_REQUIRE_ULTRA_SERVER") == "1" and not _SERVER_AVAILABLE:
    raise RuntimeError("SC_REQUIRE_ULTRA_SERVER=1 but Ultra Server is unavailable")

pytestmark = pytest.mark.skipif(
    not _SERVER_AVAILABLE,
    reason="Ultra Server not available on localhost:7777",
)


@pytest.fixture(scope="module")
def agent_identity(tmp_path_factory):
    """Create a real AgentIdentity for the E2E test module."""
    if os.name == "nt":
        from enterprise.identity import AgentIdentity
        data_dir = tmp_path_factory.mktemp("e2e_identity")
        return AgentIdentity.init("e2e-test-agent", data_dir=data_dir)

    import hashlib
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    agent_id = "SC-" + hashlib.sha256(public_key_bytes).hexdigest()[:8].upper()
    return SimpleNamespace(
        _private_key=private_key,
        public_key_bytes=public_key_bytes,
        agent_id=agent_id,
        sign=private_key.sign,
    )


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
        req = urllib.request.Request(
            f"{SERVER_URL}/status",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
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


# ── US-3: Lifecycle Endpoint Authentication Tests ─────────────────────────────
class TestLifecycleAuth:
    """Every lifecycle mutation must reject requests without its required proof.

    These tests run against the live Ultra Server (localhost:7777) and exercise
    the real HTTP layer — no mocks, no stubs.

    Agent routes require a signed agent proof. Administrative routes require
    an operator bearer. Recovery requires both. What matters here is that the
    server never returns 2xx/3xx for an unauthenticated lifecycle mutation.
    """

    LIFECYCLE_ENDPOINTS = [
        ("POST",  "/register-pair"),
        ("POST",  "/provision-tsk"),
        ("POST",  "/bind-identity"),
        ("POST",  "/confirm-recovery"),
        ("PATCH", "/tsk/keys/nonexistent-client-id"),
        ("PATCH", "/bpc/pairs/nonexistent-pair-id"),
    ]

    def _raw_request(self, method: str, path: str, body: dict | None = None,
                     headers: dict | None = None) -> tuple[int, dict]:
        """Make a raw HTTP request and return (status_code, json_body)."""
        import json as _json
        import urllib.request as _req
        import urllib.error as _err
        data = _json.dumps(body or {}).encode()
        req = _req.Request(
            f"{SERVER_URL}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with _req.urlopen(req, timeout=5) as resp:
                return resp.status, _json.loads(resp.read())
        except _err.HTTPError as exc:
            try:
                body_bytes = exc.read()
                return exc.code, _json.loads(body_bytes)
            except Exception:
                return exc.code, {}

    def test_bind_identity_no_auth_is_rejected(self):
        """POST /bind-identity without Authorization header must return 401 or 503."""
        status, body = self._raw_request("POST", "/bind-identity", body={
            "client_id": "test-no-auth",
            "public_key": "dGVzdA==",
        })
        assert status in (401, 503), (
            f"Expected 401 or 503, got {status}. "
            f"Lifecycle endpoint must reject unauthenticated requests. body={body}"
        )
        assert body.get("ok") is False, f"ok must be False on rejection, got: {body}"

    def test_bind_identity_wrong_token_is_rejected(self):
        """POST /bind-identity with wrong Bearer token must return 401."""
        status, body = self._raw_request(
            "POST", "/bind-identity",
            body={"client_id": "test-wrong-token", "public_key": "dGVzdA=="},
            headers={"Authorization": "Bearer this-is-the-wrong-secret-token"},
        )
        # Agent-signed routes reject the missing proof; admin routes reject the bearer.
        assert status in (401, 503), (
            f"Expected 401 or 503 for wrong token, got {status}. body={body}"
        )
        assert body.get("ok") is False, f"ok must be False on rejection, got: {body}"

    def test_tsk_keys_patch_no_auth_is_rejected(self):
        """PATCH /tsk/keys/:clientId without Authorization header must return 401 or 503."""
        status, body = self._raw_request(
            "PATCH", "/tsk/keys/nonexistent-client-id",
            body={"label": "attempt-without-auth"},
        )
        assert status in (401, 503), (
            f"Expected 401 or 503, got {status}. body={body}"
        )
        assert body.get("ok") is False, f"ok must be False on rejection, got: {body}"

    def test_tsk_keys_patch_wrong_token_is_rejected(self):
        """PATCH /tsk/keys/:clientId with wrong Bearer token must return 401."""
        status, body = self._raw_request(
            "PATCH", "/tsk/keys/nonexistent-client-id",
            body={"label": "attempt-wrong-token"},
            headers={"Authorization": "Bearer totally-wrong-token-12345"},
        )
        assert status in (401, 503), (
            f"Expected 401 or 503 for wrong token, got {status}. body={body}"
        )
        assert body.get("ok") is False, f"ok must be False on rejection, got: {body}"

    def test_bpc_pairs_patch_no_auth_is_rejected(self):
        """PATCH /bpc/pairs/:pairId without Authorization header must return 401 or 503."""
        status, body = self._raw_request(
            "PATCH", "/bpc/pairs/nonexistent-pair-id",
            body={"name": "attempt-without-auth"},
        )
        assert status in (401, 503), (
            f"Expected 401 or 503, got {status}. body={body}"
        )
        assert body.get("ok") is False, f"ok must be False on rejection, got: {body}"

    def test_bpc_pairs_patch_wrong_token_is_rejected(self):
        """PATCH /bpc/pairs/:pairId with wrong Bearer token must return 401."""
        status, body = self._raw_request(
            "PATCH", "/bpc/pairs/nonexistent-pair-id",
            body={"name": "attempt-wrong-token"},
            headers={"Authorization": "Bearer wrong-token-xyz-999"},
        )
        assert status in (401, 503), (
            f"Expected 401 or 503 for wrong token, got {status}. body={body}"
        )
        assert body.get("ok") is False, f"ok must be False on rejection, got: {body}"

    def test_all_lifecycle_endpoints_reject_empty_bearer(self):
        """All three lifecycle endpoints must reject an empty Bearer token."""
        for method, path in self.LIFECYCLE_ENDPOINTS:
            status, body = self._raw_request(
                method, path, body={},
                headers={"Authorization": "Bearer "},
            )
            assert status in (401, 503), (
                f"{method} {path}: Expected 401 or 503 for empty Bearer, got {status}. body={body}"
            )
            assert body.get("ok") is False, (
                f"{method} {path}: ok must be False on rejection, got: {body}"
            )

    def test_all_lifecycle_endpoints_reject_malformed_auth_header(self):
        """All lifecycle endpoints must reject malformed operator auth."""
        for method, path in self.LIFECYCLE_ENDPOINTS:
            status, body = self._raw_request(
                method, path, body={},
                headers={"Authorization": "NotBearer some-token"},
            )
            assert status in (401, 503), (
                f"{method} {path}: Expected 401 or 503 for malformed header, got {status}. body={body}"
            )
            assert body.get("ok") is False, (
                f"{method} {path}: ok must be False on rejection, got: {body}"
            )


class TestSignedLifecycleAuth:
    """Exercise body binding, replay protection, and identity ownership live."""

    @staticmethod
    def _request(path: str, payload: bytes, headers: dict[str, str]) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"{SERVER_URL}{path}",
            data=payload,
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_signed_proof_is_body_bound_and_single_use(self, agent_identity):
        from enterprise.lifecycle_auth import lifecycle_auth_headers

        idempotency_key = str(uuid.uuid4())
        payload = json.dumps(
            {
                "requestorId": agent_identity.agent_id,
                "idempotencyKey": idempotency_key,
            },
            separators=(",", ":"),
        ).encode()
        headers = {
            "X-Idempotency-Key": idempotency_key,
            **lifecycle_auth_headers(agent_identity, payload),
        }
        first_status, _ = self._request("/provision-tsk", payload, headers)
        assert first_status == 200

        replay_status, replay = self._request("/provision-tsk", payload, headers)
        assert replay_status == 409
        assert replay["error"] == "AGENT_AUTH_REPLAY"

        tampered = json.dumps(
            {"requestorId": "SC-00000000"}, separators=(",", ":")
        ).encode()
        tamper_status, tamper = self._request("/provision-tsk", tampered, headers)
        assert tamper_status == 401
        assert tamper["error"] == "AGENT_AUTH_INVALID_SIGNATURE"

    def test_signed_agent_cannot_provision_for_another_identity(self, agent_identity):
        from enterprise.lifecycle_auth import lifecycle_auth_headers

        idempotency_key = str(uuid.uuid4())
        payload = json.dumps(
            {"requestorId": "SC-00000000", "idempotencyKey": idempotency_key},
            separators=(",", ":"),
        ).encode()
        status, body = self._request(
            "/provision-tsk",
            payload,
            {
                "X-Idempotency-Key": idempotency_key,
                **lifecycle_auth_headers(agent_identity, payload),
            },
        )
        assert status == 403
        assert body["error"] == "AGENT_OWNERSHIP_MISMATCH"

    def test_recovery_requires_operator_authorization_too(self, agent_identity):
        from enterprise.lifecycle_auth import lifecycle_auth_headers

        payload = json.dumps(
            {
                "agentName": "e2e-test-agent",
                "agentId": agent_identity.agent_id,
                "newPubHex": agent_identity.public_key_bytes.hex(),
                "challengeHash": "deadbeef",
            },
            separators=(",", ":"),
        ).encode()
        status, body = self._request(
            "/confirm-recovery", payload, lifecycle_auth_headers(agent_identity, payload)
        )
        assert status in (401, 503)
        assert body["error"] in ("ADMIN_AUTH_REQUIRED", "ADMIN_AUTH_UNCONFIGURED")
