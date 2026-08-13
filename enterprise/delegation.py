"""Portable dual-signature delegation and action proofs.

An authority signs a narrowly scoped :class:`DelegationGrant`.  The delegated
agent then signs an :class:`AgentActionProof` that references the exact grant.
Verification keeps authorization and authorship distinct while binding both to
the same action, target, payload digest, mode, classification, and time window.

This module is transport-neutral.  It does not issue policy decisions, actuate
tools, persist revocation state, or replace the governed runtime.  Callers must
provide current revocation and replay state to :func:`verify_delegated_action`.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable, Mapping

from enterprise.identity import AgentIdentity

SCHEMA_VERSION = "selfconnect.delegation.v1"
RECEIPT_SCHEMA_VERSION = "selfconnect.delegated-result-receipt.v1"
ED25519 = "ed25519"
ECDSA_P384_SHA384 = "ecdsa-p384-sha384"
_HEX = frozenset("0123456789abcdef")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON, rejecting NaN and non-JSON values."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def payload_digest(payload: bytes) -> str:
    """Return the SHA-256 digest used to bind content without retaining it."""
    return hashlib.sha256(bytes(payload)).hexdigest()


def public_key_fingerprint(public_key: bytes) -> str:
    """Return a collision-resistant fingerprint for a principal public key."""
    return hashlib.sha256(bytes(public_key)).hexdigest()


def canonical_agent_id(public_key: bytes) -> str:
    """Full-key principal used for authorization and precise revocation."""
    return "SCID-" + public_key_fingerprint(public_key)


def _agent_id(public_key: bytes) -> str:
    return "SC-" + public_key_fingerprint(public_key)[:8].upper()


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _valid_digest(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX for ch in value)


def _valid_time(value: float) -> bool:
    return isinstance(value, (int, float)) and math.isfinite(float(value))


def _verify_signature(algorithm: str, public_key: bytes, data: bytes, signature: bytes) -> bool:
    if algorithm == ED25519:
        return AgentIdentity.verify(data, signature, public_key)
    if algorithm == ECDSA_P384_SHA384:
        from enterprise.crypto import cng_verify

        return cng_verify(data, signature, public_key)
    return False


def _signer_algorithm(signer: Any) -> str:
    public_key = bytes(signer.public_key_bytes)
    if len(public_key) == 32:
        return ED25519
    if len(public_key) == 96:
        return ECDSA_P384_SHA384
    raise ValueError("unsupported signer public key format")


def _bounded_text(name: str, value: str, *, maximum: int = 256) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{name} must not contain control characters")


def _normalise_json_object(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    normalised = json.loads(canonical_bytes(dict(value)).decode("utf-8"))
    if not isinstance(normalised, dict):
        raise ValueError(f"{name} must be an object")
    if len(canonical_bytes(normalised)) > 16_384:
        raise ValueError(f"{name} exceeds 16,384 canonical bytes")
    return normalised


@dataclass(frozen=True)
class DelegationGrant:
    """Authority-signed permission for one agent to perform bounded actions."""

    schema: str
    issuer_principal: str
    issuer_key_fingerprint: str
    subject_agent_id: str
    subject_public_key_hex: str
    allowed_actions: tuple[str, ...]
    target_constraints: dict[str, Any]
    governance_mode: str
    classification_ceiling: str
    issued_at: float
    not_before: float
    expires_at: float
    revocation_epoch: int
    nonce: str
    signature_algorithm: str
    issuer_public_key_hex: str
    signature_hex: str = ""

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_VERSION:
            raise ValueError("unsupported delegation schema")
        for name in (
            "issuer_principal", "subject_agent_id", "governance_mode",
            "classification_ceiling", "nonce",
        ):
            _bounded_text(name, getattr(self, name))
        if not self.allowed_actions or len(self.allowed_actions) > 128:
            raise ValueError("allowed_actions must contain 1 to 128 actions")
        for action in self.allowed_actions:
            _bounded_text("allowed action", action)
        if len(set(self.allowed_actions)) != len(self.allowed_actions):
            raise ValueError("allowed_actions must not contain duplicates")
        _normalise_json_object("target_constraints", self.target_constraints)
        if not all(_valid_time(value) for value in (self.issued_at, self.not_before, self.expires_at)):
            raise ValueError("delegation timestamps must be finite")
        if self.not_before < self.issued_at or self.expires_at <= self.not_before:
            raise ValueError("delegation time window is invalid")
        if not isinstance(self.revocation_epoch, int) or self.revocation_epoch < 0:
            raise ValueError("revocation_epoch must be a non-negative integer")
        if self.signature_algorithm not in {ED25519, ECDSA_P384_SHA384}:
            raise ValueError("unsupported signature algorithm")
        try:
            issuer_key = bytes.fromhex(self.issuer_public_key_hex)
            subject_key = bytes.fromhex(self.subject_public_key_hex)
            bytes.fromhex(self.signature_hex) if self.signature_hex else b""
        except ValueError as exc:
            raise ValueError("delegation key or signature encoding is invalid") from exc
        expected_length = 32 if self.signature_algorithm == ED25519 else 96
        if len(issuer_key) != expected_length or len(subject_key) != 32:
            raise ValueError("delegation public key length is invalid")
        if self.issuer_key_fingerprint != public_key_fingerprint(issuer_key):
            raise ValueError("issuer fingerprint does not match issuer public key")
        if self.subject_agent_id != _agent_id(subject_key):
            raise ValueError("subject agent id does not match subject public key")

    def unsigned_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature_hex", None)
        value["allowed_actions"] = list(self.allowed_actions)
        return value

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.unsigned_dict())

    @property
    def grant_id(self) -> str:
        """Stable digest of the authority-signed grant body."""
        return _digest(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["allowed_actions"] = list(self.allowed_actions)
        value["grant_id"] = self.grant_id
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DelegationGrant":
        raw = dict(value)
        supplied_id = raw.pop("grant_id", None)
        raw["allowed_actions"] = tuple(raw.get("allowed_actions", ()))
        grant = cls(**raw)
        if supplied_id is not None and supplied_id != grant.grant_id:
            raise ValueError("grant_id does not match delegation body")
        return grant


@dataclass(frozen=True)
class AgentActionProof:
    """Agent-authored action bound to one authority-signed delegation grant."""

    schema: str
    grant_id: str
    action_id: str
    agent_id: str
    agent_public_key_hex: str
    action: str
    target: dict[str, Any]
    payload_sha256: str
    governance_mode: str
    classification: str
    occurred_at: float
    signature_algorithm: str
    signature_hex: str = ""

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_VERSION:
            raise ValueError("unsupported action-proof schema")
        for name in ("action_id", "agent_id", "action", "governance_mode", "classification"):
            _bounded_text(name, getattr(self, name))
        if not _valid_digest(self.grant_id) or not _valid_digest(self.payload_sha256):
            raise ValueError("grant_id and payload_sha256 must be lowercase SHA-256 digests")
        _normalise_json_object("target", self.target)
        if not _valid_time(self.occurred_at):
            raise ValueError("occurred_at must be finite")
        if self.signature_algorithm != ED25519:
            raise ValueError("agent action proofs currently require Ed25519")
        try:
            public_key = bytes.fromhex(self.agent_public_key_hex)
            bytes.fromhex(self.signature_hex) if self.signature_hex else b""
        except ValueError as exc:
            raise ValueError("action key or signature encoding is invalid") from exc
        if len(public_key) != 32 or self.agent_id != _agent_id(public_key):
            raise ValueError("agent identity does not match action public key")

    def unsigned_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature_hex", None)
        return value

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.unsigned_dict())

    @property
    def proof_id(self) -> str:
        return _digest(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "proof_id": self.proof_id}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentActionProof":
        raw = dict(value)
        supplied_id = raw.pop("proof_id", None)
        proof = cls(**raw)
        if supplied_id is not None and supplied_id != proof.proof_id:
            raise ValueError("proof_id does not match action-proof body")
        return proof


@dataclass(frozen=True)
class DelegationVerification:
    """Structured, non-throwing verification result."""

    ok: bool
    reason: str
    grant_id: str = ""
    proof_id: str = ""
    issuer_principal: str = ""
    agent_id: str = ""


@dataclass(frozen=True)
class DelegatedActionReceipt:
    """Executing-agent signature over authorization, output, target, and ledger head."""

    schema: str
    receipt_id: str
    grant_id: str
    proof_id: str
    action_id: str
    delegated_agent_id: str
    agent_id: str
    agent_public_key_hex: str
    action: str
    target_sha256: str
    result_sha256: str
    result_status: str
    ledger_head: str
    issued_at: float
    signature_algorithm: str
    signature_hex: str = ""

    def __post_init__(self) -> None:
        if self.schema != RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported delegated receipt schema")
        for name in (
            "receipt_id", "action_id", "delegated_agent_id", "agent_id", "action", "result_status",
        ):
            _bounded_text(name, getattr(self, name))
        for name in ("grant_id", "proof_id", "target_sha256", "result_sha256", "ledger_head"):
            if not _valid_digest(getattr(self, name)):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not _valid_time(self.issued_at):
            raise ValueError("receipt timestamp must be finite")
        if self.signature_algorithm != ED25519:
            raise ValueError("delegated receipts require Ed25519")
        try:
            public_key = bytes.fromhex(self.agent_public_key_hex)
            bytes.fromhex(self.signature_hex) if self.signature_hex else b""
        except ValueError as exc:
            raise ValueError("receipt key or signature encoding is invalid") from exc
        if len(public_key) != 32 or self.agent_id != _agent_id(public_key):
            raise ValueError("receipt signer identity does not match public key")

    def unsigned_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature_hex", None)
        return value

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DelegatedActionReceipt":
        return cls(**dict(value))


def sign_delegated_receipt(
    *,
    grant: DelegationGrant,
    proof: AgentActionProof,
    agent_identity: AgentIdentity,
    result: Mapping[str, Any],
    result_status: str,
    ledger_head: str,
    issued_at: float,
) -> DelegatedActionReceipt:
    """Sign the final result with the executing runtime identity."""
    target_digest = _digest(_normalise_json_object("target", proof.target))
    result_digest = _digest(dict(result))
    receipt_id = _digest({
        "grant_id": grant.grant_id,
        "proof_id": proof.proof_id,
        "action_id": proof.action_id,
        "target_sha256": target_digest,
        "result_sha256": result_digest,
        "ledger_head": ledger_head,
    })
    receipt = DelegatedActionReceipt(
        schema=RECEIPT_SCHEMA_VERSION,
        receipt_id=receipt_id,
        grant_id=grant.grant_id,
        proof_id=proof.proof_id,
        action_id=proof.action_id,
        delegated_agent_id=proof.agent_id,
        agent_id=agent_identity.agent_id,
        agent_public_key_hex=agent_identity.public_key_bytes.hex(),
        action=proof.action,
        target_sha256=target_digest,
        result_sha256=result_digest,
        result_status=result_status,
        ledger_head=ledger_head,
        issued_at=issued_at,
        signature_algorithm=ED25519,
    )
    return replace(receipt, signature_hex=agent_identity.sign(receipt.signing_bytes()).hex())


def verify_delegated_receipt(
    receipt: DelegatedActionReceipt,
    *,
    expected_executor_public_key: bytes,
    expected_grant_id: str,
    expected_proof_id: str,
    expected_action_id: str,
    expected_action: str,
    expected_delegated_agent_id: str,
    expected_result_status: str,
    expected_target: Mapping[str, Any],
    expected_result: Mapping[str, Any] | None = None,
    expected_ledger_head: str | None = None,
) -> DelegationVerification:
    """Verify receipt authorship and optional result/ledger bindings."""
    base = {
        "grant_id": receipt.grant_id,
        "proof_id": receipt.proof_id,
        "agent_id": receipt.agent_id,
    }

    def fail(reason: str) -> DelegationVerification:
        return DelegationVerification(False, reason, **base)

    try:
        public_key = bytes.fromhex(receipt.agent_public_key_hex)
        signature = bytes.fromhex(receipt.signature_hex)
    except ValueError:
        return fail("receipt signature encoding is invalid")
    if public_key != bytes(expected_executor_public_key):
        return fail("receipt signer is not the trusted executor")
    if receipt.agent_id != _agent_id(bytes(expected_executor_public_key)):
        return fail("receipt executor identity does not match")
    if receipt.grant_id != expected_grant_id or receipt.proof_id != expected_proof_id:
        return fail("receipt authorization binding does not match")
    if receipt.action_id != expected_action_id or receipt.action != expected_action:
        return fail("receipt action binding does not match")
    if receipt.delegated_agent_id != expected_delegated_agent_id:
        return fail("receipt delegated-author binding does not match")
    if receipt.result_status != expected_result_status:
        return fail("receipt result status does not match")
    if receipt.target_sha256 != _digest(_normalise_json_object("target", expected_target)):
        return fail("receipt target digest does not match")
    expected_receipt_id = _digest({
        "grant_id": receipt.grant_id,
        "proof_id": receipt.proof_id,
        "action_id": receipt.action_id,
        "target_sha256": receipt.target_sha256,
        "result_sha256": receipt.result_sha256,
        "ledger_head": receipt.ledger_head,
    })
    if receipt.receipt_id != expected_receipt_id:
        return fail("receipt id does not match its bindings")
    if not receipt.signature_hex or not _verify_signature(
        receipt.signature_algorithm, public_key, receipt.signing_bytes(), signature
    ):
        return fail("receipt signature is invalid")
    if expected_result is not None and receipt.result_sha256 != _digest(dict(expected_result)):
        return fail("receipt result digest does not match")
    if expected_ledger_head is not None and receipt.ledger_head != expected_ledger_head:
        return fail("receipt ledger head does not match")
    return DelegationVerification(True, "ok", **base)


def issue_delegation_grant(
    *,
    signer: Any,
    issuer_principal: str,
    subject_public_key: bytes,
    allowed_actions: Iterable[str],
    target_constraints: Mapping[str, Any],
    governance_mode: str,
    classification_ceiling: str,
    issued_at: float,
    not_before: float,
    expires_at: float,
    revocation_epoch: int,
    nonce: str,
) -> DelegationGrant:
    """Create and sign a delegation grant with an Ed25519 or P-384 signer."""
    issuer_public_key = bytes(signer.public_key_bytes)
    subject_key = bytes(subject_public_key)
    grant = DelegationGrant(
        schema=SCHEMA_VERSION,
        issuer_principal=issuer_principal,
        issuer_key_fingerprint=public_key_fingerprint(issuer_public_key),
        subject_agent_id=_agent_id(subject_key),
        subject_public_key_hex=subject_key.hex(),
        allowed_actions=tuple(allowed_actions),
        target_constraints=_normalise_json_object("target_constraints", target_constraints),
        governance_mode=governance_mode,
        classification_ceiling=classification_ceiling,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        revocation_epoch=revocation_epoch,
        nonce=nonce,
        signature_algorithm=_signer_algorithm(signer),
        issuer_public_key_hex=issuer_public_key.hex(),
    )
    return replace(grant, signature_hex=bytes(signer.sign(grant.signing_bytes())).hex())


def sign_delegated_action(
    *,
    grant: DelegationGrant,
    agent_identity: AgentIdentity,
    action_id: str,
    action: str,
    target: Mapping[str, Any],
    payload: bytes,
    governance_mode: str,
    classification: str,
    occurred_at: float,
) -> AgentActionProof:
    """Create an agent-authored proof referencing the exact signed grant."""
    proof = AgentActionProof(
        schema=SCHEMA_VERSION,
        grant_id=grant.grant_id,
        action_id=action_id,
        agent_id=agent_identity.agent_id,
        agent_public_key_hex=agent_identity.public_key_bytes.hex(),
        action=action,
        target=_normalise_json_object("target", target),
        payload_sha256=payload_digest(payload),
        governance_mode=governance_mode,
        classification=classification,
        occurred_at=occurred_at,
        signature_algorithm=ED25519,
    )
    return replace(proof, signature_hex=agent_identity.sign(proof.signing_bytes()).hex())


def verify_delegated_action(
    grant: DelegationGrant,
    proof: AgentActionProof,
    *,
    now: float,
    payload: bytes | None = None,
    trusted_issuer_public_key: bytes | None = None,
    revoked_grant_ids: Iterable[str] = (),
    revoked_agent_key_ids: Iterable[str] = (),
    revoked_agent_ids: Iterable[str] = (),
    minimum_revocation_epoch: int = 0,
    seen_action_ids: Iterable[str] = (),
) -> DelegationVerification:
    """Verify authority, authorship, scope, time, revocation, and replay inputs.

    The function is deliberately non-mutating.  A caller must atomically record
    ``proof.action_id`` after success if replay protection spans calls/processes.
    """
    base = {
        "grant_id": grant.grant_id,
        "proof_id": proof.proof_id,
        "issuer_principal": grant.issuer_principal,
        "agent_id": proof.agent_id,
    }

    def fail(reason: str) -> DelegationVerification:
        return DelegationVerification(False, reason, **base)

    if not _valid_time(now):
        return fail("verification time is invalid")
    try:
        issuer_key = bytes.fromhex(grant.issuer_public_key_hex)
        grant_signature = bytes.fromhex(grant.signature_hex)
        agent_key = bytes.fromhex(proof.agent_public_key_hex)
        action_signature = bytes.fromhex(proof.signature_hex)
    except ValueError:
        return fail("signature encoding is invalid")
    if trusted_issuer_public_key is not None and issuer_key != bytes(trusted_issuer_public_key):
        return fail("delegation issuer is not the trusted authority")
    if not grant.signature_hex or not _verify_signature(
        grant.signature_algorithm, issuer_key, grant.signing_bytes(), grant_signature
    ):
        return fail("delegation authority signature is invalid")
    if proof.grant_id != grant.grant_id:
        return fail("action proof references a different delegation grant")
    if proof.agent_id != grant.subject_agent_id or agent_key.hex() != grant.subject_public_key_hex:
        return fail("action author is not the delegated subject")
    if not proof.signature_hex or not _verify_signature(
        proof.signature_algorithm, agent_key, proof.signing_bytes(), action_signature
    ):
        return fail("agent action signature is invalid")
    if float(now) < grant.not_before:
        return fail("delegation is not yet valid")
    if float(now) > grant.expires_at or proof.occurred_at > grant.expires_at:
        return fail("delegation is expired")
    if proof.occurred_at < grant.not_before or proof.occurred_at > float(now):
        return fail("action time is outside the delegation verification window")
    if grant.grant_id in set(revoked_grant_ids):
        return fail("delegation grant is revoked")
    # Compatibility callers may still use the old parameter name, but its
    # values are full SCID principals now; a short display ID cannot revoke.
    revoked_principals = set(revoked_agent_key_ids) | set(revoked_agent_ids)
    if canonical_agent_id(agent_key) in revoked_principals:
        return fail("delegated agent is revoked")
    if grant.revocation_epoch < minimum_revocation_epoch:
        return fail("delegation revocation checkpoint is stale")
    if proof.action_id in set(seen_action_ids):
        return fail("action id has already been consumed")
    if proof.action not in grant.allowed_actions:
        return fail("action is outside the delegated scope")
    if proof.governance_mode != grant.governance_mode:
        return fail("governance mode does not match delegation")
    if proof.classification != grant.classification_ceiling:
        return fail("classification is not authorized by this exact-match grant")
    for key, expected in grant.target_constraints.items():
        if key not in proof.target or proof.target[key] != expected:
            return fail(f"target constraint {key!r} does not match delegation")
    if payload is not None and proof.payload_sha256 != payload_digest(payload):
        return fail("payload digest does not match the action proof")
    return DelegationVerification(True, "ok", **base)


def verify_historical_delegated_action(
    grant: DelegationGrant,
    proof: AgentActionProof,
    *,
    payload: bytes | None = None,
    trusted_issuer_public_key: bytes | None = None,
) -> DelegationVerification:
    """Authenticate an already-completed action without current-state checks.

    Historical receipt recovery must still prove the owner's authority and the
    delegated agent's authorship.  It deliberately evaluates the immutable
    grant/proof pair at the proof's signed occurrence time, so later expiry or
    revocation does not erase an authentic completion record.
    """
    return verify_delegated_action(
        grant,
        proof,
        now=proof.occurred_at,
        payload=payload,
        trusted_issuer_public_key=trusted_issuer_public_key,
    )


__all__ = [
    "DelegatedActionReceipt",
    "AgentActionProof",
    "DelegationGrant",
    "DelegationVerification",
    "ECDSA_P384_SHA384",
    "ED25519",
    "SCHEMA_VERSION",
    "canonical_bytes",
    "canonical_agent_id",
    "issue_delegation_grant",
    "sign_delegated_receipt",
    "verify_delegated_receipt",
    "payload_digest",
    "public_key_fingerprint",
    "sign_delegated_action",
    "verify_delegated_action",
    "verify_historical_delegated_action",
]
