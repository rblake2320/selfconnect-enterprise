"""One-way NIP-01 signed-event export for verified SelfConnect evidence.

This module does not connect to relays and does not accept events as authority.
NIP-01 requires a dedicated secp256k1 Schnorr signer; existing SelfConnect
Ed25519/P-384 identities are deliberately not relabeled as Nostr identities.
"""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, Sequence

if TYPE_CHECKING:
    from enterprise.observer import LedgerObserver

MAX_CONTENT_BYTES = 1_048_576
_RESERVED_TAGS = frozenset({"selfconnect-schema", "source-sha256"})


class NostrEventSigner(Protocol):
    """Dedicated NIP-01 signer using a 32-byte x-only secp256k1 public key."""

    @property
    def public_key_xonly(self) -> bytes: ...

    def sign_schnorr(self, event_id: bytes) -> bytes: ...


def export_verified_record(
    record: Mapping[str, Any],
    *,
    source_verifier: Callable[[Mapping[str, Any]], bool],
    signer: NostrEventSigner,
    created_at: int,
    kind: int,
    tags: Sequence[Sequence[str]] = (),
) -> dict[str, Any]:
    """Render a verified record as a signed NIP-01 event without publishing it."""
    if not isinstance(created_at, int) or isinstance(created_at, bool) or created_at < 0:
        raise ValueError("created_at must be a non-negative integer")
    if not isinstance(kind, int) or isinstance(kind, bool) or not 0 <= kind <= 65_535:
        raise ValueError("kind must be an integer from 0 through 65535")
    if not source_verifier(record):
        raise PermissionError("source record verification failed")

    normalized_tags = _validate_tags(tags)
    source = dict(record)
    source_bytes = _canonical_json(source)
    if len(source_bytes) > MAX_CONTENT_BYTES:
        raise ValueError("source record exceeds export size limit")
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    normalized_tags.extend(
        [
            ["selfconnect-schema", "selfconnect.nostr-evidence.v1"],
            ["source-sha256", source_hash],
        ]
    )
    content = _canonical_json(
        {
            "schema": "selfconnect.nostr-evidence.v1",
            "sourceSha256": source_hash,
            "record": source,
        }
    ).decode("utf-8")

    public_key = bytes(signer.public_key_xonly)
    if len(public_key) != 32:
        raise ValueError("Nostr signer must expose a 32-byte x-only public key")
    pubkey = public_key.hex()
    serialized = _canonical_json([0, pubkey, created_at, kind, normalized_tags, content])
    event_id_bytes = hashlib.sha256(serialized).digest()
    signature = bytes(signer.sign_schnorr(event_id_bytes))
    if len(signature) != 64:
        raise ValueError("Nostr signer must return a 64-byte Schnorr signature")
    return {
        "id": event_id_bytes.hex(),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": normalized_tags,
        "content": content,
        "sig": signature.hex(),
    }


def export_from_verified_observer(
    observer: LedgerObserver,
    *,
    signer: NostrEventSigner,
    kind: int,
    since_seq: int = 0,
) -> list[dict[str, Any]]:
    """Recommended production path from a verifier-bound LedgerObserver."""
    from enterprise.observer import LedgerObserver

    if type(observer) is not LedgerObserver:
        raise TypeError("Nostr export requires the exact LedgerObserver type")
    if observer._unsafe_unverified or observer._verifier is None:
        raise PermissionError("Nostr export requires a verifier-bound observer")
    records = observer.extract(since_seq=since_seq)
    events: list[dict[str, Any]] = []
    for record in records:
        events.append(
            export_verified_record(
                record.raw,
                source_verifier=lambda _record: True,
                signer=signer,
                created_at=int(record.ts),
                kind=kind,
                tags=[
                    ["source-seq", str(record.seq)],
                    ["source-agent", record.agent_id],
                    ["classification", record.classification],
                ],
            )
        )
    return events


def _validate_tags(tags: Sequence[Sequence[str]]) -> list[list[str]]:
    if isinstance(tags, (str, bytes)) or len(tags) > 128:
        raise ValueError("tags must be a bounded sequence")
    result: list[list[str]] = []
    for tag in tags:
        if isinstance(tag, (str, bytes)) or not tag or len(tag) > 16:
            raise ValueError("each tag must be a non-empty bounded string sequence")
        values = list(tag)
        if any(not isinstance(value, str) or len(value) > 1_024 for value in values):
            raise ValueError("tag values must be bounded strings")
        if values[0] in _RESERVED_TAGS:
            raise ValueError("caller cannot supply reserved export tags")
        result.append(values)
    return result


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("export value is not canonical JSON data") from exc


__all__ = [
    "MAX_CONTENT_BYTES",
    "NostrEventSigner",
    "export_from_verified_observer",
    "export_verified_record",
]
