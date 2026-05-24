"""enterprise — SelfConnect Enterprise layer.

Win32 surface expansion for production, air-gapped, and compliance-regulated
AI agent deployments. Built on the SelfConnect SDK (sdk/ submodule).

Modules:
    registry         — SetProp/GetProp agent registry + BirthTag identity
    transport        — WM_COPYDATA structured payload transport
    identity         — Persistent machine-bound ed25519 agent identity (DPAPI)
    ledger           — Chained signed action log (tamper-evident)
    crypto           — FIPS-validated ECDSA P-384/SHA-384 via Windows CNG (NCrypt)
    policy           — Signed policy bundles + deny-by-default enforcer
    policy_sign      — CNG-signed policy bundle signing/verification
    operator         — Thread-safe operator approval queue
    birth_tag_v2     — Signed birth tag stamper (Tier 1 — signer only)
    cache_bus        — Process-exit event bus for Tier 3 plugin invalidation
    discovery_config — Centralised discovery safety cap constants
    coordination     — Named Events zero-polling sync (planned)
    hidden_desktop   — CreateDesktop invisible execution (planned)
"""
from enterprise.birth_tag_v2 import (  # noqa: F401
    stamp_signed_birth_tag,
    verify_signed_birth_tag,
)
from enterprise.cache_bus import (  # noqa: F401
    callback_count,
    clear_all_callbacks,
    notify_process_exit,
    register_exit_callback,
    unregister_exit_callback,
)
from enterprise.classified_mode import ClassifiedModeProfile  # noqa: F401
from enterprise.control import AgentControlRecord, ControlPlane  # noqa: F401
from enterprise.crypto import CngSigner, cng_delete_key, cng_key_exists, cng_sha384, cng_verify  # noqa: F401
from enterprise.egress_guard import EgressGuard  # noqa: F401
from enterprise.export_guard import ExportGuard  # noqa: F401
from enterprise.identity import AgentIdentity  # noqa: F401
from enterprise.identity_cng import CngIdentity, CngLedger  # noqa: F401
from enterprise.labels import (
    ALLOWED_CAVEATS,  # noqa: F401
    CLASSIFICATION_LEVELS,  # noqa: F401
    Classification,  # noqa: F401
    LabelEnvelope,  # noqa: F401
)
from enterprise.labels import le as classification_le  # noqa: F401
from enterprise.labels import rank as classification_rank  # noqa: F401
from enterprise.ledger import AgentLedger, ThreadSafeAgentLedger  # noqa: F401
from enterprise.observer import (  # noqa: F401
    EvidenceExporter,
    EvidenceRecord,
    LedgerObserver,
    ObserverFilter,
    RedactionConfig,
    ShadowHook,
    TrainingTrigger,
)
from enterprise.operator import OperatorQueue, PendingApproval  # noqa: F401
from enterprise.policy import AgentPolicy, PolicyBundle, PolicyDecision, PolicyEnforcer, make_bundle  # noqa: F401
from enterprise.policy_sign import sign_policy, verify_policy_signature  # noqa: F401
from enterprise.registry import (  # noqa: F401
    BirthTag,
    HeartbeatDaemon,
    discover_mesh,
    find_agent,
    read_birth_tag,
    send_data,
    signal_ready,
    stamp_birth_tag,
    update_heartbeat,
    wait_for,
)
from enterprise.discovery_config import (  # noqa: F401
    HANDSHAKE_BACKOFF_SEC,
    HANDSHAKE_TIMEOUT_MS,
    MAX_CANDIDATES_PER_CYCLE,
    MAX_STAMPS_PER_PID,
)
from enterprise.transport import CopyDataListener  # noqa: F401
from enterprise.bpc_crypto import (  # noqa: F401
    b64url,
    b64url_decode,
    body_hash,
    canonicalize,
    compute_fingerprint,
    constant_time_equal,
    derive_p256_from_ed25519,
    generate_nonce,
    hash_secret,
    hmac_derive,
    p256_public_key_to_jwk,
    sign_payload,
    verify_payload_with_jwk,
)
from enterprise.tsk_client import (  # noqa: F401
    TSKClientState,
    SegmentConfig,
    commit_hotp_counter,
    compute_checksum,
    derive_segment_value,
    generate_tsk_key,
    parse_provision_payload,
    validate_hex_secret,
)
from enterprise.ultra_gate import (  # noqa: F401
    UltraGate,
    InjectionDeniedError,
    UltraGateNotBootstrappedError,
)
from enterprise.identity_gate import (  # noqa: F401
    get_current_mode,
    gated_send_string,
    emergency_bypass,
    release_bypass,
    DegradationCascade,
    MODE_BYPASS,
    MODE_AUDIT,
    MODE_ENFORCE,
)
from enterprise.key_recovery import (  # noqa: F401
    RecoveryManager,
    check_peer_recovery,
    update_peer_registry_from_recovery,
    RECOVERY_WINDOW_SEC,
)
from enterprise.discovery_config import (  # noqa: F401
    IDENTITY_BRIDGE_TIMEOUT_MS,
    IDENTITY_MODE_DEFAULT,
    ULTRA_SERVER_URL,
)
