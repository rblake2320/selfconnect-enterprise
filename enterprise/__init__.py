"""enterprise — SelfConnect Enterprise layer (Linux-compatible stub for testing).
This stub imports only the cross-platform modules. Windows-only modules
(crypto, identity, identity_cng, registry, transport, ledger, policy_sign)
are excluded on non-Windows because they have module-level ctypes.windll calls.
"""
import sys

# Cross-platform modules (no Win32 dependency at module level)
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
from enterprise.egress_guard import EgressGuard  # noqa: F401
from enterprise.export_guard import ExportGuard  # noqa: F401
from enterprise.labels import (
    ALLOWED_CAVEATS,  # noqa: F401
    CLASSIFICATION_LEVELS,  # noqa: F401
    Classification,  # noqa: F401
    LabelEnvelope,  # noqa: F401
)
from enterprise.labels import le as classification_le  # noqa: F401
from enterprise.labels import rank as classification_rank  # noqa: F401
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
from enterprise.discovery_config import (  # noqa: F401
    HANDSHAKE_BACKOFF_SEC,
    HANDSHAKE_TIMEOUT_MS,
    MAX_CANDIDATES_PER_CYCLE,
    MAX_STAMPS_PER_PID,
)
# Ultra identity gate — cross-platform (available on all OS)
from enterprise.identity_gate import (  # noqa: F401
    IdentityGate,
    IdentityGateDecision,
    MODE_AUDIT,
    MODE_BYPASS,
    MODE_ENFORCE,
    DEGRADATION_DESCRIPTIONS,
    emergency_bypass,
    get_identity_mode,
    guarded_send_string,
)
from enterprise.ultra_gate import (  # noqa: F401
    GateResult,
    InjectionDeniedError,
    UltraGate,
    UltraGateBootstrapError,
)
from enterprise.key_recovery import (  # noqa: F401
    KeyRecovery,
    PeerRecoveryDetector,
    recovery_pub_path,
)

# Windows-only modules — skip on non-Windows
if sys.platform == "win32":
    from enterprise.crypto import CngSigner, cng_delete_key, cng_key_exists, cng_sha384, cng_verify  # noqa: F401
    from enterprise.identity import AgentIdentity  # noqa: F401
    from enterprise.identity_cng import CngIdentity, CngLedger  # noqa: F401
    from enterprise.ledger import AgentLedger  # noqa: F401
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
    from enterprise.transport import CopyDataListener  # noqa: F401
