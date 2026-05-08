"""enterprise — SelfConnect Enterprise layer.

Win32 surface expansion for production, air-gapped, and compliance-regulated
AI agent deployments. Built on the SelfConnect SDK (sdk/ submodule).

Modules:
    registry       — SetProp/GetProp agent registry + BirthTag identity
    transport      — WM_COPYDATA structured payload transport
    identity       — Persistent machine-bound ed25519 agent identity (DPAPI)
    ledger         — Chained signed action log (tamper-evident)
    crypto         — FIPS-validated ECDSA P-384/SHA-384 via Windows CNG (NCrypt)
    policy         — Signed policy bundles + deny-by-default enforcer
    policy_sign    — CNG-signed policy bundle signing/verification
    operator       — Thread-safe operator approval queue
    coordination   — Named Events zero-polling sync (planned)
    hidden_desktop — CreateDesktop invisible execution (planned)
"""
from enterprise.control import AgentControlRecord, ControlPlane  # noqa: F401
from enterprise.crypto import CngSigner, cng_delete_key, cng_key_exists, cng_sha384, cng_verify  # noqa: F401
from enterprise.identity import AgentIdentity  # noqa: F401
from enterprise.identity_cng import CngIdentity, CngLedger  # noqa: F401
from enterprise.ledger import AgentLedger  # noqa: F401
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
from enterprise.transport import CopyDataListener  # noqa: F401
