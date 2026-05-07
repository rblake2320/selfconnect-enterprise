"""enterprise — SelfConnect Enterprise layer.

Win32 surface expansion for production, air-gapped, and compliance-regulated
AI agent deployments. Built on the SelfConnect SDK (sdk/ submodule).

Modules:
    registry       — SetProp/GetProp agent registry + BirthTag identity
    transport      — WM_COPYDATA structured payload transport
    coordination   — Named Events zero-polling sync (planned)
    hidden_desktop — CreateDesktop invisible execution (planned)
    observer_jsonl — Structured JSONL event logging (planned)
"""
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
