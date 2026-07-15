"""enterprise/mcp_tools.py — MCP-compatible tool registry for SelfConnect Enterprise.

Each tool definition is compatible with the Model Context Protocol (MCP) tool schema:
  {"name": str, "description": str, "inputSchema": {...JSON Schema object...}}

These tools expose the governed OS-native AI peer mesh via MCP. Every actuating tool
(inject, route, channel operations) requires an active channel lease and produces an
audit receipt. Identity is OS-verified, not API-key-asserted.

Security properties enforced in this schema layer:
  - All string inputs that reach OS/crypto/audit sinks carry maxLength and/or pattern.
  - All integer inputs that bound queries or timeouts carry maximum.
  - sc_pipe_ping.pipe_name is restricted to local named pipes (\\\\.\\pipe\\...) only.
  - sc_receipt_verify.expected_agent_pub_b64 is required — absent key = no sig check = fail-open.
  - sc_request_lease.agent_id is required — leases without identity are unauditable.
  - sc_audit_search.limit carries a maximum to prevent unbounded audit dumps.
  - get_tool_registry() and get_tool() return deep-copied dicts — callers cannot mutate
    the live schema registry through the returned objects.
"""
from __future__ import annotations

import copy
from typing import Any

# ── Shared constraint constants ────────────────────────────────────────────────
# These are the authoritative bounds for every field type. Executors MUST also
# enforce these independently; the schema is the first line of defence, not the only one.

_LEASE_ID_MAX   = 128    # UUID-style lease identifiers
_AGENT_ID_MAX   = 128    # SC-XXXXXXXX style identifiers
_EVENT_TYPE_MAX = 64     # short event type tokens
_REASON_MAX     = 512    # human-readable reason strings
_HEX_MAX        = 1024   # hex-encoded hash/sig inputs (512 bytes → 1024 hex chars)
_B64_MAX        = 1024   # base64-encoded sig/key inputs (~768 bytes → 1024 b64 chars)
_ISO_MAX        = 32     # ISO 8601 timestamp strings
_EXE_NAME_MAX   = 260    # Windows MAX_PATH for exe names
_TEXT_MAX       = 65535  # WM_CHAR injection text ceiling (documented in description)
_RAW_TEXT_MAX   = 131072 # 128 KB for terminal readback buffers
_RECEIPT_MAX    = 8192   # JSON-serialised ActionReceipt (generous but bounded)
_BIRTH_ID_MAX   = 128    # birth_id tokens
_PIPE_NAME_MAX  = 256    # \\.\pipe\<name> — 256 chars covers all valid local pipe names

# Win32 HWND is a 32-bit value on all architectures (WOW64/native); valid range 0x0001–0xFFFF_FFFE.
_HWND_MAX       = 0xFFFFFFFE

# Pattern for local named pipes only: \\.\pipe\<name>
# Blocks: UNC remote paths (\\server\pipe\), path traversal (..), and bare names.
_PIPE_NAME_PATTERN = r"^\\\\\.\\pipe\\[A-Za-z0-9_\-\.]{1,200}$"

# Pattern for lease IDs: UUID or SC-hex forms.
_LEASE_ID_PATTERN = r"^[A-Za-z0-9_\-]{1,128}$"

# Pattern for agent IDs: SC-XXXXXXXX or slug forms.
_AGENT_ID_PATTERN = r"^[A-Za-z0-9_\-]{1,128}$"

# Pattern for hex-encoded bytes: lowercase/uppercase hex digits only.
_HEX_PATTERN = r"^[0-9A-Fa-f]+$"

# Pattern for base64 strings (standard + URL-safe alphabets, with optional padding).
_B64_PATTERN = r"^[A-Za-z0-9+/\-_]+=*$"

# Pattern for ISO 8601 timestamps: YYYY-MM-DDTHH:MM:SS[.ffffff][Z|±HH:MM]
_ISO_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"

# Pattern for event type tokens: lowercase alphanumeric with hyphens.
_EVENT_TYPE_PATTERN = r"^[a-z][a-z0-9\-]{0,62}$"


_TOOLS: list[dict[str, Any]] = [
    {
        "name": "sc_inject_text",
        "description": (
            "Inject text to a verified terminal target via WM_CHAR PostMessage. "
            "Requires an active channel lease. Target must pass fail-closed HWND/PID/class checks. "
            "Returns success only after UIA readback confirms a new visible payload occurrence."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["lease_id", "hwnd", "text"],
            "additionalProperties": False,
            "properties": {
                "lease_id": {
                    "type": "string",
                    "description": "Active channel lease ID",
                    "maxLength": _LEASE_ID_MAX,
                    "pattern": _LEASE_ID_PATTERN,
                },
                "hwnd": {
                    "type": "integer",
                    "description": "Target window handle",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "text": {
                    "type": "string",
                    "description": f"Text to inject (max {_TEXT_MAX} chars)",
                    "minLength": 1,
                    "maxLength": _TEXT_MAX,
                },
                "delivery_timeout_ms": {
                    "type": "integer",
                    "default": 3000,
                    "description": "Maximum wait for UIA echo confirmation",
                    "minimum": 100,
                    "maximum": 10000,
                },
                "classification": {
                    "type": "string",
                    "enum": ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"],
                    "description": "Classification label for the payload; required in government profile",
                },
                "approval_id": {
                    "type": "string",
                    "maxLength": 64,
                    "pattern": r"^[A-Za-z0-9-]+$",
                    "description": "Approved OperatorQueue request bound to this agent and action",
                },
                "echo_filter": {
                    "type": "boolean",
                    "default": True,
                    "description": "Strip injected text from readback",
                },
            },
        },
    },
    {
        "name": "sc_read_output",
        "description": (
            "Read terminal output via UIA TextPattern. Echo-filtered: injected text is stripped "
            "so only true peer/model output is returned. Returns delta since last read."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["lease_id", "hwnd"],
            "additionalProperties": False,
            "properties": {
                "lease_id": {
                    "type": "string",
                    "maxLength": _LEASE_ID_MAX,
                    "pattern": _LEASE_ID_PATTERN,
                },
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "timeout_ms": {
                    "type": "integer",
                    "default": 5000,
                    "description": "Max wait for new output",
                    "minimum": 100,
                    "maximum": 30000,
                },
                "strip_ansi": {"type": "boolean", "default": True},
                "classification": {
                    "type": "string",
                    "enum": ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"],
                    "default": "UNCLASSIFIED",
                    "description": "Classification label used by the mandatory policy gate",
                },
                "approval_id": {
                    "type": "string",
                    "maxLength": 64,
                    "pattern": r"^[A-Za-z0-9-]+$",
                    "description": "One-time approved request bound to this exact read context",
                },
            },
        },
    },
    {
        "name": "sc_verify_target",
        "description": (
            "Run all fail-closed target guard checks: HWND valid, PID matches, exe matches, "
            "window class is a known terminal, title matches expected. Returns guard report."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["hwnd"],
            "additionalProperties": False,
            "properties": {
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "expected_exe": {
                    "type": "string",
                    "description": "Expected executable name (e.g. WindowsTerminal.exe)",
                    "maxLength": _EXE_NAME_MAX,
                },
                "expected_class": {
                    "type": "string",
                    "description": "Expected window class",
                    "maxLength": 256,
                },
                "expected_pid": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4194304,
                },
            },
        },
    },
    {
        "name": "sc_request_lease",
        "description": (
            "Request a channel lease for a target HWND. The lease binds: agent SID, target HWND, "
            "window class, birth_id, generation, and role. Lease is short-lived and must be renewed. "
            "agent_id is required — leases without an explicit agent identity cannot be audited."
        ),
        "inputSchema": {
            "type": "object",
            # SECURITY FIX (HIGH — IDENTITY BYPASS): agent_id added to required.
            # Previously optional, allowing unauthenticated/unauditable lease requests.
            "required": ["hwnd", "role", "agent_id"],
            "additionalProperties": False,
            "properties": {
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "role": {
                    "type": "string",
                    "enum": ["sender", "receiver", "observer"],
                    "description": "Channel role",
                },
                "ttl_seconds": {
                    "type": "integer",
                    "default": 300,
                    "minimum": 30,
                    "maximum": 3600,
                },
                "agent_id": {
                    "type": "string",
                    "description": "Requesting agent identifier (required for audit binding)",
                    "maxLength": _AGENT_ID_MAX,
                    "pattern": _AGENT_ID_PATTERN,
                },
            },
        },
    },
    {
        "name": "sc_revoke_lease",
        "description": "Revoke an active channel lease. The lease holder or an authorized admin may revoke.",
        "inputSchema": {
            "type": "object",
            "required": ["lease_id"],
            "additionalProperties": False,
            "properties": {
                "lease_id": {
                    "type": "string",
                    "maxLength": _LEASE_ID_MAX,
                    "pattern": _LEASE_ID_PATTERN,
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for revocation (logged to audit)",
                    "maxLength": _REASON_MAX,
                },
            },
        },
    },
    {
        "name": "sc_list_leases",
        "description": "List all active channel leases. Returns lease IDs, holders, targets, roles, and TTLs.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "filter_role": {
                    "type": "string",
                    "enum": ["sender", "receiver", "observer", "all"],
                    "default": "all",
                },
                "filter_agent_id": {
                    "type": "string",
                    "maxLength": _AGENT_ID_MAX,
                    "pattern": _AGENT_ID_PATTERN,
                },
                "include_expired": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "sc_get_lease_info",
        "description": "Get detailed information about a specific channel lease.",
        "inputSchema": {
            "type": "object",
            "required": ["lease_id"],
            "additionalProperties": False,
            "properties": {
                "lease_id": {
                    "type": "string",
                    "maxLength": _LEASE_ID_MAX,
                    "pattern": _LEASE_ID_PATTERN,
                },
            },
        },
    },
    {
        "name": "sc_audit_tail",
        "description": "Return the most recent N audit events. Events include: inject, read, verify, lease, revoke, guard-fail.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "n": {"type": "integer", "default": 20, "minimum": 1, "maximum": 1000},
                "event_type": {
                    "type": "string",
                    "description": "Filter by event type",
                    "maxLength": _EVENT_TYPE_MAX,
                    "pattern": _EVENT_TYPE_PATTERN,
                },
            },
        },
    },
    {
        "name": "sc_audit_search",
        "description": "Search the audit log by agent_id, target HWND, event type, or time range.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "agent_id": {
                    "type": "string",
                    "maxLength": _AGENT_ID_MAX,
                    "pattern": _AGENT_ID_PATTERN,
                },
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "event_type": {
                    "type": "string",
                    "maxLength": _EVENT_TYPE_MAX,
                    "pattern": _EVENT_TYPE_PATTERN,
                },
                "since_iso": {
                    "type": "string",
                    "description": "ISO 8601 timestamp lower bound",
                    "maxLength": _ISO_MAX,
                    "pattern": _ISO_PATTERN,
                },
                "until_iso": {
                    "type": "string",
                    "description": "ISO 8601 timestamp upper bound",
                    "maxLength": _ISO_MAX,
                    "pattern": _ISO_PATTERN,
                },
                # SECURITY FIX (HIGH — MISSING VALIDATION): limit now has a maximum.
                # Previously unbounded — a caller could request limit=99999999 and
                # trigger a massive audit log dump.
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "minimum": 1,
                    "maximum": 1000,
                },
            },
        },
    },
    {
        "name": "sc_mesh_peers",
        "description": "List active mesh peers: agent IDs, OS-verified SIDs, channel roles, and connection status.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "include_offline": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "sc_channel_status",
        "description": (
            "Report availability of each channel type: WM_CHAR (PostMessage), UIA TextPattern, "
            "ETW ConsoleHost, DACL named pipe. Returns health per channel."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "check_etw": {
                    "type": "boolean",
                    "default": True,
                    "description": "Probe ETW session availability",
                },
            },
        },
    },
    {
        "name": "sc_target_guard_check",
        "description": (
            "Run all target guard checks without injecting. Returns pass/fail for each check: "
            "HWND valid, PID live, exe match, class match, title match, birth_id match, generation match."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["hwnd"],
            "additionalProperties": False,
            "properties": {
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "birth_id": {
                    "type": "string",
                    "description": "Expected birth_id (from sc_session_stamp)",
                    "maxLength": _BIRTH_ID_MAX,
                },
                "generation": {
                    "type": "integer",
                    "description": "Expected session generation counter",
                    "minimum": 0,
                    "maximum": 4294967295,
                },
            },
        },
    },
    {
        "name": "sc_identity_sign",
        "description": "Sign a payload hash with the agent's CNG/TPM-backed identity key. Returns signature (base64) and public key.",
        "inputSchema": {
            "type": "object",
            "required": ["payload_hex"],
            "additionalProperties": False,
            "properties": {
                "payload_hex": {
                    "type": "string",
                    "description": "Hex-encoded bytes to sign",
                    "maxLength": _HEX_MAX,
                    "pattern": _HEX_PATTERN,
                },
                "key_provider": {
                    "type": "string",
                    "enum": ["software", "tpm"],
                    "default": "software",
                },
            },
        },
    },
    {
        "name": "sc_identity_verify",
        "description": "Verify a signed payload against a peer's public key. Returns verified=true/false.",
        "inputSchema": {
            "type": "object",
            "required": ["payload_hex", "signature_b64", "public_key_b64"],
            "additionalProperties": False,
            "properties": {
                "payload_hex": {
                    "type": "string",
                    "maxLength": _HEX_MAX,
                    "pattern": _HEX_PATTERN,
                },
                "signature_b64": {
                    "type": "string",
                    "maxLength": _B64_MAX,
                    "pattern": _B64_PATTERN,
                },
                "public_key_b64": {
                    "type": "string",
                    "maxLength": _B64_MAX,
                    "pattern": _B64_PATTERN,
                },
                "algorithm": {
                    "type": "string",
                    "enum": ["ECDSA-P256", "ECDSA-P384", "Ed25519"],
                    "default": "ECDSA-P256",
                },
            },
        },
    },
    {
        "name": "sc_session_stamp",
        "description": (
            "Stamp a new session with a hardware birth_id. The stamp binds: process PID, HWND, "
            "window class, executable path hash, and a timestamp. Used as the anchor for generation tracking."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["hwnd"],
            "additionalProperties": False,
            "properties": {
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "use_tpm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include TPM attestation in stamp",
                },
            },
        },
    },
    {
        "name": "sc_channel_route",
        "description": (
            "Classify a target and return the recommended channel type. "
            "Terminal windows → WM_CHAR. Browser windows → UIA Value/Invoke. "
            "Sidecar control planes → named pipe. Unknown → deny."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["hwnd"],
            "additionalProperties": False,
            "properties": {
                "hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "preferred_channel": {
                    "type": "string",
                    "enum": ["auto", "wm_char", "uia", "pipe"],
                    "default": "auto",
                },
            },
        },
    },
    {
        "name": "sc_echo_filter",
        "description": "Apply echo filter to raw terminal output. Strips SC_PROBE tokens and injected text. Returns clean peer output.",
        "inputSchema": {
            "type": "object",
            "required": ["raw_text", "injected_text"],
            "additionalProperties": False,
            "properties": {
                "raw_text": {
                    "type": "string",
                    "description": "Raw terminal readback",
                    "maxLength": _RAW_TEXT_MAX,
                },
                "injected_text": {
                    "type": "string",
                    "description": "The text that was injected",
                    "maxLength": _TEXT_MAX,
                },
                "probe_token": {
                    "type": "string",
                    "description": "SC_PROBE token used for echo detection",
                    "maxLength": 256,
                },
            },
        },
    },
    {
        "name": "sc_pipe_ping",
        "description": (
            "Ping a local named pipe channel to verify it is live and responding. Returns latency_ms. "
            "Only local named pipes (\\\\.\\ pipe\\<name>) are accepted — remote UNC paths are rejected."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["pipe_name"],
            "additionalProperties": False,
            "properties": {
                # SECURITY FIX (CRITICAL — INJECTION): pipe_name now has maxLength and a
                # pattern that restricts input to local Win32 named pipes only.
                # Without this, an attacker can supply a UNC remote path
                # (\\evil-host\pipe\sc-control) or a path-traversal sequence to reach
                # arbitrary pipes including remote ones, bypassing the DACL model.
                "pipe_name": {
                    "type": "string",
                    "description": (
                        "Local named pipe path — must match \\\\.\\pipe\\<name> exactly. "
                        "Remote UNC paths and path traversal sequences are rejected."
                    ),
                    "maxLength": _PIPE_NAME_MAX,
                    "pattern": _PIPE_NAME_PATTERN,
                },
                "timeout_ms": {
                    "type": "integer",
                    "default": 1000,
                    "minimum": 100,
                    "maximum": 10000,
                },
            },
        },
    },
    {
        "name": "sc_policy_check",
        "description": "Check whether an action is permitted under the current policy configuration. Returns allowed=true/false and the policy rule that applied.",
        "inputSchema": {
            "type": "object",
            "required": ["action_type", "agent_id", "target_hwnd"],
            "additionalProperties": False,
            "properties": {
                "action_type": {
                    "type": "string",
                    "enum": ["inject", "read", "lease", "revoke", "admin"],
                },
                "agent_id": {
                    "type": "string",
                    "maxLength": _AGENT_ID_MAX,
                    "pattern": _AGENT_ID_PATTERN,
                },
                "target_hwnd": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _HWND_MAX,
                },
                "classification": {
                    "type": "string",
                    "description": "Data classification label",
                    "enum": ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"],
                },
            },
        },
    },
    {
        "name": "sc_receipt_verify",
        "description": (
            "Verify an agent signature over the receipt's payload_hex. This does not establish "
            "delivery, UIA readback, or semantic consistency of other receipt fields. "
            "expected_agent_pub_b64 is required — omitting it would skip signature verification "
            "and cause this tool to fail open."
        ),
        "inputSchema": {
            "type": "object",
            # SECURITY FIX (CRITICAL — FAIL-OPEN): expected_agent_pub_b64 added to required.
            # Previously optional — a caller that omits the trusted public key causes the
            # executor to skip signature verification, accepting any receipt as valid.
            "required": ["receipt_json", "expected_agent_pub_b64"],
            "additionalProperties": False,
            "properties": {
                "receipt_json": {
                    "type": "string",
                    "description": "JSON object containing payload_hex and its agent signature",
                    "maxLength": _RECEIPT_MAX,
                },
                "expected_agent_pub_b64": {
                    "type": "string",
                    "description": "Expected agent public key for sig verification (required — no key = no sig check)",
                    "maxLength": _B64_MAX,
                    "pattern": _B64_PATTERN,
                },
            },
        },
    },
]

TOOL_COUNT = len(_TOOLS)
# Internal index: NOT exposed directly — callers must use get_tool() which returns a copy.
_TOOL_INDEX: dict[str, dict] = {t["name"]: t for t in _TOOLS}


def get_tool_registry() -> list[dict]:
    """Return all registered MCP tool definitions.

    Returns a deep copy of the registry so callers cannot mutate the live
    schema definitions through the returned objects.  This prevents a
    concurrent-mutation race in multi-threaded MCP dispatchers.
    """
    return copy.deepcopy(_TOOLS)


def get_tool(name: str) -> dict:
    """Return a single tool definition by name.

    Returns a deep copy so callers cannot mutate the live schema through
    the returned dict.

    Raises KeyError if the tool is not registered.
    """
    try:
        return copy.deepcopy(_TOOL_INDEX[name])
    except KeyError:
        raise KeyError(f"Unknown MCP tool: {name!r}. Available: {sorted(_TOOL_INDEX)}")
