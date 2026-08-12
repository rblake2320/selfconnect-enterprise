"""Single source of truth for tools that require delegated authorization."""

PROTECTED_DELEGATED_TOOLS = frozenset(
    {
        "sc_inject_text",
        "sc_read_output",
        "sc_request_lease",
        "sc_request_target_lease",
        "sc_revoke_lease",
        "sc_identity_sign",
        "sc_session_stamp",
        "sc_channel_route",
    }
)

