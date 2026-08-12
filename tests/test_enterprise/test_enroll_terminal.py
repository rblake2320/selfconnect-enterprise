from __future__ import annotations

from unittest.mock import patch

import enroll_terminal
from enterprise.identity import AgentIdentity


def _identity_storage(tmp_path):
    data_dir = tmp_path / "identities"
    cert_path = tmp_path / "terminal-birth-cert.json"
    return (
        data_dir,
        cert_path,
        patch.object(enroll_terminal, "_default_data_dir", return_value=data_dir),
        patch("enterprise.identity._default_data_dir", return_value=data_dir),
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda value: value[4:]),
        patch.object(enroll_terminal, "CERT_PATH", cert_path),
    )


def test_enrollment_reason_and_terminal_identity_are_truthful_and_stable(tmp_path):
    data_dir, cert_path, *patchers = _identity_storage(tmp_path)
    with patchers[0], patchers[1], patchers[2], patchers[3], patchers[4], patch.object(
        enroll_terminal.os, "getpid", return_value=100
    ):
        initial, identity, _ = enroll_terminal.enroll("terminal-test")
        enroll_terminal.write_cert(initial)

    assert initial["reason"] == "new enrollment"
    assert initial["terminal_id"] == identity.canonical_id
    assert initial["process_instance_id"].endswith("-100")
    assert AgentIdentity.verify(
        enroll_terminal.json.dumps(
            {name: value for name, value in initial.items() if name != "sig"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        bytes.fromhex(initial["sig"]),
        bytes.fromhex(initial["bpc_public_key_hex"]),
    )

    data_dir, cert_path, *patchers = _identity_storage(tmp_path)
    with patchers[0], patchers[1], patchers[2], patchers[3], patchers[4], patch.object(
        enroll_terminal.os, "getpid", return_value=101
    ):
        refreshed, _, _ = enroll_terminal.enroll("terminal-test")

    assert refreshed["reason"] == "certificate refresh for existing identity"
    assert refreshed["terminal_id"] == initial["terminal_id"]
    assert refreshed["process_instance_id"].endswith("-101")


def test_explicit_rotation_is_not_reported_as_accidental_deletion(tmp_path):
    _, _, *patchers = _identity_storage(tmp_path)
    with patchers[0], patchers[1], patchers[2], patchers[3], patchers[4]:
        initial, _, _ = enroll_terminal.enroll("terminal-rotate")
        enroll_terminal.write_cert(initial)
        rotated, _, _ = enroll_terminal.enroll("terminal-rotate", rotate=True)

    assert rotated["reason"] == "explicit key rotation"
    assert rotated["terminal_id"] != initial["terminal_id"]

