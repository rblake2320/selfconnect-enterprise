from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.provenance_admin import main
from enterprise.provenance_ipc import EnrollmentRegistry


def identity():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "SC-" + hashlib.sha256(public).hexdigest()[:8].upper(), public.hex()


def test_admin_enroll_list_replace_and_remove(tmp_path, capsys):
    path = tmp_path / "config" / "enrollments.json"
    agent_id, public_key = identity()
    assert main([
        "--file", str(path),
        "enroll",
        "--agent-id", agent_id,
        "--algorithm", "ed25519",
        "--public-key-hex", public_key,
        "--sid", "S-1-5-21-1-2-3-1001",
        "--supervisor",
    ]) == 0
    registry = EnrollmentRegistry.load(path)
    assert registry.supervisor_id == agent_id
    assert main(["--file", str(path), "list"]) == 0
    output = capsys.readouterr().out
    assert agent_id in output
    assert public_key not in output

    assert main([
        "--file", str(path),
        "enroll",
        "--agent-id", agent_id,
        "--algorithm", "ed25519",
        "--public-key-hex", public_key,
        "--sid", "S-1-5-21-1-2-3-1001",
        "--disabled",
    ]) == 0
    assert EnrollmentRegistry.load(path).get(agent_id) is None
    assert main(["--file", str(path), "remove", "--agent-id", agent_id]) == 0
    assert json.loads(path.read_text(encoding="ascii"))["agents"] == []


def test_admin_rejects_key_label_mismatch_without_modifying_file(tmp_path):
    path = tmp_path / "enrollments.json"
    path.write_text('{"agents":[],"version":1}\n', encoding="ascii")
    before = path.read_bytes()
    _agent_id, public_key = identity()
    with pytest.raises(Exception, match="agent_id does not match"):
        main([
            "--file", str(path),
            "enroll",
            "--agent-id", "SC-00000000",
            "--algorithm", "ed25519",
            "--public-key-hex", public_key,
            "--sid", "S-1-5-21-1-2-3-1001",
        ])
    assert path.read_bytes() == before
