from __future__ import annotations

import base64
import hashlib
import json

import pytest
from enterprise.identity import AgentIdentity
from enterprise.lifecycle_auth import (
    LIFECYCLE_AUTH_AUDIENCE,
    LIFECYCLE_AUTH_DOMAIN,
    lifecycle_auth_headers,
)


def _material(payload: bytes, auth: dict[str, str]) -> bytes:
    return b"".join(
        (
            LIFECYCLE_AUTH_DOMAIN,
            auth["method"].encode("ascii"),
            b"\x00",
            auth["path"].encode("ascii"),
            b"\x00",
            auth["aud"].encode("ascii"),
            b"\x00",
            hashlib.sha256(payload).digest(),
            auth["ts"].encode("ascii"),
            b"\x00",
            auth["nonce"].encode("ascii"),
        )
    )


def test_lifecycle_proof_is_domain_method_path_and_audience_bound(tmp_path):
    identity = AgentIdentity.init("lifecycle-domain", data_dir=tmp_path)
    payload = b'{"requestorId":"SC-00000000"}'
    header = lifecycle_auth_headers(
        identity,
        payload,
        method="POST",
        path="/provision-tsk",
    )
    auth = json.loads(header["X-SC-Agent-Auth"])
    assert auth["aud"] == LIFECYCLE_AUTH_AUDIENCE
    assert identity.verify(
        _material(payload, auth),
        base64.b64decode(auth["sig"]),
        identity.public_key_bytes,
    )
    for field, value in (
        ("method", "GET"),
        ("path", "/bind-identity"),
        ("aud", "another-protocol"),
    ):
        altered = {**auth, field: value}
        assert not identity.verify(
            _material(payload, altered),
            base64.b64decode(auth["sig"]),
            identity.public_key_bytes,
        )


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/register-pair"), ("POST", "register-pair"), ("POST", "/x?y=1")],
)
def test_lifecycle_proof_rejects_ambiguous_endpoint(method, path, tmp_path):
    identity = AgentIdentity.init("lifecycle-invalid", data_dir=tmp_path)
    with pytest.raises(ValueError):
        lifecycle_auth_headers(identity, b"{}", method=method, path=path)
