"""Structural checks for the repository's documentation evidence records."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "LOG.md"
PARKED_PATH = ROOT / "PARKED.md"
WHY_PATH = ROOT / "WHY.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
README_PATH = ROOT / "README.md"
CATALOG_PATH = ROOT / "docs" / "assurance" / "control_catalog.json"
PROVENANCE_ACCEPTANCE_PATH = (
    ROOT / "docs" / "operations" / "2026-07-16-provenance-service-acceptance.json"
)
HA_TEST_COVERAGE_PATH = ROOT / "docs" / "assurance" / "ha_test_coverage.json"

LOG_ID_RE = re.compile(r"^## (LOG-\d{8}-\d{3})\b", re.MULTILINE)
PARK_ID_RE = re.compile(r"^## (PARK-\d{8}-\d{3})\b", re.MULTILINE)
WHY_ID_RE = re.compile(r"^## (WHY-\d{8}-\d{3})\b", re.MULTILINE)
LOG_REF_RE = re.compile(r"\bLOG-\d{8}-\d{3}\b")
PARK_REF_RE = re.compile(r"\bPARK-\d{8}-\d{3}\b")
WHY_REF_RE = re.compile(r"\bWHY-\d{8}-\d{3}\b")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _assert_unique(ids: list[str], record_type: str) -> None:
    assert len(ids) == len(set(ids)), f"duplicate {record_type} IDs: {ids}"


def test_record_files_are_linked_from_readme_and_changelog() -> None:
    readme = _read(README_PATH)
    changelog = _read(CHANGELOG_PATH)

    for target in ("(LOG.md)", "(WHY.md)", "(PARKED.md)"):
        assert target in readme
        assert target in changelog


def test_log_ids_are_unique_and_entries_have_required_fields() -> None:
    text = _read(LOG_PATH)
    matches = list(LOG_ID_RE.finditer(text))
    ids = [match.group(1) for match in matches]
    _assert_unique(ids, "log")
    assert ids, "LOG.md must contain at least one work-log entry"

    required = (
        "**Timestamp (UTC):**",
        "**Actor:**",
        "**Category:**",
        "**Base commit:**",
        "**Change reference:**",
        "**Why:**",
        "**Parked records:**",
        "**Changed:**",
        "**Reason:**",
        "**Full actions and links:**",
        "**Validation:**",
    )
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        entry = text[match.start() : end]
        missing = [field for field in required if field not in entry]
        assert not missing, f"{match.group(1)} missing fields: {missing}"


def test_parked_ids_are_unique() -> None:
    text = _read(PARKED_PATH)
    matches = list(PARK_ID_RE.finditer(text))
    ids = [match.group(1) for match in matches]
    _assert_unique(ids, "parked")

    required = (
        "**Status:**",
        "**Category:**",
        "**Former location:**",
        "**Source commit:**",
        "**Affected paths:**",
        "**Action log:**",
        "**Why changed:**",
        "**Parked by:**",
        "**Former wording:**",
        "**Recovery source:**",
        "**Reason parked:**",
        "**Replacement:**",
        "**Restore when:**",
        "**Restore procedure:**",
        "**Validation after restore:**",
        "**Recovery rehearsal:**",
        "**Restoration risks:**",
        "**Evidence and links:**",
    )
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        entry = text[match.start() : end]
        missing = [field for field in required if field not in entry]
        assert not missing, f"{match.group(1)} missing fields: {missing}"


def test_why_ids_are_unique_and_entries_have_recovery_fields() -> None:
    text = _read(WHY_PATH)
    matches = list(WHY_ID_RE.finditer(text))
    ids = [match.group(1) for match in matches]
    _assert_unique(ids, "why")
    assert ids, "WHY.md must contain at least one decision record"

    required = (
        "**Status:**",
        "**Decision date (UTC):**",
        "**Decision owner:**",
        "**Action log:**",
        "**Parked records:**",
        "**Source state:**",
        "**Decision:**",
        "**Why:**",
        "**Alternatives considered:**",
        "**Consequences:**",
        "**Rollback conditions:**",
        "**Evidence and links:**",
    )
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        entry = text[match.start() : end]
        missing = [field for field in required if field not in entry]
        assert not missing, f"{match.group(1)} missing fields: {missing}"


def test_cross_record_references_resolve() -> None:
    log_text = _read(LOG_PATH)
    parked_text = _read(PARKED_PATH)
    why_text = _read(WHY_PATH)
    changelog_text = _read(CHANGELOG_PATH)
    log_ids = set(LOG_ID_RE.findall(log_text))
    parked_ids = set(PARK_ID_RE.findall(parked_text))
    why_ids = set(WHY_ID_RE.findall(why_text))
    linked_text = "\n".join(
        (log_text, why_text, parked_text, changelog_text)
    )

    refs = (
        ("log", set(LOG_REF_RE.findall(linked_text)), log_ids),
        ("parked", set(PARK_REF_RE.findall(linked_text)), parked_ids),
        ("why", set(WHY_REF_RE.findall(linked_text)), why_ids),
    )
    for record_type, referenced, defined in refs:
        missing = referenced - defined
        assert not missing, f"missing {record_type} records: {sorted(missing)}"

    assert why_ids <= set(WHY_REF_RE.findall(log_text)), (
        "every decision record must be linked from LOG.md"
    )
    assert log_ids <= set(LOG_REF_RE.findall(why_text)), (
        "every action record must be linked from WHY.md"
    )
    if parked_ids:
        assert parked_ids <= set(PARK_REF_RE.findall(log_text))
        assert parked_ids <= set(PARK_REF_RE.findall(why_text))
        assert parked_ids <= set(PARK_REF_RE.findall(changelog_text))


def test_known_overclaims_and_partner_docs_remain_absent() -> None:
    assert not (ROOT / "docs" / "partnerships").exists()
    current_surfaces = [
        README_PATH,
        ROOT / "SECURITY.md",
        ROOT / "enterprise" / "crypto.py",
        ROOT / "enterprise" / "identity_cng.py",
        ROOT / "enterprise" / "identity_gate.py",
        ROOT / "enterprise" / "tpm_attestation.py",
        ROOT / "enterprise" / "ultra_gate.py",
        ROOT / "ultra_server" / "README.md",
        ROOT / "docs" / "assurance" / "SECTOR_PROFILES.md",
        ROOT / "TEST_REGISTRY.md",
    ]
    combined = "\n".join(_read(path).lower() for path in current_surfaces)
    prohibited = (
        "os-verified sender",
        "claims are documented and proved",
        "tumbler keys with structural secrecy",
        "il4-il7",
        "il4/il7",
        "every test ever written",
        "tests are real — no mocks",
        "fips-validated cryptographic primitives",
        "algorithm suite (cnsa 2.0 compliant)",
        "fully cnsa 2.0 compliant audit trail",
        "what this system guarantees",
        "**proven by:**",
        "concurrent safety proven by",
    )
    for phrase in prohibited:
        assert phrase not in combined


def test_control_catalog_has_required_control_fields() -> None:
    import json

    catalog = json.loads(_read(CATALOG_PATH))
    assert catalog["schema_version"] == 1
    controls = catalog["controls"]
    ids = [control["id"] for control in controls]
    _assert_unique(ids, "control")
    required = {"id", "title", "scope", "assertion", "expected", "evidence", "blind_spots", "tier"}
    for control in controls:
        assert not (required - control.keys()), control["id"]
        if control["tier"] == "description":
            assert "command" not in control
        else:
            assert control["tier"] in {"quick", "release", "live"}
            assert isinstance(control.get("command"), list) and control["command"]


def test_provenance_service_acceptance_artifact_is_bounded_and_redacted() -> None:
    import json

    evidence = json.loads(_read(PROVENANCE_ACCEPTANCE_PATH))
    assert evidence["schema"] == "selfconnect.provenance.acceptance-summary.v1"
    assert evidence["status"] == "implemented_and_exercised"
    assert all(evidence["lifecycle_checks"].values())
    assert all(evidence["enrolled_agent_checks"].values())
    assert evidence["source"]["wheel_source_mismatches"] == []
    assert evidence["recovery_evidence"]["concurrent_request_count"] == 40
    assert evidence["recovery_evidence"]["session_ledgers_verified"] == 42
    assert evidence["recovery_evidence"]["signed_events_verified"] == 168
    assert evidence["recovery_evidence"]["signed_session_index_entries_verified"] == 126
    assert evidence["blind_spots"]
    assert evidence["claim_boundary"]["not_established"]

    encoded = json.dumps(evidence).lower()
    prohibited = (
        "c:\\\\users\\\\",
        "c:\\\\programdata\\\\",
        "s-1-5-21-",
        "scpa-",
        "scpx-",
        "desktop-",
    )
    for value in prohibited:
        assert value not in encoded


def test_ha_test_coverage_never_hides_unexecuted_levels_as_passes() -> None:
    import json
    from urllib.parse import urlparse

    from tools.ci_test_gate import ALLOWED_SKIPS

    matrix = json.loads(_read(HA_TEST_COVERAGE_PATH))
    assert matrix["schema_version"] == 2
    assert matrix["authoritative_open_work"].endswith("/issues/28")
    standards = matrix["standards"]
    standard_ids = {entry["id"] for entry in standards}
    assert len(standard_ids) == len(standards)
    assert {urlparse(entry["url"]).hostname for entry in standards} <= {
        "csrc.nist.gov",
        "redis.io",
        "www.postgresql.org",
    }
    skip_groups = matrix["skip_groups"]
    assert {group["id"]: group["count"] for group in skip_groups} == {
        "generic-windows-ultra-unavailable": 34,
        "generic-windows-posix-semantics": 4,
    }
    assert sum("Ultra Server" in reason for reason in ALLOWED_SKIPS.values()) == 34
    assert sum("Ultra Server" not in reason for reason in ALLOWED_SKIPS.values()) == 4
    for group in skip_groups:
        assert set(group) == {
            "id",
            "count",
            "reason",
            "substitute",
            "non_equivalence",
            "closure",
        }
        assert group["count"] > 0
        assert all(
            group[field]
            for field in ("reason", "substitute", "non_equivalence", "closure")
        )

    expected_status = {
        "process-loss": "pass",
        "database-process-loss": "pass",
        "redis-functional-failover": "pass",
        "redis-independent-failure-domains": "open",
        "cross-host-handoff": "pass",
        "cross-host-service-network-partition": "partial",
        "whole-host-loss": "open",
        "alternate-site": "open",
        "authoritative-state-composition": "partial",
        "secret-reprovisioning": "partial",
        "replica-integrity-promotion-denial": "pass",
        "old-writer-fencing": "partial",
        "recovered-site-resync-before-write": "partial",
        "full-recovery-reconstitution": "partial",
        "backup-restore": "open",
        "enterprise-failback": "partial",
        "repeated-same-principal-failover": "partial",
        "monitoring-alerting": "partial",
        "immutable-evidence-deployment": "open",
        "key-custody": "partial",
        "independent-security-review": "partial",
        "rpo-rto-objectives": "partial",
        "cp4-related-plan-coordination": "open",
        "cp4-automated-testing": "partial",
        "cp4-self-challenge": "partial",
        "integration-test-skips": "pass",
    }
    levels = matrix["levels"]
    ids = [level["id"] for level in levels]
    _assert_unique(ids, "HA test level")
    required = {"id", "status", "requirement", "evidence", "limitations", "closure"}
    assert {level["status"] for level in levels} <= {"pass", "partial", "open"}
    assert "skip" not in {level["status"] for level in levels}
    for level in levels:
        assert set(level) == required
        assert level["requirement"] and level["limitations"]
        assert isinstance(level["evidence"], list) and level["evidence"]
        evidence_kinds = set()
        for evidence in level["evidence"]:
            kind, separator, reference = evidence.partition(":")
            assert separator and reference, f"malformed evidence: {evidence}"
            assert kind in {"artifact", "ci", "drill", "issue", "repo", "standard"}
            evidence_kinds.add(kind)
            if kind in {"artifact", "repo"}:
                path = reference.split("#", 1)[0]
                assert not Path(path).is_absolute()
                assert (ROOT / path).is_file(), f"missing evidence path: {path}"
            elif kind == "ci":
                parsed = urlparse(reference)
                assert parsed.scheme == "https" and parsed.hostname == "github.com"
                assert re.fullmatch(
                    r"/rblake2320/selfconnect-enterprise/actions/runs/\d+",
                    parsed.path,
                )
            elif kind == "issue":
                assert reference == matrix["authoritative_open_work"]
            elif kind == "standard":
                assert reference in standard_ids
            elif kind == "drill":
                assert re.fullmatch(r"sha256:[0-9a-f]{64}", reference)
        if level["status"] in {"partial", "open"}:
            assert level["closure"], f"{level['id']} has no closure condition"
        else:
            assert level["closure"] == ""
            assert evidence_kinds & {"artifact", "ci", "drill"}, (
                f"{level['id']} PASS lacks machine evidence"
            )

    status = {level["id"]: level["status"] for level in levels}
    assert status == expected_status
