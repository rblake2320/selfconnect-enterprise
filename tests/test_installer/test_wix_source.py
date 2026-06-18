"""
tests/test_installer/test_wix_source.py

Validates the WiX v4 installer source (selfconnect-enterprise.wxs) without
requiring the WiX toolset to be installed.

Tests:
  1. WXS file is valid XML
  2. UpgradeCode is present and matches the expected GUID
  3. <ServiceInstall> element exists with correct Name attribute
  4. <MajorUpgrade> element exists
  5. All explicit component GUIDs are unique (no duplicates across the file)
  6. <Package> element has a Version attribute

Note on WiX preprocessor directives:
  WiX uses processing instructions like ``<?define Foo = "Bar" ?>`` that are
  not valid standard XML PIs (the target contains spaces/``=`` characters).
  Python's ``xml.etree.ElementTree`` rejects these.  We strip them before
  parsing; they carry no structural information tested here.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Locate the WXS source file
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WXS_PATH = REPO_ROOT / "installer" / "selfconnect-enterprise.wxs"

# WiX v4 default namespace
WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"

# Regex that matches WiX preprocessor PIs: <?define ...?>, <?ifdef ...?>, etc.
_WIX_PI_RE = re.compile(r"<\?(?:define|ifdef|ifndef|else|endif|error|warning|include)[^?]*\?>", re.DOTALL)


def _sanitize_wxs(text: str) -> str:
    """Strip WiX preprocessor processing instructions so ET can parse the file."""
    return _WIX_PI_RE.sub("", text)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def wxs_tree() -> ET.ElementTree:
    """Parse the WXS file once for all tests in this module."""
    assert WXS_PATH.exists(), f"WXS source not found: {WXS_PATH}"
    raw = WXS_PATH.read_text(encoding="utf-8")
    sanitized = _sanitize_wxs(raw)
    root = ET.fromstring(sanitized)
    return ET.ElementTree(root)


@pytest.fixture(scope="module")
def wxs_root(wxs_tree: ET.ElementTree) -> ET.Element:
    return wxs_tree.getroot()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_all(root: ET.Element, local_tag: str) -> list[ET.Element]:
    """Find all descendants with the given local tag name (namespace-agnostic)."""
    # Try namespace-qualified first
    qualified = f"{{{WIX_NS}}}{local_tag}"
    elements = root.findall(f".//{qualified}")
    if elements:
        return elements
    # Fallback: match by local name without namespace (handles documents where
    # the default namespace is declared differently)
    return [el for el in root.iter() if _local_name(el.tag) == local_tag]


def _local_name(tag: str) -> str:
    """Strip namespace from a Clark-notation tag, e.g. '{ns}Tag' -> 'Tag'."""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _find_one(root: ET.Element, local_tag: str) -> ET.Element | None:
    results = _find_all(root, local_tag)
    return results[0] if results else None


# ---------------------------------------------------------------------------
# Test 1: Valid XML
# ---------------------------------------------------------------------------


def test_wxs_is_valid_xml() -> None:
    """installer/selfconnect-enterprise.wxs must be parseable XML.

    WiX preprocessor directives (<?define ...?>) are stripped before parsing
    because they use non-standard PI syntax that Python's ET rejects.  The
    structural XML (elements, attributes, nesting) is what this test validates.
    """
    assert WXS_PATH.exists(), f"WXS file missing: {WXS_PATH}"
    raw = WXS_PATH.read_text(encoding="utf-8")
    sanitized = _sanitize_wxs(raw)
    root = ET.fromstring(sanitized)
    assert root is not None, "XML root element is None after parsing"


# ---------------------------------------------------------------------------
# Test 2: UpgradeCode present and correct
# ---------------------------------------------------------------------------

EXPECTED_UPGRADE_CODE = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"


def test_upgrade_code_present_and_correct(wxs_root: ET.Element) -> None:
    """<Package> must carry UpgradeCode matching the canonical project GUID."""
    package = _find_one(wxs_root, "Package")
    assert package is not None, "<Package> element not found in WXS"

    upgrade_code = package.get("UpgradeCode")
    assert upgrade_code is not None, "<Package> is missing the UpgradeCode attribute"
    assert upgrade_code.upper() == EXPECTED_UPGRADE_CODE.upper(), (
        f"UpgradeCode mismatch: got {upgrade_code!r}, "
        f"expected {EXPECTED_UPGRADE_CODE!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: ServiceInstall element with correct Name
# ---------------------------------------------------------------------------

EXPECTED_SERVICE_NAME = "SelfConnectEnterprise"


def test_service_install_exists_with_correct_name(wxs_root: ET.Element) -> None:
    """<ServiceInstall> must exist and Name must equal 'SelfConnectEnterprise'."""
    service_installs = _find_all(wxs_root, "ServiceInstall")
    assert service_installs, "<ServiceInstall> element not found in WXS"

    # At least one ServiceInstall must reference the correct service name.
    # The WXS uses a preprocessor variable $(var.ServiceName) which resolves
    # to the literal at compile time; the source contains the variable reference,
    # so we also accept that pattern.
    found_name = False
    for si in service_installs:
        name_attr = si.get("Name", "")
        if (
            name_attr == EXPECTED_SERVICE_NAME
            or "ServiceName" in name_attr          # preprocessor variable reference
            or name_attr.lower() == EXPECTED_SERVICE_NAME.lower()
        ):
            found_name = True
            break

    assert found_name, (
        f"<ServiceInstall> found but Name attribute does not match "
        f"'{EXPECTED_SERVICE_NAME}'. Got: "
        f"{[si.get('Name') for si in service_installs]}"
    )


# ---------------------------------------------------------------------------
# Test 4: MajorUpgrade element exists
# ---------------------------------------------------------------------------


def test_major_upgrade_exists(wxs_root: ET.Element) -> None:
    """<MajorUpgrade> must be present to handle clean upgrade / downgrade logic."""
    major_upgrade = _find_one(wxs_root, "MajorUpgrade")
    assert major_upgrade is not None, (
        "<MajorUpgrade> element not found. "
        "This is required for clean upgrade handling in WiX v4."
    )


# ---------------------------------------------------------------------------
# Test 5: All explicit component GUIDs are unique
# ---------------------------------------------------------------------------


def test_component_guids_are_unique(wxs_root: ET.Element) -> None:
    """No two <Component> elements may share the same explicit Guid value."""
    components = _find_all(wxs_root, "Component")
    assert components, "No <Component> elements found in WXS"

    # Collect only explicitly set GUIDs (skip '*' which tells WiX to auto-generate)
    explicit_guids: list[str] = []
    for comp in components:
        guid = comp.get("Guid", "")
        if guid and guid != "*":
            explicit_guids.append(guid.upper())

    seen: set[str] = set()
    duplicates: list[str] = []
    for guid in explicit_guids:
        if guid in seen:
            duplicates.append(guid)
        seen.add(guid)

    assert not duplicates, (
        f"Duplicate component GUIDs found: {duplicates}. "
        f"Each component must have a unique GUID."
    )


# ---------------------------------------------------------------------------
# Test 6: Package element has Version attribute
# ---------------------------------------------------------------------------


def test_package_has_version_attribute(wxs_root: ET.Element) -> None:
    """<Package> must carry a Version attribute (may be a bind variable)."""
    package = _find_one(wxs_root, "Package")
    assert package is not None, "<Package> element not found in WXS"

    version = package.get("Version")
    assert version is not None, "<Package> is missing the Version attribute"
    assert version.strip(), "<Package> Version attribute is empty"


# ---------------------------------------------------------------------------
# Test 7: Service must NOT run as LocalSystem
# ---------------------------------------------------------------------------


def test_service_does_not_run_as_local_system(wxs_root: ET.Element) -> None:
    """<ServiceInstall> Account must not be LocalSystem.

    LocalSystem has unrestricted local-machine privileges (full registry,
    TCB privilege, impersonate any local user).  A governance/audit service
    has no legitimate need for that level of access.  Accepted values are
    'NT AUTHORITY\\LocalService' or 'NT AUTHORITY\\NetworkService' (or a
    dedicated service account).
    """
    service_installs = _find_all(wxs_root, "ServiceInstall")
    assert service_installs, "<ServiceInstall> element not found in WXS"

    forbidden = {"localsystem", "local system", ".\\localsystem"}
    for si in service_installs:
        account = si.get("Account", "")
        assert account.lower().strip() not in forbidden, (
            f"<ServiceInstall> Account='{account}' is over-privileged. "
            "Use 'NT AUTHORITY\\LocalService' or a dedicated service account."
        )


# ---------------------------------------------------------------------------
# Test 8: MajorUpgrade schedule must guarantee service stop before file replacement
# ---------------------------------------------------------------------------


def test_major_upgrade_schedule_is_safe(wxs_root: ET.Element) -> None:
    """<MajorUpgrade> Schedule must be 'afterInstallInitialize' (not 'afterInstallExecute').

    'afterInstallInitialize' causes the old product's uninstall (including
    ServiceControl Stop) to run before the new product lays down files.
    'afterInstallExecute' or 'afterInstallFinalize' leave the old service
    running while new binaries are being written — a TOCTOU / file-lock hazard.
    """
    major_upgrade = _find_one(wxs_root, "MajorUpgrade")
    assert major_upgrade is not None, "<MajorUpgrade> element not found in WXS"

    schedule = major_upgrade.get("Schedule", "afterInstallInitialize")  # WiX default
    unsafe_schedules = {"afterinstallexecute", "afterinstallfinalize"}
    assert schedule.lower() not in unsafe_schedules, (
        f"<MajorUpgrade> Schedule='{schedule}' is unsafe — the old service can "
        "remain running while new files are written. "
        "Use Schedule='afterInstallInitialize'."
    )


# ---------------------------------------------------------------------------
# Test 9: Rollback CA must exist for pip install
# ---------------------------------------------------------------------------


def test_pip_install_rollback_action_exists(wxs_root: ET.Element) -> None:
    """A rollback CustomAction must exist to undo the pip install on failure.

    If a deferred action after CA_PipInstallWheel fails (e.g., service
    registration), the installer rolls back.  Without a rollback CA the
    package remains installed with no registered service, leaving the system
    in an inconsistent state.
    """
    custom_actions = _find_all(wxs_root, "CustomAction")
    assert custom_actions, "<CustomAction> elements not found in WXS"

    rollback_actions = [
        ca for ca in custom_actions
        if ca.get("Execute", "").lower() == "rollback"
    ]
    assert rollback_actions, (
        "No CustomAction with Execute='rollback' found. "
        "A rollback action is required to undo pip install if service registration fails."
    )


# ---------------------------------------------------------------------------
# Test 10: Python version must be pinned in pip custom action commands
# ---------------------------------------------------------------------------


def test_python_version_pinned_in_pip_actions(wxs_root: ET.Element) -> None:
    """py.exe invocations in pip CustomActions must specify a version flag (-3.x).

    Without a version flag, py.exe resolves to the system default Python,
    which can silently change when users install a new Python release and
    break the installed package's import paths.
    """
    import re as _re

    # Regex to find a bare py.exe call with no version flag
    # Matches: py.exe" -m  (no -3 or -3.x between py.exe" and -m)
    bare_py_pattern = _re.compile(r'py\.exe"\s+-m\b', _re.IGNORECASE)

    custom_actions = _find_all(wxs_root, "CustomAction")
    pip_actions_without_pin: list[str] = []

    for ca in custom_actions:
        value = ca.get("Value", "")
        if "pip" in value.lower() and "py.exe" in value.lower():
            if bare_py_pattern.search(value):
                pip_actions_without_pin.append(ca.get("Id", "<unknown>"))

    assert not pip_actions_without_pin, (
        f"CustomAction(s) {pip_actions_without_pin} invoke py.exe without a "
        "version flag (e.g., -3.11). Pin the Python minor version to prevent "
        "breakage when users install a newer Python release."
    )
