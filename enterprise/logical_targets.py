"""Immutable logical aliases for the existing governed terminal lease path.

Aliases are trusted startup configuration.  They do not replace the canonical
Win32 target guard: every enumerated candidate is checked by that guard and a
resolution succeeds only when exactly one live terminal matches the complete
configured identity selector.
"""
from __future__ import annotations

import ctypes
import hashlib
import ntpath
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping


_LOGICAL_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VALID_ROLES = frozenset({"sender", "receiver", "observer"})
_HWND_MAX = 0xFFFFFFFE
_CANDIDATE_LIMIT = 4096


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


class LogicalTargetError(RuntimeError):
    """A logical target cannot be resolved without ambiguity."""


@dataclass(frozen=True)
class LogicalTargetSpec:
    """Exact terminal selector supplied by a trusted startup host."""

    logical_id: str
    expected_exe_path: str
    expected_class: str
    expected_title_sha256: str
    allowed_roles: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.logical_id) is not str or not _LOGICAL_ID_RE.fullmatch(
            self.logical_id
        ):
            raise ValueError("logical_id must match ^[a-z][a-z0-9._-]{0,127}$")
        if (
            type(self.expected_exe_path) is not str
            or not self.expected_exe_path
            or self.expected_exe_path != self.expected_exe_path.strip()
            or _has_control_characters(self.expected_exe_path)
            or len(self.expected_exe_path) > 1024
            or not ntpath.isabs(self.expected_exe_path)
            or not re.match(r"^[A-Za-z]:\\", self.expected_exe_path)
        ):
            raise ValueError(
                "expected_exe_path must be a bounded local drive-letter absolute Windows path"
            )
        if (
            type(self.expected_class) is not str
            or not self.expected_class
            or self.expected_class != self.expected_class.strip()
            or _has_control_characters(self.expected_class)
            or len(self.expected_class) > 256
        ):
            raise ValueError("expected_class must be bounded, non-empty, and contain no ASCII control characters")
        if type(self.expected_title_sha256) is not str or not _SHA256_RE.fullmatch(
            self.expected_title_sha256
        ):
            raise ValueError("expected_title_sha256 must be 64 lowercase hex characters")
        try:
            roles = frozenset(self.allowed_roles)
        except TypeError as exc:
            raise ValueError("allowed_roles must be an iterable of closed lease roles") from exc
        if (
            not roles
            or any(type(role) is not str for role in roles)
            or not roles <= _VALID_ROLES
        ):
            raise ValueError("allowed_roles must be a non-empty subset of lease roles")
        object.__setattr__(self, "allowed_roles", roles)


@dataclass(frozen=True)
class ResolvedLogicalTarget:
    logical_id: str
    hwnd: int
    pid: int
    exe: str
    exe_path: str
    window_class: str
    title: str
    title_sha256: str

    def verifier_report(self) -> dict[str, Any]:
        return {
            "hwnd": self.hwnd,
            "pid": self.pid,
            "exe": self.exe,
            "exe_path": self.exe_path,
            "class": self.window_class,
            "title": self.title,
            "title_sha256": self.title_sha256,
            "valid": True,
            "ok": True,
            "reasons": [],
            "is_terminal": True,
            "is_self": False,
        }


TargetVerifier = Callable[..., dict[str, Any]]
WindowEnumerator = Callable[[], Iterable[int]]


def enumerate_top_level_windows() -> tuple[int, ...]:
    """Return a bounded snapshot of current top-level HWNDs."""
    user32 = ctypes.windll.user32
    windows: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ssize_t, ctypes.c_ssize_t)
    def callback(hwnd: int, _context: int) -> bool:
        if len(windows) >= _CANDIDATE_LIMIT:
            return False
        windows.append(int(hwnd))
        return True

    if not user32.EnumWindows(callback, 0):
        raise LogicalTargetError("top-level window enumeration failed or exceeded its bound")
    return tuple(windows)


class LogicalTargetResolver:
    """Resolve immutable aliases through the canonical live target verifier."""

    def __init__(
        self,
        specs: Iterable[LogicalTargetSpec],
        *,
        enumerate_windows: WindowEnumerator = enumerate_top_level_windows,
    ) -> None:
        if not callable(enumerate_windows):
            raise TypeError("enumerate_windows must be callable")
        copied: dict[str, LogicalTargetSpec] = {}
        for source in specs:
            if type(source) is not LogicalTargetSpec:
                raise TypeError("logical target entries must be exact LogicalTargetSpec values")
            spec = LogicalTargetSpec(
                logical_id=source.logical_id,
                expected_exe_path=source.expected_exe_path,
                expected_class=source.expected_class,
                expected_title_sha256=source.expected_title_sha256,
                allowed_roles=frozenset(source.allowed_roles),
            )
            if spec.logical_id in copied:
                raise ValueError(f"duplicate logical target {spec.logical_id!r}")
            copied[spec.logical_id] = spec
        self.__specs: Mapping[str, LogicalTargetSpec] = MappingProxyType(copied)
        self.__enumerate_windows = enumerate_windows

    def logical_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.__specs))

    def resolve(
        self,
        logical_id: str,
        *,
        role: str,
        target_verifier: TargetVerifier,
    ) -> ResolvedLogicalTarget:
        if not callable(target_verifier):
            raise LogicalTargetError("canonical target verifier is unavailable")
        spec = self.__specs.get(logical_id)
        if spec is None:
            raise LogicalTargetError(f"logical target {logical_id!r} is not configured")
        if role not in spec.allowed_roles:
            raise LogicalTargetError(
                f"lease role {role!r} is not authorized for logical target {logical_id!r}"
            )

        try:
            raw_candidates: list[int] = []
            seen_candidates: set[int] = set()
            for candidate in self.__enumerate_windows():
                if len(raw_candidates) >= _CANDIDATE_LIMIT:
                    raise LogicalTargetError("top-level window enumeration exceeded its bound")
                if type(candidate) is not int or not 1 <= candidate <= _HWND_MAX:
                    raise LogicalTargetError(
                        "top-level window enumeration returned an invalid HWND"
                    )
                if candidate in seen_candidates:
                    raise LogicalTargetError(
                        "top-level window enumeration returned duplicate HWNDs"
                    )
                seen_candidates.add(candidate)
                raw_candidates.append(candidate)
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, LogicalTargetError):
                raise
            raise LogicalTargetError("top-level window enumeration failed") from exc
        matches: list[ResolvedLogicalTarget] = []
        for value in raw_candidates:
            try:
                report = target_verifier(
                    value,
                    expect_exe_path=spec.expected_exe_path,
                    expect_class=spec.expected_class,
                    expect_title_sha256=spec.expected_title_sha256,
                    require_terminal=True,
                )
            except Exception as exc:  # noqa: BLE001
                raise LogicalTargetError("canonical target verification failed") from exc
            if type(report) is not dict:
                raise LogicalTargetError("canonical target verifier returned an invalid report")
            if report.get("ok") is not True:
                continue
            title = report.get("title")
            pid = report.get("pid")
            exe = report.get("exe")
            exe_path = report.get("exe_path")
            window_class = report.get("class")
            if (
                type(pid) is not int
                or pid <= 0
                or type(exe) is not str
                or not exe
                or type(exe_path) is not str
                or type(window_class) is not str
                or type(title) is not str
                or type(report.get("hwnd")) is not int
                or report.get("hwnd") != value
                or report.get("valid") is not True
                or report.get("is_terminal") is not True
                or report.get("is_self") is not False
                or type(report.get("reasons")) is not list
                or report.get("reasons") != []
            ):
                raise LogicalTargetError(
                    "canonical target verifier returned an incomplete identity binding"
                )
            title_sha256 = hashlib.sha256(title.encode("utf-8")).hexdigest()
            if (
                ntpath.normcase(ntpath.abspath(exe_path))
                != ntpath.normcase(ntpath.abspath(spec.expected_exe_path))
                or ntpath.normcase(exe) != ntpath.normcase(ntpath.basename(exe_path))
                or window_class != spec.expected_class
                or title_sha256 != spec.expected_title_sha256
            ):
                raise LogicalTargetError(
                    "canonical target verifier returned a mismatched successful report"
                )
            matches.append(
                ResolvedLogicalTarget(
                    logical_id=logical_id,
                    hwnd=value,
                    pid=pid,
                    exe=exe,
                    exe_path=exe_path,
                    window_class=window_class,
                    title=title,
                    title_sha256=title_sha256,
                )
            )

        if not matches:
            raise LogicalTargetError(f"logical target {logical_id!r} has no safe live match")
        if len(matches) != 1:
            raise LogicalTargetError(f"logical target {logical_id!r} is ambiguous")
        return matches[0]


__all__ = [
    "LogicalTargetError",
    "LogicalTargetResolver",
    "LogicalTargetSpec",
    "ResolvedLogicalTarget",
    "enumerate_top_level_windows",
]
