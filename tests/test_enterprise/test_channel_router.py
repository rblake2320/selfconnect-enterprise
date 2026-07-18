"""Tests for experiments/win32_probe/channel_router.py."""
from __future__ import annotations

import hashlib
import threading
from unittest.mock import patch

import pytest

from experiments.win32_probe.channel_router import (
    BROWSER_CLASSES,
    TERMINAL_CLASSES,
    MAX_PAYLOAD_LENGTH,
    ChannelRouter,
    ChannelRoutingError,
    ChannelType,
    ActionReceipt,
    TargetBinding,
)


class TestChannelTypeEnum:
    def test_all_values_are_strings(self):
        for ct in ChannelType:
            assert isinstance(ct.value, str)

    def test_deny_exists(self):
        assert ChannelType.DENY == "deny"

    def test_wm_char_exists(self):
        assert ChannelType.WM_CHAR == "wm_char"

    def test_uia_exists(self):
        assert ChannelType.UIA == "uia"

    def test_pipe_exists(self):
        assert ChannelType.PIPE == "pipe"


class TestChannelSets:
    def test_terminal_classes_nonempty(self):
        assert len(TERMINAL_CLASSES) > 0

    def test_browser_classes_nonempty(self):
        assert len(BROWSER_CLASSES) > 0

    def test_cascadia_in_terminal_classes(self):
        assert "CASCADIA_HOSTING_WINDOW_CLASS" in TERMINAL_CLASSES

    def test_console_in_terminal_classes(self):
        assert "ConsoleWindowClass" in TERMINAL_CLASSES

    def test_chrome_in_browser_classes(self):
        assert "Chrome_WidgetWin_1" in BROWSER_CLASSES

    def test_no_overlap_between_terminal_and_browser(self):
        assert TERMINAL_CLASSES.isdisjoint(BROWSER_CLASSES)


class TestClassify:
    def test_hwnd_zero_is_denied(self):
        router = ChannelRouter()
        decision = router.classify(0)
        assert decision.channel == ChannelType.DENY
        assert "invalid" in decision.reason.lower()

    def test_terminal_class_routes_to_wm_char(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1234),
        ):
            decision = router.classify(1001)
        assert decision.channel == ChannelType.WM_CHAR
        assert decision.window_class == "CASCADIA_HOSTING_WINDOW_CLASS"

    def test_browser_class_routes_to_uia(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="Chrome_WidgetWin_1"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Chrome"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=5678),
        ):
            decision = router.classify(2002)
        assert decision.channel == ChannelType.UIA

    def test_unknown_class_is_denied(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="SomeRandomWidget_XYZ"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Unknown"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=999),
        ):
            decision = router.classify(3003)
        assert decision.channel == ChannelType.DENY
        assert "SomeRandomWidget_XYZ" in decision.reason

    def test_empty_class_is_denied(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class", return_value=""),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value=""),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=0),
        ):
            decision = router.classify(4004)
        assert decision.channel == ChannelType.DENY

    def test_classify_records_decision(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="ConsoleWindowClass"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="cmd"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=111),
        ):
            router.classify(5005)
        assert len(router.last_decisions()) == 1

    def test_console_window_class_routes_to_wm_char(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="ConsoleWindowClass"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="cmd"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=200),
        ):
            decision = router.classify(6006)
        assert decision.channel == ChannelType.WM_CHAR


class TestRoute:
    def test_matching_expected_binding_reaches_mutation(self):
        title = "Bound Terminal"
        binding = TargetBinding(
            pid=4242,
            exe="WindowsTerminal.exe",
            exe_path=r"C:\Program Files\WindowsApps\Terminal\WindowsTerminal.exe",
            window_class="CASCADIA_HOSTING_WINDOW_CLASS",
            title_sha256=hashlib.sha256(title.encode("utf-8")).hexdigest(),
        )

        def accept_binding(hwnd, **_kwargs):
            return {"ok": True, "reasons": [], "hwnd": hwnd, "title": title}

        router = ChannelRouter(target_verifier=accept_binding)
        with (
            patch(
                "experiments.win32_probe.channel_router._get_window_class",
                return_value="CASCADIA_HOSTING_WINDOW_CLASS",
            ),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value=title),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=4242),
            patch.object(router, "_inject_wm_char", return_value=True) as inject,
        ):
            receipt = router.route(8006, "hello", expected_binding=binding)
        assert receipt.success is True
        inject.assert_called_once_with(8006, "hello")

    def test_expected_binding_is_revalidated_before_mutation(self):
        calls = []

        def reject_replacement(hwnd, **kwargs):
            calls.append((hwnd, kwargs))
            return {"ok": False, "reasons": ["pid changed at final boundary"]}

        router = ChannelRouter(target_verifier=reject_replacement)
        binding = TargetBinding(
            pid=4242,
            exe="WindowsTerminal.exe",
            exe_path=r"C:\Program Files\WindowsApps\Terminal\WindowsTerminal.exe",
            window_class="CASCADIA_HOSTING_WINDOW_CLASS",
            title_sha256="a" * 64,
        )
        with (
            patch(
                "experiments.win32_probe.channel_router._get_window_class",
                return_value="CASCADIA_HOSTING_WINDOW_CLASS",
            ),
            patch(
                "experiments.win32_probe.channel_router._get_window_title",
                return_value="Replacement Terminal",
            ),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=5252),
            patch.object(router, "_inject_wm_char") as inject,
        ):
            with pytest.raises(ChannelRoutingError, match="pid changed at final boundary"):
                router.route(8007, "hello", expected_binding=binding)
        assert calls[0][1]["expect_title_sha256"] == "a" * 64
        inject.assert_not_called()

    def test_route_denied_raises_channel_routing_error(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="RandomUnknownClass"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="?"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=0),
        ):
            with pytest.raises(ChannelRoutingError):
                router.route(7007, "hello")

    def test_route_hwnd_zero_raises_channel_routing_error(self):
        router = ChannelRouter()
        with pytest.raises(ChannelRoutingError):
            router.route(0, "hello")

    def test_route_returns_action_receipt(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", return_value=True),
        ):
            receipt = router.route(8008, "hello world")
        assert isinstance(receipt, ActionReceipt)
        assert receipt.hwnd == 8008
        assert receipt.channel == ChannelType.WM_CHAR
        assert receipt.transport_enqueued is True
        assert receipt.delivery_confirmed is False

    def test_route_receipt_has_payload_hash(self):
        import hashlib
        router = ChannelRouter()
        text = "test injection"
        expected_hash = hashlib.sha256(text.encode()).hexdigest()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", return_value=True),
        ):
            receipt = router.route(9009, text)
        assert receipt.payload_hash == expected_hash

    def test_route_receipt_id_is_uuid(self):
        import uuid
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", return_value=True),
        ):
            receipt = router.route(1111, "ping")
        uuid.UUID(receipt.receipt_id)  # raises if not valid UUID

    def test_inject_error_does_not_raise_from_route(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", side_effect=RuntimeError("win32 error")),
        ):
            receipt = router.route(2222, "hello")
        assert receipt.success is False

    def test_windows_terminal_delivery_targets_input_site_child(self):
        router = ChannelRouter()
        posted: list[tuple[int, int, int, int]] = []

        def enumerate_child(_parent, callback, context):
            callback(222, context)

        def class_for(hwnd):
            return (
                "CASCADIA_HOSTING_WINDOW_CLASS"
                if hwnd == 111
                else "Windows.UI.Input.InputSite.WindowClass"
            )

        with (
            patch("experiments.win32_probe.channel_router._WIN32_AVAILABLE", True),
            patch("experiments.win32_probe.channel_router._get_window_class", side_effect=class_for),
            patch(
                "experiments.win32_probe.channel_router.win32gui.EnumChildWindows",
                side_effect=enumerate_child,
            ),
            patch(
                "experiments.win32_probe.channel_router.win32api.PostMessage",
                side_effect=lambda *args: posted.append(args),
            ),
        ):
            assert router._inject_wm_char(111, "A\r") is True

        assert posted[0][0] == 222
        assert posted[0][2] == ord("A")
        assert all(message[0] == 222 for message in posted)
        assert len(posted) == 3

    def test_windows_terminal_without_input_site_fails_closed(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._WIN32_AVAILABLE", True),
            patch(
                "experiments.win32_probe.channel_router._get_window_class",
                return_value="CASCADIA_HOSTING_WINDOW_CLASS",
            ),
            patch("experiments.win32_probe.channel_router.win32gui.EnumChildWindows"),
            patch("experiments.win32_probe.channel_router.win32api.PostMessage") as post,
        ):
            assert router._inject_wm_char(111, "A") is False
        post.assert_not_called()


# ---------------------------------------------------------------------------
# Adversarial security tests (added by WRAITH review)
# ---------------------------------------------------------------------------

class TestHWNDRangeValidation:
    """CRITICAL: negative and sentinel HWND values must be DENY, not routed."""

    def test_negative_hwnd_is_denied(self):
        """HWND_BROADCAST (-1) and similar must be rejected, not routed."""
        router = ChannelRouter()
        decision = router.classify(-1)
        assert decision.channel == ChannelType.DENY
        assert "forbidden" in decision.reason or "range" in decision.reason or "invalid" in decision.reason.lower()

    def test_large_negative_hwnd_is_denied(self):
        router = ChannelRouter()
        decision = router.classify(-999999)
        assert decision.channel == ChannelType.DENY

    def test_negative_hwnd_route_raises(self):
        router = ChannelRouter()
        with pytest.raises(ChannelRoutingError):
            router.route(-1, "attack")

    def test_hwnd_zero_deny_is_recorded_in_audit_log(self):
        """CRITICAL: hwnd=0 DENY must appear in last_decisions() — no audit bypass."""
        router = ChannelRouter()
        router.classify(0)
        decisions = router.last_decisions(10)
        assert len(decisions) == 1
        assert decisions[0].channel == ChannelType.DENY

    def test_hwnd_negative_deny_is_recorded_in_audit_log(self):
        """CRITICAL: negative-HWND DENY must appear in audit log."""
        router = ChannelRouter()
        router.classify(-1)
        decisions = router.last_decisions(10)
        assert len(decisions) == 1
        assert decisions[0].channel == ChannelType.DENY


class TestPayloadValidation:
    """HIGH: text payload must be validated before injection."""

    def test_non_str_text_raises_value_error(self):
        """MISSING VALIDATION: passing bytes must raise, not silently corrupt."""
        router = ChannelRouter()
        with pytest.raises((ValueError, TypeError)):
            router.route(8008, b"bytes payload")  # type: ignore[arg-type]

    def test_none_text_raises(self):
        router = ChannelRouter()
        with pytest.raises((ValueError, TypeError)):
            router.route(8008, None)  # type: ignore[arg-type]

    def test_oversized_payload_raises_value_error(self):
        """INTEGRITY: payload larger than MAX_PAYLOAD_LENGTH must be rejected
        to prevent partial delivery being falsely reported as success."""
        router = ChannelRouter()
        oversized = "A" * (MAX_PAYLOAD_LENGTH + 1)
        with pytest.raises(ValueError, match="maximum allowed length"):
            router.route(8008, oversized)

    def test_max_payload_boundary_is_accepted(self):
        """Exactly MAX_PAYLOAD_LENGTH chars must pass validation (no off-by-one)."""
        router = ChannelRouter()
        exact = "A" * MAX_PAYLOAD_LENGTH
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", return_value=True),
        ):
            receipt = router.route(8008, exact)
        assert receipt.success is True


class TestLeaseIdValidation:
    """HIGH: lease_id structural validation — empty string must not bypass lease checks."""

    def test_empty_string_lease_id_raises(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
        ):
            with pytest.raises(ValueError, match="empty"):
                router.route(8008, "hello", lease_id="")

    def test_whitespace_lease_id_raises(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
        ):
            with pytest.raises(ValueError, match="empty"):
                router.route(8008, "hello", lease_id="   ")

    def test_none_lease_id_is_accepted(self):
        """None lease_id is valid (unauthenticated path, if policy allows)."""
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", return_value=True),
        ):
            receipt = router.route(8008, "hello", lease_id=None)
        assert receipt.success is True

    def test_valid_lease_id_passes_through(self):
        router = ChannelRouter()
        with (
            patch("experiments.win32_probe.channel_router._get_window_class",
                  return_value="CASCADIA_HOSTING_WINDOW_CLASS"),
            patch("experiments.win32_probe.channel_router._get_window_title", return_value="Terminal"),
            patch("experiments.win32_probe.channel_router._get_window_pid", return_value=1000),
            patch.object(router, "_inject_wm_char", return_value=True),
        ):
            receipt = router.route(8008, "hello", lease_id="lease-abc-123")
        assert receipt.success is True


class TestThreadSafety:
    """HIGH: concurrent classify() must not produce corrupted _decisions list."""

    def test_concurrent_classify_all_recorded(self):
        """100 concurrent classify() calls must each produce exactly one decision."""
        router = ChannelRouter()
        errors = []

        def classify_once(hwnd: int) -> None:
            try:
                with (
                    patch("experiments.win32_probe.channel_router._get_window_class",
                          return_value="ConsoleWindowClass"),
                    patch("experiments.win32_probe.channel_router._get_window_title",
                          return_value="term"),
                    patch("experiments.win32_probe.channel_router._get_window_pid",
                          return_value=hwnd),
                ):
                    router.classify(hwnd)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=classify_once, args=(i + 1,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Threads raised: {errors}"
        # All 50 decisions must be present (list[-50:] covers them all)
        all_decisions = router.last_decisions(100)
        assert len(all_decisions) == 50
