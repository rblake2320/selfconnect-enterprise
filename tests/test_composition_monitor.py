"""Adversarial tests — no mocks, real failure injection, non-happy-path."""
import time
from enterprise.composition_monitor import (
    CompositionMonitor, CompositionSignature, DEFAULT_EFFECT_MAP,
)


class RecordingLedger:
    def __init__(self): self.entries = []
    def log(self, event, result=None, metadata=None):
        self.entries.append((event, result, metadata))


def test_benign_single_calls_pass():
    m = CompositionMonitor()
    assert m.observe("A", "read_text").allowed
    assert m.observe("A", "read_file").allowed  # recon+access, no egress yet


def test_recon_access_egress_arc_is_denied():
    m = CompositionMonitor()
    assert m.observe("A", "read_text").allowed          # recon
    assert m.observe("A", "read_file").allowed          # access
    v = m.observe("A", "http_request")                  # egress -> trips arc
    assert not v.allowed and v.signature == "recon_to_egress"


def test_non_adjacent_composition_still_caught():
    """Interleave unrelated calls between the arc steps — must still trip."""
    m = CompositionMonitor()
    m.observe("A", "read_text")       # recon
    m.observe("A", "assign_task")     # control (noise)
    m.observe("A", "read_file")       # access
    m.observe("A", "assign_task")     # control (noise)
    v = m.observe("A", "http_request")  # egress
    assert not v.allowed and v.signature == "recon_to_egress"


def test_per_agent_isolation_no_cross_contamination():
    """Agent B's benign calls must not complete Agent A's arc."""
    m = CompositionMonitor()
    m.observe("A", "read_text")       # A: recon
    m.observe("B", "read_file")       # B: access (different agent)
    v = m.observe("B", "http_request")  # B egress — B has no recon -> allow
    assert v.allowed


def test_window_expiry_resets_arc():
    m = CompositionMonitor(window_seconds=10.0)
    t = 1000.0
    m.observe("A", "read_text", now=t)        # recon at t
    m.observe("A", "read_file", now=t + 1)    # access
    # egress arrives after window — recon/access evicted -> allowed
    v = m.observe("A", "http_request", now=t + 20)
    assert v.allowed


def test_unknown_action_treated_as_elevated_not_benign():
    """A tool not in the effect map must not be a silent bypass."""
    m = CompositionMonitor(max_elevated_rate=2)
    for _ in range(3):
        v = m.observe("A", "some_new_undeclared_tool")  # -> 'unknown' -> elevated
    assert not v.allowed and v.signature == "elevated_velocity"


def test_velocity_anomaly_denies_burst():
    m = CompositionMonitor(max_elevated_rate=4)
    last = None
    for _ in range(6):
        last = m.observe("A", "write_file")  # mutate = elevated
    assert not last.allowed and last.signature == "elevated_velocity"


def test_fail_closed_on_internal_error():
    """Corrupt the effect map to force an internal exception -> must DENY."""
    m = CompositionMonitor()
    m._effect_map = None  # inject failure
    v = m.observe("A", "read_text")
    assert not v.allowed and v.signature == "internal_error"


def test_ledger_records_denials():
    led = RecordingLedger()
    m = CompositionMonitor(ledger=led)
    m.observe("A", "read_text"); m.observe("A", "read_file")
    m.observe("A", "http_request")
    assert any(e[0] == "composition_check" and e[1] == "denied" for e in led.entries)


def test_ledger_failure_does_not_flip_deny_to_allow():
    class BrokenLedger:
        def log(self, *a, **k): raise RuntimeError("ledger down")
    m = CompositionMonitor(ledger=BrokenLedger())
    m.observe("A", "read_text"); m.observe("A", "read_file")
    v = m.observe("A", "http_request")
    assert not v.allowed  # deny survives ledger failure


def test_memory_bounded_under_flood():
    m = CompositionMonitor(max_window_len=50, window_seconds=1e9)
    for i in range(5000):
        m.observe("A", "read_text", now=float(i))
    assert len(m._windows["A"].effects) <= 50


def test_execute_then_egress_shape():
    m = CompositionMonitor()
    m.observe("A", "subprocess")             # execute
    v = m.observe("A", "http_request")       # egress
    assert not v.allowed and v.signature == "execute_then_egress"


if __name__ == "__main__":
    import sys, traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except Exception:
            print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
