# Control Baseline Targets (Superseded Snapshot)

**Historical version:** SelfConnect Enterprise v1.0.0
**Original date:** 2026-05-08
**Status:** Superseded; do not use as readiness or authorization evidence

The former table labeled repository components as satisfying NIST SP 800-53
Low, Moderate, and High baseline controls. That was not a defensible control
assessment. Software tests can provide candidate evidence for a control, but
they do not establish the system boundary, control parameters, inheritance,
deployment configuration, operating effectiveness, residual risk acceptance,
or authorization decision.

The former document also incorrectly:

- described DPAPI and NCrypt software-KSP keys as machine/device identity;
- treated hash chaining as sufficient audit-information protection;
- converted repository gaps into POA&M items without an authorization owner;
- inferred ATO readiness from component tests; and
- used fixed test counts as continuing release evidence.

Use these current sources instead:

- [`../ato/NIST_800-53_control_map.md`](../ato/NIST_800-53_control_map.md) for
  bounded candidate control evidence and explicit deployment dependencies;
- [`../assurance/CONTROL_CATALOG.md`](../assurance/CONTROL_CATALOG.md) for
  executable assertions and named blind spots;
- [`../../GAPS.md`](../../GAPS.md) for open engineering and claim boundaries;
- [`../../SECURITY.md`](../../SECURITY.md) for system-level non-guarantees; and
- [`gap-analysis.md`](gap-analysis.md) for preliminary, assessor-qualified gap
  tracking.

No repository document determines that a NIST baseline is satisfied, that a
POA&M is approved, or that a deployment is ready for an ATO. Those decisions
belong to the responsible system owner, assessor, and Authorizing Official for
the defined operational boundary.
