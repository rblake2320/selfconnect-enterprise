# Decision Rationale

This append-only record explains why material repository decisions were made.
It separates rationale from the chronological action record in `LOG.md` and the
restoration material in `PARKED.md`.

The linked record chain is:

`CHANGELOG.md` summary -> `LOG.md` action -> `WHY.md` rationale -> `PARKED.md`
recovery record, when material was removed or changed.

## Recording Rules

1. Create a `WHY-*` record for material implementation, security, compliance,
   release, architecture, or evidence-policy decisions.
2. State the evidence and uncertainty available at the time. Do not rewrite a
   decision later to make it appear better informed than it was.
3. Record alternatives considered, consequences, and explicit rollback
   conditions.
4. Link the action log, parked recovery record when applicable, issues or pull
   requests, source commits, tests, and external authorities.
5. Supersede a decision with a new `WHY-*` record. Retain the former rationale
   and link both directions.

## Entry Template

```markdown
## WHY-<UTC-date>-<sequence> - Short decision title

**Status:** Accepted | Superseded | Reversed
**Decision date (UTC):** YYYY-MM-DDTHH:MM:SSZ
**Decision owner:** Person or accountable role
**Action log:** LOG-<UTC-date>-<sequence>
**Parked records:** PARK-<UTC-date>-<sequence>, or `None`
**Source state:** Repository, branch, and full Git SHA

**Decision:** What was decided.

**Why:** The problem, evidence, and constraints that drove the decision.

**Alternatives considered:** Options rejected or deferred and why.

**Consequences:** Benefits, costs, risks, and patent/compliance effects.

**Rollback conditions:** Observable conditions that should trigger restoration
or a replacement decision.

**Evidence and links:** Tests, artifacts, commits, issues, authorities, and all
related records.
```

## Register

## WHY-20260715-005 - Treat enqueue, delivery, and execution as separate propositions

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T06:38:00Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-005](LOG.md#log-20260715-005)
**Parked records:** [PARK-20260715-007](PARKED.md#park-20260715-007)
**Source state:** `selfconnect-enterprise`, `origin/master`,
`bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`

**Decision:** A successful Win32 post is enqueue evidence only. Governed
delivery requires a newly observed UIA payload occurrence, and governed action
acceptance requires a separately specified effect that cannot be satisfied by
command echo. Terminal images must match protected path policies, not only
class names and basenames.

**Why:** Live testing produced a false positive on a dead terminal session even
though every `PostMessage` call returned normally. The same audit found that
the watcher equated API presence with health and that the guard discarded the
directory returned by `QueryFullProcessImageNameW`. These were composition and
claim failures that deterministic component tests did not cover.

**Alternatives considered:** Treating queue acceptance as delivery was rejected
because Win32 message APIs do not acknowledge application handling. Automatic
retry after missing readback was rejected because partial delivery could make a
retry duplicate an action. Trusting executable basename plus class was rejected
because both can be reproduced from a user-writable location.

**Consequences:** Governed injection now depends on readable UIA output and can
return an ambiguity error after a payload may have arrived. Callers must not
automatically retry that result. Full conformance requires a live shell and a
bounded effect token. Unsupported terminal installations fail closed until a
protected path policy is reviewed.

**Rollback conditions:** Replace UIA confirmation only with a channel-specific
ACK that proves equal or stronger handling and resists replay/stale evidence.
Expand trusted image roots only with adversarial tests and an explicit custody
argument. Never restore enqueue-only success in a governed path.

**Evidence and links:** `tests/test_enterprise/test_mcp_dispatch.py`,
`tests/test_enterprise/test_channel_router.py`,
`experiments/win32_probe/target_guard_load_test.py`,
`tools/irs_runtime_conformance.py`, and
[PARK-20260715-007](PARKED.md#park-20260715-007).

## WHY-20260715-004 - Keep the product repository neutral and bound TSK claims to disclosed data

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T06:05:16Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-004](LOG.md#log-20260715-004)
**Parked records:** [PARK-20260715-006](PARKED.md#park-20260715-006)
**Source state:** `selfconnect-enterprise`, `origin/master`,
`bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`

**Decision:** Keep product code and assurance documentation vendor-neutral.
Describe the TSK boundary as a complete server record plus a reduced owning-client
view, not as structural secrecy from that client.

**Why:** Named prospective relationships create avoidable IP, endorsement, and
maintenance coupling. Separately, the owning client receives shared secret,
segment type, length, order, initial counter, and total-length data required for
key construction. Literal omission of `position` fields is true but does not
hide the effective ordered layout.

The repository also maintains an executable catalog so a claim is not treated
as a control unless its scope, assertion, expected result, evidence, and blind
spots are named. Deployment and authorization items remain descriptions.

**Alternatives considered:** Retaining a named briefing in the repository was
rejected; it belongs in an owner-controlled external diligence package. Claiming
the layout is hidden because offsets are omitted was rejected as technically
misleading. Redesigning TSK was deferred because it is an upstream protocol
decision and not required for the currently tested lifecycle controls.

**Consequences:** External adapters are evaluated by a neutral contract and live
acceptance gate. TSK retains separate key material, rotating segments, checksum,
replay, and server lifecycle/counter controls without relying on an unsupported
hidden-layout proposition.

**Rollback conditions:** Add a named integration artifact only in a separate,
authorized diligence repository or package. Strengthen the TSK claim only after
a revised protocol and adversarial proof establish a non-derivable client view.

**Evidence and links:** `ultra_server/server.test.mjs`,
`enterprise/ultra_gate.py`, `SECURITY.md`,
`docs/assurance/CONTROL_CATALOG.md`, and
[PARK-20260715-006](PARKED.md#park-20260715-006).

## WHY-20260715-003 - Fail closed on unknown classification strings

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T05:52:00Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-003](LOG.md#log-20260715-003)
**Parked records:** [PARK-20260715-005](PARKED.md#park-20260715-005)
**Source state:** `selfconnect-enterprise`, `origin/master`,
`bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`

**Decision:** Unknown classification strings are configuration errors or runtime
denials; they never receive a rank below UNCLASSIFIED.

**Why:** A negative default rank made malformed values less restrictive than
every known classification and created a direct ceiling bypass.

**Alternatives considered:** Mapping unknown values to UNCLASSIFIED was rejected
because it hides typos and attacker-controlled markings. Mapping them to the
highest classification was rejected because it still normalizes invalid input.

**Consequences:** Bad configuration fails early; malformed runtime records are
denied or excluded. Callers must use the defined classification vocabulary.

**Rollback conditions:** Replace only with an equally fail-closed validated
label registry and explicit migration procedure.

**Evidence and links:** `enterprise/labels.py`, `enterprise/policy.py`,
`enterprise/classified_mode.py`, `enterprise/observer.py`, targeted tests, and
[PARK-20260715-005](PARKED.md#park-20260715-005).

## WHY-20260715-002 - Require authenticated durable Ultra lifecycle composition

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T05:40:00Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-002](LOG.md#log-20260715-002)
**Parked records:** [PARK-20260715-004](PARKED.md#park-20260715-004)
**Source state:** `selfconnect-enterprise`, `origin/master`,
`bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`

**Decision:** Production Ultra lifecycle operations require cryptographic agent
proof, separate operator authority where applicable, ownership validation,
durable PostgreSQL/Redis state, and live restart evidence.

**Why:** Authentication headers that are not verified provide no control.
Memory-only identity state and optional live tests cannot support restart or
production durability claims. Durable storage must also preserve security
counters under concurrency and stale metadata writes.

**Alternatives considered:** Bearer-only lifecycle authentication was rejected
because it loses agent attribution. Memory fallback in production was rejected
because a restart silently loses authority state. Mock persistence was rejected
because it had already hidden a HOTP rollback defect.

**Consequences:** Production has real service dependencies and secret-custody
requirements. Development remains explicitly volatile. CI becomes slower but
tests the composition that carries the claim.

**Rollback conditions:** Replace PostgreSQL/Redis only with stores that pass the
same atomicity, replay, idempotency, ownership, and restart conformance suite.

**Evidence and links:** Ultra source/tests, `tools/ultra_restart_conformance.py`,
CI workflow, [GAPS.md](GAPS.md), and
[PARK-20260715-004](PARKED.md#park-20260715-004).

## WHY-20260715-001 - Require composed controls and evidence-bounded IRS positioning

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T05:17:47Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-001](LOG.md#log-20260715-001)
**Parked records:** [PARK-20260715-001](PARKED.md#park-20260715-001),
[PARK-20260715-002](PARKED.md#park-20260715-002),
[PARK-20260715-003](PARKED.md#park-20260715-003)
**Source state:** `selfconnect-enterprise`, `origin/master`,
`bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`

**Decision:** A SelfConnect action may be described as governed only when the
same execution path requires a live target binding, externally pinned signed
policy, applicable operator approval, active ControlPlane state, and persistent
signed audit. IRS positioning will distinguish engineering support from agency
authorization and will identify unverified external assertions.

**Why:** Component tests did not prove that the default MCP path used the
components together. IRM 10.24.1 requires audit trails, inventories,
recordkeeping, privacy/security, human oversight, and high-impact governance,
but it does not prescribe SelfConnect's hash-chain/signature/Merkle mechanisms.
Overstating either side would weaken partner diligence and the evidence record.

**Alternatives considered:** Documentation-only corrections were rejected
because the actuator gap was real. Making every low-level module globally
intercepted was rejected as infeasible and misleading. Claiming IRS compliance
from tests was rejected because privacy, boundary, retention, assessment, and
authorization decisions are external.

**Consequences:** The default MCP actuator now fails closed until governance is
configured. Integrators receive a concrete runtime factory, IRS evidence schema,
and live conformance procedure. Existing direct low-level callers may need to
migrate or remain explicitly outside the governed-runtime claim.

**Rollback conditions:** Replace the composition only if an equivalent path
enforces all named gates with equal or stronger live evidence. Never restore the
former universal claims unless an executable whole-system assertion and
deployment evidence support them.

**Evidence and links:** [official IRM 10.24.1](https://www.irs.gov/irm/part10/irm_10-024-001r),
[sector profiles](docs/assurance/SECTOR_PROFILES.md),
`tests/test_enterprise/test_governed_runtime.py`,
`tests/test_enterprise/test_irs_evidence.py`, and
`tools/irs_runtime_conformance.py`.

## WHY-20260710-001 - Use linked, restorable change records

**Status:** Accepted
**Decision date (UTC):** 2026-07-10T04:43:01Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260710-001](LOG.md#log-20260710-001)
**Parked records:** None
**Source state:** `selfconnect-enterprise`, `origin/master`,
`cf0f2a36b05cca2acce943a036ae6b7239d1cd57`

**Decision:** Maintain separate but cross-linked records for release summaries,
full actions, decision rationale, and restorable prior states.

**Why:** Git retains historical content but does not reliably explain intent,
the evidence used, rollback triggers, or the complete procedure for restoring a
previous implementation. Security, compliance, and patent-evidence corrections
also need a clear record showing that narrower language preserves history rather
than erasing prior reduction-to-practice artifacts.

**Alternatives considered:** A larger `CHANGELOG.md` was rejected because release
readers should not have to parse operational detail. Relying only on commit
messages was rejected because messages do not provide a stable recovery index or
require links between rationale, evidence, and parked material.

**Consequences:** Documentation work requires additional recordkeeping. In
return, material changes have a traceable reason, recovery source, rollback
condition, and validation path. Parking a claim records its history; it does not
endorse the former wording or make a patentability or authorization conclusion.

**Rollback conditions:** Replace this structure only if it becomes unmaintainable,
fails to preserve recovery information, or an adopted repository governance
system provides equivalent traceability. Any replacement must first preserve
these records and document a migration path.

**Evidence and links:** [LOG-20260710-001](LOG.md#log-20260710-001),
[PARKED.md](PARKED.md), [CHANGELOG.md](CHANGELOG.md), and
`tests/test_documentation_records.py`.
