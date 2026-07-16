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

## WHY-20260716-005 - Separate monitoring authority and bound telemetry labels

**Status:** Accepted
**Decision date (UTC):** 2026-07-16T14:28:08Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260716-005](LOG.md#log-20260716-005)
**Parked records:** [PARK-20260716-005](PARKED.md#park-20260716-005)
**Source state:** `selfconnect-enterprise`, pull request #25,
`b3c2707298d3fb92659ab1e574dd4ce3ce77db49`

**Decision:** Metrics scraping gets one dedicated bearer authority accepted
only by `/metrics`, with one bounded previous token for rotation. Production
refuses an absent, short, reused, or administrator-equal metrics token. Metric
labels come only from explicit closed sets. The supplied monitoring stack binds
to loopback, reads ignored secret files, persists state, and pins images by
registry digest.

**Why:** Read-only observability does not need lifecycle mutation authority.
Sharing the administrator token increased blast radius, while labeling unknown
requests with raw paths let unauthenticated input consume unbounded telemetry
resources. Deployment examples are copied into real environments, so insecure
defaults would become operational risk rather than harmless documentation.

**Alternatives considered:** Retaining admin authentication was rejected on
least-privilege grounds. Hashing or truncating raw paths was rejected because it
still permits attacker-controlled cardinality. Disabling metrics by default was
rejected because a separately authenticated loopback endpoint is testable and
supports the requested reference deployment.

**Consequences:** Operators provision and rotate one additional secret.
Prometheus cannot administer Ultra even if its credential is compromised.
Future Ultra routes must be explicitly added to the metric-route allowlist or
they appear safely as `__unmatched__`.

**Rollback conditions:** Replace this design only with an equal or stronger
read-only monitoring identity and a proven bounded-label contract. Do not
restore administrator-token scraping or raw path labels.

**Evidence and links:** `ultra_server/monitoring-security.test.mjs`,
`ultra_server/monitoring-config.test.mjs`, live HTTP results recorded in
[LOG-20260716-005](LOG.md#log-20260716-005), issue #14, and pull request #25.

## WHY-20260716-004 - Pin the merged fail-closed console transport

**Status:** Accepted
**Decision date (UTC):** 2026-07-16T02:06:16Z
**Updated (UTC):** 2026-07-16T02:16:31Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260716-004](LOG.md#log-20260716-004)
**Parked records:** [PARK-20260716-004](PARKED.md#park-20260716-004)
**Source state:** `selfconnect-enterprise`,
`chore/pin-core-console-transport`,
`8dcd6e58afb05f05d6fee97bba4c8d46a0ae9907`

**Decision:** Advance the Enterprise SelfConnect lock only to canonical core
merge `5c493300b937a0f912e32a131061a132d2c11fe8` and require the full composed
workflow before accepting compatibility.

**Why:** The prior lock included repaired core CI but not the subsequently
reproduced `ConsoleWindowClass` delivery defect. The new core commit separates
queue/API acceptance from receiver delivery, selects the native console-input
path by verified class, fails closed on partial write or caller-console
restoration failure, and prevents higher-level callers from recording success
without a structured transport record. The transport implementation remains
identified by ancestor `56d5ff1802dca5d4136bcc32fa37aa122d4944dc`.
PR #15 corrected the post-merge smoke oracle to select a unique external window,
preserve caller exclusion, and assert exact HWND/PID identity; it did not weaken
the production discovery boundary. Repository-local proof is necessary but does
not establish compatibility with Enterprise, BPC, and TSK.

**Alternatives considered:** Follow SelfConnect `master`; rejected because a
moving branch is not reproducible. Keep `a87e490`; rejected because Enterprise
would continue testing a source set with the known transport false-positive
behavior. Pin the PR head; rejected because only the canonical merge commit
identifies the delivered default-branch source. Treat core hosted CI as composed
evidence; rejected because it does not install and exercise the Enterprise
portfolio boundary.

**Consequences:** Enterprise tests the exact canonical core head containing the
merged transport behavior and deterministic smoke evidence, and retains
immutable source identity across all composed jobs. The lock update does not
broaden any delivery, security, compliance, patent, or authorization claim
beyond the named evidence.

**Rollback conditions:** If the composed jobs reveal a compatibility or
security regression, keep this change unmerged and diagnose the failed
proposition. Restore `a87e490` only for historical reproduction or under a new
bounded rollback decision that records the missing core fix.

**Evidence and links:** [LOG-20260716-004](LOG.md#log-20260716-004),
[PARK-20260716-004](PARKED.md#park-20260716-004), `portfolio-lock.json`,
`tools/portfolio_conformance.py`, SelfConnect PR #14, SelfConnect PR #15, and
the associated hosted Enterprise workflow.

## WHY-20260716-003 - Use bounded BPC error codes across the Ultra boundary

**Status:** Accepted
**Decision date (UTC):** 2026-07-16T01:43:00Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260716-003](LOG.md#log-20260716-003)
**Parked records:** [PARK-20260716-003](PARKED.md#park-20260716-003)
**Source state:** Enterprise PR #23 at `de9dd25`

**Decision:** Enterprise boundary adapters must emit lowercase bounded BPC
error codes accepted by the strict TSK bridge. Shadow/ghost responses use
`shadow_denied`; invalid result shapes use `invalid_result`.

**Why:** The bridge treats BPC callback results as untrusted and accepts only a
restricted error-code alphabet. Enterprise's earlier uppercase product-specific
code was therefore sanitized, breaking evidence specificity while correctly
remaining fail-closed. Aligning the adapter with the bounded contract keeps the
denial reason useful without widening the bridge's trust boundary.

**Alternatives considered:** Widen the bridge to accept arbitrary uppercase or
free-form callback errors; rejected because it would reintroduce error-text
injection. Assert only `ok == false`; rejected because it would stop proving
that automatic shadow quarantine is the denial source. Keep the generic
`VERIFICATION_FAILED`; safe but less useful for operational evidence.

**Consequences:** Composed clients receive a stable, bounded shadow denial and
the live test proves it. Detailed forensic context remains in BPC audit records,
not in the authorization response.

**Rollback conditions:** Replace these codes only with another closed,
machine-validated error vocabulary shared by BPC, TSK, and Enterprise. Never
restore arbitrary callback error propagation.

**Evidence and links:** [LOG-20260716-003](LOG.md#log-20260716-003),
[PARK-20260716-003](PARKED.md#park-20260716-003), the named unit/live tests,
and failed hosted job `87515299829`.

## WHY-20260716-002 - Pin canonical merge commits after coordinated hardening

**Status:** Accepted
**Decision date (UTC):** 2026-07-16T01:38:40Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260716-002](LOG.md#log-20260716-002)
**Parked records:** [PARK-20260716-002](PARKED.md#park-20260716-002)
**Source state:** `selfconnect-enterprise`,
`hardening/portfolio-pins-20260715`,
`229c5598b2bf4bd3d40cbf2648a412896e96c0bd`

**Decision:** Advance the composition lock only to canonical merged component
commits, then require a new Enterprise composition run before treating the set
as compatible.

**Why:** Pull-request checks proved each proposed change, but a PR head is not
the final source identity delivered from the default branch. BPC and TSK also
changed a shared authorization contract, so repository-local green checks were
necessary but insufficient. The Enterprise lanes must assemble the final merge
commits and exercise the real composed boundary.

**Alternatives considered:** Pin PR heads; rejected because they are not the
canonical delivered state. Follow default branches; rejected because future
changes would silently alter the composition. Retain the old lock; rejected
because it would omit the completed security corrections while still appearing
green.

**Consequences:** The lock records the actual portfolio being evaluated and
future component changes remain explicit review events. A failed hosted
composition run blocks this update rather than being reclassified or skipped.

**Rollback conditions:** Restore the former lock only to reproduce historical
evidence. For an active rollback, create a new decision record naming the
failed proposition and pin a reviewed set that passes the same composed gates.

**Evidence and links:** [LOG-20260716-002](LOG.md#log-20260716-002),
[PARK-20260716-002](PARKED.md#park-20260716-002), `portfolio-lock.json`, and
the associated hosted Enterprise workflow.

## WHY-20260716-001 - Use one executable lock for portfolio composition

**Status:** Accepted
**Decision date (UTC):** 2026-07-16T01:13:16Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260716-001](LOG.md#log-20260716-001)
**Parked records:** [PARK-20260716-001](PARKED.md#park-20260716-001)
**Source state:** `selfconnect-enterprise`,
`hardening/portfolio-conformance-20260715`,
`ce249afa89a2bb3022ee93acc8309f8c63dad8b9`

**Decision:** Keep the exact SelfConnect, BPC, and TSK source identities used by
Enterprise in one machine-readable portfolio lock. CI must read that lock and
verify actual checkout commits and package metadata before composition tests.

**Why:** Repository-local test counts cannot establish cross-repository
compatibility. Duplicated SHA literals in two workflow jobs and prose could
drift independently, leaving green evidence attached to an older composition.
The gate must identify the exact tested sources and fail before execution when
the checkouts or package identities do not match.

**Alternatives considered:** Use branch names; rejected because they are
mutable. Keep duplicate literals and compare them in review; rejected because
manual review was the failure mode. Automatically follow every repository's
`master`; rejected because unreviewed upstream changes would make builds
non-reproducible. Treat a green component branch as compatible; rejected
because BPC/TSK contract changes require composed verification.

**Consequences:** A component upgrade is now an explicit lock change. CI has a
single reproducible composition identity and records actual checkout/package
metadata. The lock can lag upstream until compatibility review completes, so
freshness remains a release decision rather than an inferred property.

**Rollback conditions:** Replace this lock only with an equivalent immutable
dependency mechanism that is consumed directly by every composition job and
verifies actual source plus package identity. Do not restore independent
hard-coded pins.

**Evidence and links:** [LOG-20260716-001](LOG.md#log-20260716-001),
[PARK-20260716-001](PARKED.md#park-20260716-001),
`tools/portfolio_conformance.py`, `tests/test_portfolio_conformance.py`, and
control `PORTFOLIO-PIN-001` in `docs/assurance/control_catalog.json`.

## WHY-20260715-008 - Require the authoritative server for Level 0 authorization

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T11:30:07Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-008](LOG.md#log-20260715-008),
[LOG-20260715-009](LOG.md#log-20260715-009),
[LOG-20260715-010](LOG.md#log-20260715-010),
[LOG-20260715-011](LOG.md#log-20260715-011),
[LOG-20260715-012](LOG.md#log-20260715-012)
**Parked records:** [PARK-20260715-017](PARKED.md#park-20260715-017)
**Source state:** `selfconnect-enterprise`,
`hardening/partner-rollout-readiness-20260715`,
`e071d745a5c87aaa0d008e35d2bd0928dea384e0`

**Decision:** Level 0 authorization must be a successful response from the live
Ultra verifier. Enforce mode defaults to strict denial and cannot convert a
server rejection or outage into authorization through a weaker fallback.
High-assurance operation also requires a deployment-supplied mesh secret.

**Why:** A local checksum can validate client-side structure but cannot observe
the server's durable nonce store, pair anomaly state, TSK lifecycle state, or
authoritative identity binding. Calling that path full BPC+TSK verification was
a composition error. A known default mesh secret further made possession
predictable in any deployment that failed to override configuration.

**Alternatives considered:** Keep local verification and rename it; rejected
because it would leave the claimed governed path bypassing authoritative state.
Permit fallback after a cryptographic rejection; rejected because rejection is
a security decision, not an availability signal. Remove all fallback modes;
deferred because explicitly configured lower-assurance compatibility remains a
documented product choice outside strict enforce mode.

**Consequences:** Enforce-mode availability now depends on the Ultra service,
which is intentional. Operators must provision a strong mesh secret and health,
restart, and dependency controls. Compatibility deployments can explicitly set
`SC_STRICT_ENFORCE=0`, but cannot cite the strict Level 0 property.

**Rollback conditions:** Replace the HTTP verifier only with an equivalent
authoritative verifier that preserves durable replay, identity, anomaly, and TSK
state. Never restore authorization from local self-checks merely to avoid a
service dependency.

**Evidence and links:** [LOG-20260715-008](LOG.md#log-20260715-008),
[LOG-20260715-009](LOG.md#log-20260715-009),
[LOG-20260715-010](LOG.md#log-20260715-010),
[LOG-20260715-011](LOG.md#log-20260715-011),
[LOG-20260715-012](LOG.md#log-20260715-012),
[PARK-20260715-017](PARKED.md#park-20260715-017),
`tests/test_identity_gate.py`, `tests/test_e2e_ultra_gate.py`, and the
pinned BPC/TSK protocol commits.

## WHY-20260715-007 - Bind security and compliance claims to the implemented boundary

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T11:24:27Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-007](LOG.md#log-20260715-007)
**Parked records:** [PARK-20260715-016](PARKED.md#park-20260715-016)
**Source state:** `selfconnect-enterprise`,
`hardening/partner-rollout-readiness-20260715`,
`e071d745a5c87aaa0d008e35d2bd0928dea384e0`

**Decision:** Describe OS protection, cryptographic key possession, platform
claims, hardware custody, protocol secrecy, policy filtering, candidate control
evidence, and authorization as separate properties. Remove readiness and
control-satisfaction conclusions from developer documentation. Make the local
TPM probe fail closed when it cannot read the hardware implementation property,
and advertise only algorithms/identity properties implemented by the MCP tools.

**Why:** The audit found that correct components had been composed into claims
the implementation did not establish. DPAPI was presented as hardware/process
identity; the software KSP was presented as device binding; a software Ed25519
signature plus independent platform claim was presented as TPM-backed payload
signing; owning-client TSK metadata was presented as structural secrecy; and
component tests were promoted to NIST baseline readiness. These overclaims
weaken engineering credibility and patent evidence even when the underlying
component is useful.

**Alternatives considered:** Leave historical files untouched and add one
disclaimer; rejected because search and partner review would still find the
false claims as current repository statements. Delete historical records;
rejected because provenance and restoration history matter. Add new
cryptographic infrastructure during the wording audit; rejected because a
claim correction must not invent evidence or blur into an unreviewed redesign.

**Consequences:** Current documentation is more conservative and separates
candidate evidence from deployment/assessment decisions. Some former marketing
language is no longer available. Restoring stronger wording now requires exact
implementation, named evidence, deployment configuration, and external review
where applicable. The TPM experiment now returns non-hardware/NA rather than
inferring hardware on a property-query failure.

**Rollback conditions:** Correct only a factual regression in the bounded
replacement. Do not restore a broader claim because a demonstration needs
stronger wording. Add a new decision when a redesigned protocol, hardware-bound
key path, validated cryptographic deployment, or qualified assessment provides
the missing evidence.

**Evidence and links:** [LOG-20260715-007](LOG.md#log-20260715-007),
[PARK-20260715-016](PARKED.md#park-20260715-016), `SECURITY.md`, `GAPS.md`,
`docs/ato/NIST_800-53_control_map.md`,
`docs/ato/THREAT_MODEL.md`, and
`docs/assurance/CONTROL_CATALOG.md`.

## WHY-20260715-006 - Prefer bounded rotation and explicit lifecycle boundaries over inferred readiness

**Status:** Accepted
**Decision date (UTC):** 2026-07-15T07:07:32Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Parked records:** [PARK-20260715-008](PARKED.md#park-20260715-008),
[PARK-20260715-009](PARKED.md#park-20260715-009), and
[PARK-20260715-010](PARKED.md#park-20260715-010), and
[PARK-20260715-011](PARKED.md#park-20260715-011), and
[PARK-20260715-012](PARKED.md#park-20260715-012), and
[PARK-20260715-013](PARKED.md#park-20260715-013), and
[PARK-20260715-014](PARKED.md#park-20260715-014), and
[PARK-20260715-015](PARKED.md#park-20260715-015)
**Source state:** `selfconnect-enterprise`,
`hardening/partner-rollout-readiness-20260715`,
`b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`

**Decision:** Add fail-closed abuse composition, bounded current/previous secret
rotation, challenge-bound recovery tokens, two-phase TSK rotation with resume,
and verified local ledger segmentation. Keep deployment custody, actual backup
restore, external witnessing, and authorization as non-executable descriptions.
Remove surfaces that only imply a control or stronger test evidence.
Require the IRS action record kind to determine retention rather than applying
the prompt-log schedule to unrelated test or incident evidence.
Treat algorithm and backend identity as evidence fields, not validation claims;
require the stored public key and backend marker to match the loaded signer.
Treat deployable package contents as a security boundary: keep Ultra private
while source-relative dependencies remain and package only an explicit runtime
allowlist.
Recover lifecycle requests with operation-specific durable reconciliation under
a per-resource lock; never infer that an unknown side effect is safe to replay.
Describe named tests as tests of their stated propositions, not proof of a
broader system guarantee.
Use the installed VCS commit as dependency identity and report package version
as separate metadata; do not infer source provenance from a release label.

**Why:** A control must survive process restart and failure boundaries, not
only a happy-path call. Shadow-mode deception was useful for observation but
unsafe as an authorization result. Replacing credentials in one step risks
outages; accepting unlimited old credentials defeats rotation. TSK local state
must not advance before the server binding commits. Ledger rotation must retain
one signed sequence and fail closed on corruption. None of these code properties
can create personnel custody, provider retention, or an external authorization.

**Alternatives considered:** Immediate key replacement without overlap was
rejected as the normal procedure because it creates avoidable outages; unlimited
keyrings were rejected because retired credentials would remain valid. Automatic
TSK renewal at exhaustion was deferred until approval and abandoned-candidate
policy are defined. A generic timeout takeover for `processing` idempotency rows
was rejected because replay after an unknown side effect could duplicate pair or
TSK creation. A new graph, service, or distillation package was rejected because
no scoped enforcement requirement justified it.
Relying on a parent `.gitignore` to define an npm artifact was rejected because
the package root did not apply that exclusion and the dry-run proved local state
would ship.

**Consequences:** Operators can rotate without exposing secret values in
evidence and can retire the previous generation deterministically. TSK rotation
and service restart are recoverable under the tested composition. Local ledger
files are bounded and verifiable across segments. More live tests require real
PostgreSQL, Redis, and process restarts, while external restore/custody checks
remain manual deployment evidence. Idempotency recovery is operation-specific:
durable advisory locks serialize ownership, exact resources reconstruct lost
responses, absent resources may execute once under the lock, and ambiguous
state fails closed rather than applying a generic timeout retry.

**Rollback conditions:** Roll back a rotation interface only if a replacement
preserves challenge binding, owner proof, bounded verification overlap,
compare-and-swap binding, old-key revocation, lost-response retry safety, and
restart recovery. Roll back ledger segmentation only if the replacement retains
fsync durability, cross-segment sequence/signature verification, corrupt-resume
refusal, and a tested migration procedure. Never restore deceptive shadow
success as permission or restore blanket evidence wording.

**Evidence and links:** [LOG-20260715-006](LOG.md#log-20260715-006),
`ultra_server/*.test.mjs`, `tests/test_e2e_ultra_gate.py`,
`tests/test_enterprise/test_ledger.py`, the two Ultra operational runbooks,
`docs/assurance/control_catalog.json`, and the linked PARK records.

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
