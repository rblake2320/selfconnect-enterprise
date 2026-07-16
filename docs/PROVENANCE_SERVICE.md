# Dedicated Provenance Service

The `SelfConnectProvenance` Windows service is the hardened local write boundary
for Enterprise and Government audit events. It separates the authoritative
ledger writer from agent processes; it is not an off-host immutability service,
an ATO, or a substitute for an independently administered retention system.

## Boundary

- SCM runs the process as `NT SERVICE\SelfConnectProvenance` with a restricted
  service SID and configured restart actions.
- Only that service SID, SYSTEM, and Administrators receive authority on the
  service root. Enrolled client SIDs do not receive ledger write authority.
- The local named pipe uses `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`, an explicit DACL, bounded instances and frames,
  request deadlines, and client/server SID pinning.
- A request is accepted only when its OS token presents exactly one enrolled
  SID and its enrolled agent key verifies the event and complete request.
- Nonces, receipts, and request IDs are persisted in SQLite. Recovery searches
  the signed ledger, repairs required replication, advances the signed session
  high-water index, and returns the original receipt without duplicating the
  event.
- Enterprise and Government runtime construction uses the service client and
  has no automatic in-process fallback. Consumer mode remains an explicit,
  separate posture.

## Install

Build and review one wheel, then run from an elevated PowerShell:

```powershell
python -m build
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\deploy\provenance_service.ps1 `
  -Action Install `
  -WheelPath .\dist\selfconnect_enterprise-1.2.3-py3-none-any.whl `
  -AuditMode enterprise `
  -WormSink memory
```

`memory` is suitable only for the local service-boundary drill. Government mode
refuses installation unless `s3` or `r2` is selected, and the chosen provider's
retention configuration still requires live verification.

Manage enrollments as an administrator, then restart the service:

```powershell
scent-provenance-admin enroll `
  --agent-id SC-... `
  --algorithm ed25519 `
  --public-key-hex ... `
  --sid S-1-5-21-...
Restart-Service SelfConnectProvenance
```

## Acceptance Drill

The acceptance script creates disposable non-admin users, installs the reviewed
wheel through SCM, runs valid and adversarial requests under distinct tokens,
tests direct filesystem denial, pipe squatting, DACL tamper refusal, forced
process restart during concurrent submissions, offline signature/chain
verification, and uninstall rollback. It does not print passwords or private
keys.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\deploy\provenance_service_acceptance.ps1 `
  -WheelPath .\dist\selfconnect_enterprise-1.2.3-py3-none-any.whl `
  -EvidencePath .\docs\operations\provenance-service-acceptance.json
```

The issue is not closed by parser or unit tests. Closure requires a report from
an installed service and a distinct non-admin token. A second Windows host is
still required before claiming remote-host rejection was exercised rather than
inferred from `PIPE_REJECT_REMOTE_CLIENTS`.

## Recovery

`RepairAcl` reapplies the exact service-SID filesystem contract after an
authorized review of a detected ACL drift:

```powershell
.\deploy\provenance_service.ps1 -Action RepairAcl
```

Uninstall does not silently activate in-process provenance for Enterprise or
Government. The hardened runtime remains unavailable until the service is
reinstalled and its pinned identity is configured.
