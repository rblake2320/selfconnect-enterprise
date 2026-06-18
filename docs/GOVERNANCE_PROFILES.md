# SelfConnect Governance Profiles

Last updated: 2026-06-18

SelfConnect has three intended operating levels. They must remain distinct.
Do not force normal day-to-day users through the enterprise or government
control path.

## 1. Normal SelfConnect

Purpose: fast local use, experimentation, daily AI-to-AI work, personal
automation, and capability discovery.

Default posture:

- free-flowing local operation;
- minimal setup;
- target guard remains recommended for right-window safety;
- no mandatory TPM, ETW, service mode, ATO package, WORM sink, or formal lease
  workflow;
- users should be able to test new channels quickly.

Normal SelfConnect should stay usable by normal people. It is not the place to
require IL6/IL7 controls.

## 2. SelfConnect Enterprise

Purpose: business, regulated teams, auditability, repeatable deployment, and
buyer-ready governance.

Default posture:

- Windows service mode available;
- MCP runtime dispatch available through governed tools;
- active leases required for actuating enterprise MCP tools;
- audit records on tool calls and policy decisions;
- channel router chooses target-specific native channels;
- ETW, named pipe, UIA, and WORM paths are optional adapters, enabled where the
  deployment needs them.

Enterprise is where governance becomes the default, but it should still support
developer-friendly setup and testing.

## 3. SelfConnect Government

Purpose: IL6/IL7-minded environments, air-gapped deployments, classified
workflows, high-assurance identity, and ATO evidence.

Default posture:

- fail closed where identity or audit guarantees are missing;
- TPM-backed signing and session stamping required for sensitive identity paths;
- WORM/off-host audit replication required for AU-9 style evidence;
- service identity, service SID, ETW, least privilege, strict target guard, and
  explicit policy enforcement are expected;
- manual bypasses must be rare, audited, time-limited, and operator-attributed.

Government mode should never be silently approximated. If hardware-backed
identity or immutable audit is unavailable, return `NA` or deny rather than
claim compliance.

## Runtime Mapping

`enterprise.mcp_dispatch.MCPDispatcher` defaults to `profile="enterprise"`.
It also accepts `normal`, `enterprise`, and `government` so tests and future
services can make the posture explicit.

Important boundary:

- the enterprise MCP dispatcher does not weaken its lease gate in `normal`
  profile;
- normal day-to-day SelfConnect should use the normal SDK/product path instead
  of pretending the enterprise MCP control plane is a casual-use surface;
- government profile denies software-only identity signing and software-only
  session stamping until TPM support is wired.

This split protects both product usability and enterprise/government credibility.
