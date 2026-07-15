# SelfConnect Governance Profiles

Last updated: 2026-07-15

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
embed government authorization controls.

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

Purpose: a separate high-assurance product and deployment layer for government
authorization packages, air-gapped deployments, classified workflows up to
Secret where specifically authorized, high-assurance identity, and assessment
evidence.

Default posture:

- fail closed where required identity or audit evidence is missing;
- hardware-backed signing and session evidence required only when a deployment
  has selected and live-validated that control;
- WORM/off-host audit replication required for AU-9 style evidence;
- service identity, service SID, ETW, least privilege, strict target guard, and
  explicit policy enforcement are expected;
- manual bypasses must be rare, audited, time-limited, and operator-attributed.

Government mode should never be silently approximated. If hardware-backed
identity or immutable audit is unavailable, return `NA` or deny rather than
claim compliance.

### DoD impact-level boundary

The current DoD Cloud Computing SRG impact levels are IL2, IL4, IL5, and IL6.
There is no current IL7. Internal tests that exceed an IL6-oriented engineering
baseline must use a neutral name such as `higher_assurance_adversarial`; they do
not create a new impact level.

- IL4 and IL5 cover CUI, with IL5 used for CUI requiring stronger protection
  and unclassified national-security systems as determined by the information
  owner and Authorizing Official.
- IL6 covers classified information up to Secret. It is not a Top Secret
  authorization. Higher classifications require a separately approved
  classified environment.
- An impact level applies to a cloud service offering and its authorization
  boundary. It is separate from a person's clearance, an application's ATO,
  RMF categorization, and FedRAMP authorization.
- Passing SelfConnect tests is engineering evidence only. It is not a DoD
  Provisional Authorization, Mission Owner ATO, IATT, or clearance decision.

See the DoD Cyber Exchange's
[current authorized cloud service offerings](https://public.cyber.mil/dccs/cso/)
and [DISN Connection Process Guide](https://dl.dod.cyber.mil/wp-content/uploads/connect/CPG/ConnProcGuide.html),
plus DoDI 8520.03 and the applicable current SRG/authorization package, for the
authoritative categorization and assessment requirements.

## Runtime Mapping

`enterprise.mcp_dispatch.MCPDispatcher` defaults to `profile="enterprise"`.
Its `government` value is a fail-closed compatibility/test posture inside this
repository, not the complete SelfConnect Government product or an authorization.

Important boundary:

- the enterprise MCP dispatcher does not weaken its lease gate in `normal`
  profile;
- normal day-to-day SelfConnect should use the normal SDK/product path instead
  of pretending the enterprise MCP control plane is a casual-use surface;
- the compatibility `government` profile rejects requests that do not ask for
  TPM evidence, but its current signing tool still combines a software Ed25519
  signature with a separate TPM platform claim. That is not TPM-backed payload
  signing or remote attestation and is insufficient evidence for the separate
  Government product until the signing key, payload, and verified claim are
  bound by a reviewed protocol.

This split protects both product usability and enterprise/government credibility.
