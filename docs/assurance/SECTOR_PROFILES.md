# Assurance Profiles and Product Boundaries

**Status:** Architecture rule, not a compliance determination  
**Last reviewed:** 2026-07-15

## Product Layers

SelfConnect is intentionally layered. A stronger layer composes the layer below;
it does not redefine the core transport or make every installation regulated.

| Layer | Responsibility | Explicit non-claim |
|---|---|---|
| SelfConnect | Win32 OS-level target discovery, guarded terminal input, UIA/visual read paths, local transport, and mesh primitives | No enterprise or government authorization implied |
| SelfConnect Enterprise | Persistent identity, externally trusted signed policy, one-time operator approval, control plane, live target binding, signed evidence, and provider-verified retention adapters | No sector compliance or agency authorization implied |
| SelfConnect Government | Separately packaged/deployed high-assurance composition, approved cryptographic modules and environment, classification handling, STIG/SRG configuration, continuous monitoring, assessment evidence, and authorization integration | Tests do not create IL, PA, ATO, IATT, or clearance status |

The `government` dispatcher setting in this repository is a fail-closed
compatibility and adversarial-test posture. It is not the complete SelfConnect
Government product.

## Sector Profile Rule

Government, healthcare, financial services, and tax workflows share the same
Enterprise control engine, but each profile must be defined independently. A
profile is acceptable only when it identifies:

1. authoritative sources and their effective dates;
2. covered entities, data types, systems, and geographic boundary;
3. required identity, approval, segregation, retention, incident, and recovery behavior;
4. executable assertions and live deployment probes;
5. evidence location, owner, review cadence, and exception expiration;
6. external agreements and decisions that code cannot supply; and
7. named blind spots and prohibited claims.

No profile may inherit the word `compliant` from another profile. Shared tests
establish shared engineering propositions only.

## Government Profile

Authoritative starting points include the current DoD Cloud Computing SRG,
DoDI 8520.03, NIST SP 800-53, agency policy, and the system authorization
package. DoD impact levels are IL2, IL4, IL5, and IL6; IL6 stops at Secret.
Top Secret requires a separate authorized classified environment.

Required external gates include the chosen CSO's applicable impact-level
authorization, the Mission Owner system boundary and ATO/IATT as applicable,
RMF categorization, personnel/access authorization, approved cryptographic
configuration, STIG/SRG results, continuous monitoring, incident response, and
an independent assessment. SelfConnect tests can support but cannot replace
these decisions.

## IRS Tax Profile

The IRS profile is a government/tax specialization, not the definition of the
Enterprise core. It adds use-case/model/data inventory records, sensitive-data purpose evidence,
high-impact determination and human review fields, and IRS retention labels.
Actual IRS systems of record, privacy review, external adapters, records
disposition, and authorization remain deployment responsibilities.

## Healthcare Profile

The current HIPAA Security Rule requires regulated entities to protect ePHI
with administrative, physical, and technical safeguards. The HHS audit protocol
for 45 CFR 164.312(b) asks whether mechanisms record and examine activity in all
systems that contain or use ePHI. See the [HHS Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
and [HHS audit protocol](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html).

Before a healthcare claim, the profile must additionally establish covered
entity/business-associate status, a BAA where required, minimum-necessary use,
access and disclosure accounting boundaries, ePHI encryption/configuration,
breach/incident workflows, backup and contingency testing, retention, and live
audit review. SelfConnect audit events alone do not establish HIPAA compliance.

## Financial Services Profile

The governing authority depends on the institution and regulator. For entities
under FTC jurisdiction, the [GLBA Safeguards Rule](https://www.ftc.gov/legal-library/browse/rules/safeguards-rule)
requires an information security program with administrative, technical, and
physical safeguards for customer information and includes service-provider
oversight. Other banks, broker-dealers, insurers, payment systems, and states
have different or additional authorities.

Before a financial-services claim, the profile must establish regulator and
product scope, nonpublic personal information and payment-data boundaries,
qualified-individual/accountability requirements, risk assessment, encryption
and access controls, monitoring/testing, service-provider controls, incident
reporting, retention/legal hold, business continuity, and change/transaction
approval semantics. SelfConnect evidence is one control input, not the complete
program.

## Cross-Sector Release Gate

A sector capability may be described as `implemented` only when its code and
named tests exist. It may be described as `live-validated` only when a real
deployment conformance run is attached. It may be described as `assessed` or
`authorized` only when the responsible external party has issued that result.
Anything else remains `not assessed`, `open`, or `parked`.
