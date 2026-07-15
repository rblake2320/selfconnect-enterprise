# NIST SP 800-53 Rev. 5 Candidate Evidence Map

**System:** SelfConnect Enterprise v1.2.3 engineering prototype
**Updated:** 2026-07-15
**Status:** Preliminary developer self-assessment; not an assessor determination

This map identifies repository artifacts that may support assessment of selected
NIST SP 800-53 Rev. 5 controls in a defined deployment. `Implemented` is not a
control-effectiveness conclusion used in this document. A component test cannot
select a baseline, fill organization-defined parameters, establish inheritance,
prove every runtime path uses the component, or replace SP 800-53A assessment
procedures and an Authorizing Official's decision.

Authoritative starting points:

- [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5)
- [NIST SP 800-53A Rev. 5](https://doi.org/10.6028/NIST.SP.800-53Ar5)
- [Executable SelfConnect control catalog](../assurance/CONTROL_CATALOG.md)
- [Open deployment and composition gaps](../../GAPS.md)

## Candidate Mapping

| Control | Repository evidence | Narrow proposition | Required deployment/assessment evidence |
|---|---|---|---|
| AC-3 | `GovernedRuntime`, `PolicyEnforcer`, `MCPDispatcher` tests | The composed governed MCP path fails closed when required policy, approval, target, identity, or ledger components are absent. Legacy/lower-level paths are outside this proposition. | Entry-point inventory, bypass analysis, deployed configuration, role/policy review, SP 800-53A assessment |
| AC-4 | `ObserverFilter`, `EgressGuard`, `ExportGuard` tests | Calls routed through these components enforce their tested classification/filter rules. They are not OS/network interception boundaries. | Complete data-flow inventory, OS/network enforcement, cross-repository route testing |
| AC-6 | Agent-policy action/target/application allowlists | Named policy tests exercise deny-by-default list evaluation. | Account/role design, administrative process, privilege review, inherited controls |
| AC-17 | Ultra binds its HTTP listener to loopback in the tested configuration | The Ultra listener is local-only. This does not prove that the whole product or host has no remote access path. | Host listener inventory, remote-management policy, firewall and service configuration |
| AU-2 / AU-3 / AU-12 | `AgentLedger`, `CngLedger`, `ProvenanceRecorder`, governed-runtime tests | Named governed paths create structured signed/hash-linked records with the fields exercised by tests. Direct SDK or unwrapped calls are not globally intercepted. | Event-selection rationale, clock source, aggregation, review, capacity, failure response, coverage reconciliation |
| AU-9 | Ledger verification, segment lifecycle, S3 Object Lock sink/proof artifact | Interior retained-entry tampering is detected; one dated S3 sink exercise produced retention read-back and fork rejection. A local chain cannot detect tail/file deletion without a trusted checkpoint. | Live bucket policy/custody, retention/legal hold, monitoring, restore drill, deployed replication coverage |
| AU-10 | Signature verification and externally pinned recorder-key support | A valid signature establishes possession of the corresponding private key for the signed bytes under the verifier's trust input. It does not by itself establish human attribution or legal non-repudiation. | Identity proofing, exclusive key custody, trusted time, revocation, personnel process, assessor/legal review |
| IA-2 / IA-3 | Full public-key verification, BPC/TSK binding, named-pipe SID probe | The tested verifier binds requests to registered key material and exact BPC/TSK identity. A same-user SID and an eight-hex-character agent label are not independent device authentication. | Enrollment/proofing, full-identifier collision policy, device inventory, revocation, multi-node binding evidence |
| IA-5 | DPAPI identity, NCrypt software KSP, key-rotation paths, TPM probes | DPAPI provides current-user OS protection at rest; the software KSP and TPM probes are distinct mechanisms. The current MCP TPM option does not bind its software Ed25519 signature to the platform claim. | Approved provider/module/configuration, key generation/custody/rotation/destruction, bound attestation protocol |
| SC-4 | Random named-pipe name and `FILE_FLAG_FIRST_PIPE_INSTANCE` experiment | These measures mitigate pipe-name squatting in the exercised local experiment. They do not make same-user shared resources confidential. | DACL/SACL verification, service identity, namespace ownership, live hostile-process tests |
| SC-8 | BPC body-bound signatures, timestamps/nonces, TSK checksums | The exercised messages have integrity/freshness checks. These mechanisms do not provide confidentiality, and the current Ultra HTTP listener is loopback plaintext. | Protected transport design, certificate/service identity, cryptographic configuration, route inventory |
| SC-13 | CNG/NCrypt algorithm adapters and signed `crypto_backend` metadata | The code invokes named algorithms/providers and rejects recorded-backend mismatch. Algorithm selection alone is not FIPS validation. | Exact CMVP certificate/module/version/operating environment, approved mode/service indicator, configuration evidence |
| SC-28 | DPAPI/software-KSP key storage and host-dependent file storage | Private-key material is not intentionally persisted as plaintext by these identity components. Ledger/data-at-rest protection depends on the deployed host/storage controls. | BitLocker/storage configuration, ACL evidence, backup protection, media sanitization, key recovery policy |
| SI-3 | Dependency-integrity and adversarial suites | Named tests detect their enumerated package, metadata, and dependency patterns. They are not an anti-malware boundary and do not cover novel attacks. | EDR/anti-malware operation, update process, alert handling, supply-chain provenance and monitoring |
| SI-7 | Signed policies/profiles, dependency pin gate, ledger verification | Named tests reject the enumerated tampering and pin-drift cases. | Release signing, artifact/SBOM provenance, deployed integrity monitoring, exception process |
| SI-10 | Schema, label, policy, and message validation tests | Enumerated input boundaries reject the exercised malformed values. No claim covers every external parser or future tool. | External-interface inventory, fuzz/adversarial results, operational error handling |
| CA-2 / CA-7 | Red-team records, control catalog, conformance tooling | The repository supplies developer tests and evidence collection hooks. It has not completed an independent control assessment or continuous-monitoring program. | Assessor plan/results, POA&M, monitoring strategy, owner/cadence/thresholds, authorization package |
| IR-4 | ControlPlane, operator queue, emergency procedure tests | Named state transitions and queue actions behave as exercised. The same-user DPAPI/mutex emergency mechanism is not a second independent authentication factor. | Incident plan, roles, communications, exercises, forensic retention, external reporting integration |

## Status Rule

Each row is **candidate evidence** until the intended deployment boundary maps
the control, resolves inherited and external portions, executes the applicable
assessment procedures, and records the responsible assessor/AO result. No total
of “satisfied controls” is reported from repository tests.

## Explicit Boundaries

- DPAPI usually requires the same logon credentials and computer, but Microsoft
  documents exceptions such as roaming profiles. It is not described here as
  hardware binding.
- A TPM platform claim over an ephemeral probe key is not remote attestation of
  the ordinary agent signing key and is not TPM-backed payload signing.
- DoD Impact Level, FedRAMP, IRS, HIPAA, financial-sector, and other authorization
  or compliance status cannot be derived from this map.
- AU-11 uses an organization-defined period consistent with the applicable
  records-retention policy; this repository does not impose a universal period.
