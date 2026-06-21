# MSI Release Automation Evidence

**Date:** 2026-06-21  
**Verdict:** AUTOMATED BUILD PATH VERIFIED
**Scope:** GitHub Actions workflow for building and publishing the SelfConnect
Enterprise MSI as a release artifact bundle.

## Verified GitHub Actions Run

Manual workflow dispatch was executed and completed successfully.

| Field | Value |
|---|---|
| Workflow | `Build MSI Release Artifact` |
| Run ID | `27897466199` |
| Ref | `refs/heads/master` |
| Git SHA | `bb83ae8c492c77bc497fde75d9b50c3c40ef057d` |
| Result | PASS |
| Artifact bundle | `selfconnect-enterprise-msi` |
| MSI | `selfconnect-enterprise-1.2.3.msi` |
| Size | `602112` bytes |
| SHA-256 | `9A1CD2F56B6A4CE3AEFC6CC8CF4C5FE09B07F406F6D0E3ED8E62D9591749CF4D` |
| Signed | `false` |
| Generated UTC | `2026-06-21T07:37:59.3265351Z` |

Downloaded artifact bundle contents:

- `selfconnect-enterprise-1.2.3.msi`
- `msi-evidence.json`
- `msi-sha256.txt`

## What changed

Added `.github/workflows/release-msi.yml`.

The workflow runs on manual dispatch and release tags matching `v*` or
`enterprise-v*`. It:

- checks out the repository on `windows-latest`;
- installs Python 3.12 and .NET 8;
- installs WiX `4.0.6` plus the required Util/UI extensions;
- runs `python installer/build_installer.py --wix-path ".tools\wix" --output-dir dist`;
- optionally signs the MSI if `WINDOWS_SIGNING_CERT_BASE64` and
  `WINDOWS_SIGNING_CERT_PASSWORD` secrets are configured;
- records `dist/msi-evidence.json` and `dist/msi-sha256.txt`;
- uploads the MSI, evidence JSON, and hash file as one GitHub artifact bundle;
- publishes those files as GitHub Release assets when the workflow is triggered
  by a release tag.

## Boundary

This closes the CI/release-runner build and manual artifact-upload automation
gap. It does not fake code signing. If no signing certificate secret is
configured, the workflow uploads an unsigned MSI and records that boundary in
`msi-evidence.json`.

Full release signing requires a real Windows code-signing certificate and the
two GitHub secrets named above.
