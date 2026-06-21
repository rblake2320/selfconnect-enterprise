# MSI Release Automation Evidence

**Date:** 2026-06-21  
**Verdict:** AUTOMATED BUILD PATH ADDED  
**Scope:** GitHub Actions workflow for building and publishing the SelfConnect
Enterprise MSI as a release artifact bundle.

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

This closes the CI/release-runner build and release-asset publication automation
gap. It does not fake code signing. If no signing certificate secret is
configured, the workflow uploads an unsigned MSI and records that boundary in
`msi-evidence.json`.

Full release signing requires a real Windows code-signing certificate and the
two GitHub secrets named above.
