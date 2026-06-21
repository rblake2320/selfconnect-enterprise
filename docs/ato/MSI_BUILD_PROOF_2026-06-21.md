# SelfConnect Enterprise - MSI Build Proof

**Date:** 2026-06-21  
**Verdict:** PASS  
**Scope:** Local WiX build of `selfconnect-enterprise-1.2.3.msi`.

## Summary

The MSI build gate is now closed locally. A user-local .NET SDK and repo-local WiX v4 toolchain were used to build the installer from `installer/selfconnect-enterprise.wxs`.

The installer source required two WiX v4 compatibility fixes:

- Removed unsupported `Id` attributes from `util:PermissionEx` and `util:EventSource`.
- Removed the optional `WixUI_Minimal` UI reference that was inaccessible under the installed WiX v4 extension package.

## Build Output

| Field | Value |
|---|---|
| Tool | WiX `4.0.6` |
| .NET SDK | `8.0.422` user-local |
| MSI path | `dist/selfconnect-enterprise-1.2.3.msi` |
| Size | `602112` bytes |
| SHA-256 | `C3865DD770D530E448C7F32C4851DCCD2B6B349160F356269CE1F32C7621F23D` |

## Reproduce

```powershell
$env:PATH = "$(Join-Path (Get-Location) '.tools\wix');$env:USERPROFILE\.dotnet-sdk-selfconnect;$env:PATH"
python installer\build_installer.py --wix-path ".tools\wix" --output-dir dist
Get-FileHash dist\selfconnect-enterprise-1.2.3.msi -Algorithm SHA256
```

## Boundary

The MSI binary is a build artifact and is not committed to source control. Release automation should install the .NET SDK and WiX v4 on the release runner, build the MSI, sign it, and publish it as a release artifact.
