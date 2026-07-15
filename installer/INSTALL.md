# SelfConnect Enterprise — Installation Guide

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Windows | 10 22H2 / Server 2019 | x64 only |
| Python | 3.10+ | Must be on `PATH` or accessible via `py.exe` launcher |
| Visual C++ Redistributable | 2015–2022 x64 | Required by native wheel dependencies |
| TPM | TPM 2.0 recommended | Required for hardware-backed identity leases; software fallback available |
| Disk space | ~50 MB install + variable logs | `%ProgramData%\SelfConnectEnterprise` grows with audit receipts |
| Administrator rights | Required | Service installation and PATH modification need elevation |

---

## MSI Install

### Standard (GUI)

```cmd
msiexec /i selfconnect-enterprise-VERSION.msi
```

Accept the UAC prompt. The installer will:

1. Install files to `%ProgramFiles%\SelfConnectEnterprise`
2. Run `pip install` to register the Python package
3. Create `%ProgramData%\SelfConnectEnterprise\logs\` and `config\`
4. Register and start the `SelfConnectEnterprise` Windows Service
5. Add `%ProgramFiles%\SelfConnectEnterprise\Scripts` to the system `PATH`
6. Register an Application EventLog source

### Silent (enterprise IT / GPO deployment)

```cmd
msiexec /i selfconnect-enterprise-VERSION.msi /quiet /norestart SCENT_AUDIT_MODE=enterprise
```

Supported properties:

| Property | Default | Description |
|----------|---------|-------------|
| `SCENT_AUDIT_MODE` | `standard` | Sets audit verbosity (`standard`, `enterprise`, `airgap`) |
| `INSTALLDIR` | `%ProgramFiles%\SelfConnectEnterprise` | Override install location |

---

## Verify — Service

```cmd
sc query SelfConnectEnterprise
```

Expected output:

```
SERVICE_NAME: SelfConnectEnterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
        ...
```

Check the EventLog:

```powershell
Get-EventLog -LogName Application -Source SelfConnectEnterprise -Newest 10
```

---

## Verify — CLI

```cmd
scent version
```

Expected:

```
SelfConnect Enterprise v1.2.3
```

If `scent` is not found, open a new shell (the PATH change requires a new process) or run:

```powershell
refreshenv   # if Chocolatey is installed
# or restart Explorer
```

---

## Uninstall

### GUI

```cmd
msiexec /x selfconnect-enterprise-VERSION.msi
```

Or use **Settings > Apps > Installed Apps > SelfConnect Enterprise > Uninstall**.

### Silent

```cmd
msiexec /x selfconnect-enterprise-VERSION.msi /quiet /norestart
```

**What is preserved on uninstall:**

- `%ProgramData%\SelfConnectEnterprise\logs\` — audit receipts are not deleted
- `%ProgramData%\SelfConnectEnterprise\config\` — configuration is not deleted

To fully purge (destructive):

```powershell
Remove-Item -Recurse -Force "$env:ProgramData\SelfConnectEnterprise"
```

---

## Building the Installer from Source

Requirements: Python 3.10+, `pip install build`, WiX v4 toolset.

```cmd
python installer\build_installer.py
```

Optional flags:

```
--wix-path <dir>    Path to WiX bin directory (if not on PATH)
--output-dir <dir>  Where to write the .msi (default: dist/)
--skip-wheel        Re-use an already-staged wheel in installer\dist\
```

---

## Troubleshooting

### Service fails to start

1. Check the Application EventLog: `eventvwr.msc`
2. Check `%ProgramData%\SelfConnectEnterprise\logs\service.log`
3. Confirm Python is available to `LocalSystem`:
   ```cmd
   psexec -s py.exe --version
   ```

### `scent` not found after install

- Open a new terminal — PATH changes are not inherited by running processes.
- Confirm the registry entry:
  ```powershell
  (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").Path
  ```

### pip install failed during MSI setup

- Check the MSI install log: `msiexec /i ... /l*v install.log`
- Look for `CA_PipInstallWheel` errors in `install.log`.
- Ensure the target machine has internet access (or provide a pre-seeded pip cache).

### Hardware-key capability unavailable

The service can use software-backed identity and separately reports local TPM
capability. The current installer does not establish hardware-bound agent
identity, remote attestation, compliance, or authorization. If a deployment
requires a Platform-KSP key path, first ensure:

- TPM 2.0 is enabled in BIOS
- The `TBS` (TPM Base Services) Windows service is running
- The service account (`LocalSystem`) has TPM access

Then verify the exact key provider and key hardware property in the deployed
service context. TPM presence alone is not sufficient evidence.

### Upgrade from a previous version

Run the new MSI directly — `MajorUpgrade` in the installer handles stopping the old
service, replacing files, and restarting automatically. No manual uninstall required.
