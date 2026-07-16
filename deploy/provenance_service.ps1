#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Start', 'Stop', 'Status', 'RepairAcl', 'Uninstall')]
    [string]$Action = 'Status',
    [string]$PythonExe = 'C:\ProgramData\SelfConnect\Runtime\Provenance\Scripts\python.exe',
    [string]$WheelPath = '',
    [string]$RootPath = "$env:ProgramData\SelfConnect\Provenance",
    [ValidateSet('enterprise', 'government')]
    [string]$AuditMode = 'enterprise',
    [ValidateSet('memory', 's3', 'r2')]
    [string]$WormSink = 'memory',
    [switch]$FaultAfterRegistration,
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'SelfConnectProvenance'
$ServiceAccount = "NT SERVICE\$ServiceName"

if (-not ('SelfConnect.Provenance.NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace SelfConnect.Provenance {
    public static class NativeMethods {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitNamedPipe(string name, uint timeout);
    }
}
'@
}

function Invoke-Native {
    param([scriptblock]$Command, [string]$Description)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Resolve-SafeRoot {
    $full = [IO.Path]::GetFullPath($RootPath).TrimEnd('\')
    $allowed = [IO.Path]::GetFullPath("$env:ProgramData\SelfConnect").TrimEnd('\') + '\'
    if (-not $full.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "RootPath must remain below $allowed"
    }
    return $full
}

function Get-ServiceSid {
    $account = [System.Security.Principal.NTAccount]::new($ServiceAccount)
    return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Set-HardenedAcl {
    param(
        [string]$Path,
        [string]$ServiceSid,
        [System.Security.AccessControl.FileSystemRights]$ServiceRights,
        [string[]]$ReadSids = @(),
        [string[]]$TraverseSids = @()
    )
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $serviceIdentity = [System.Security.Principal.SecurityIdentifier]::new($ServiceSid)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($adminsSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid, [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, $propagation, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $adminsSid, [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, $propagation, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $serviceIdentity, $ServiceRights, $inheritance, $propagation, $allow)
    )) {
        [void]$acl.AddAccessRule($rule)
    }
    foreach ($sid in $ReadSids) {
        $reader = [System.Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $reader,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    foreach ($sid in $TraverseSids) {
        $traverser = [System.Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $traverser,
            [System.Security.AccessControl.FileSystemRights]::Traverse,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-HardenedFileAcl {
    param(
        [string]$Path,
        [string]$ServiceSid,
        [System.Security.AccessControl.FileSystemRights]$ServiceRights,
        [string[]]$ReadSids = @()
    )
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $serviceIdentity = [System.Security.Principal.SecurityIdentifier]::new($ServiceSid)
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($adminsSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $adminsSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $serviceIdentity, $ServiceRights, $allow)
    )) {
        [void]$acl.AddAccessRule($rule)
    }
    foreach ($sid in $ReadSids) {
        $reader = [System.Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $reader,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-HardenedTreeFileAcls {
    param(
        [string]$Path,
        [string]$ServiceSid,
        [System.Security.AccessControl.FileSystemRights]$ServiceRights,
        [string[]]$ReadSids = @()
    )
    foreach ($file in Get-ChildItem -LiteralPath $Path -File -Recurse -Force) {
        Set-HardenedFileAcl -Path $file.FullName -ServiceSid $ServiceSid `
            -ServiceRights $ServiceRights -ReadSids $ReadSids
    }
}

function Set-HardenedTreeDirectoryAcls {
    param(
        [string]$Path,
        [string]$ServiceSid,
        [System.Security.AccessControl.FileSystemRights]$ServiceRights,
        [string[]]$ReadSids = @()
    )
    foreach ($directory in Get-ChildItem -LiteralPath $Path -Directory -Recurse -Force) {
        Set-HardenedAcl -Path $directory.FullName -ServiceSid $ServiceSid `
            -ServiceRights $ServiceRights -ReadSids $ReadSids
    }
}

function Add-ServiceRuntimeRule {
    param(
        [string]$Path,
        [string]$ServiceSid,
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.InheritanceFlags]$Inheritance
    )
    $identity = [System.Security.Principal.SecurityIdentifier]::new($ServiceSid)
    $acl = Get-Acl -LiteralPath $Path
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        $Rights,
        $Inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Resolve-ServiceRuntimeRoots {
    $runtimeRoot = (& $PythonExe -c 'import sys; print(sys.prefix)').Trim()
    $baseRuntimeRoot = (& $PythonExe -c 'import sys; print(sys.base_prefix)').Trim()
    if ($LASTEXITCODE -ne 0 -or -not $runtimeRoot -or -not $baseRuntimeRoot) {
        throw 'Unable to resolve the dedicated and base Python runtime roots'
    }
    $runtimeRoot = [IO.Path]::GetFullPath($runtimeRoot).TrimEnd('\')
    $baseRuntimeRoot = [IO.Path]::GetFullPath($baseRuntimeRoot).TrimEnd('\')
    $runtimeBase = [IO.Path]::GetFullPath("$env:ProgramData\SelfConnect\Runtime").TrimEnd('\')
    if (-not $runtimeRoot.StartsWith(
        $runtimeBase + '\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "PythonExe must belong to a dedicated runtime below $runtimeBase"
    }
    $userProfile = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
    if ($baseRuntimeRoot.StartsWith(
        $userProfile + '\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'The base Python runtime must not be installed below a user profile'
    }
    return [pscustomobject]@{
        Application = $runtimeRoot
        Base = $baseRuntimeRoot
    }
}

function Grant-ServiceRuntimeAccess {
    param(
        [string]$RuntimeRoot,
        [string]$BaseRuntimeRoot,
        [string]$ServiceSid
    )
    $productRoot = [IO.Path]::GetFullPath("$env:ProgramData\SelfConnect").TrimEnd('\')
    $runtimeBase = Join-Path $productRoot 'Runtime'
    foreach ($path in @($productRoot, $runtimeBase)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "Required product runtime boundary is missing: $path"
        }
        Add-ServiceRuntimeRule -Path $path -ServiceSid $ServiceSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::Traverse) `
            -Inheritance ([System.Security.AccessControl.InheritanceFlags]::None)
    }
    Add-ServiceRuntimeRule -Path $runtimeRoot -ServiceSid $ServiceSid `
        -Rights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -Inheritance (
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        )
    if (-not $baseRuntimeRoot.Equals($runtimeRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Add-ServiceRuntimeRule -Path $baseRuntimeRoot -ServiceSid $ServiceSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
            -Inheritance (
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
    }
    return @($runtimeRoot, $baseRuntimeRoot, $runtimeBase, $productRoot) |
        Sort-Object -Unique
}

function Revoke-ServiceRuntimeAccess {
    param([string[]]$Paths, [string]$ServiceSid)
    if (-not $ServiceSid) { return }
    $identity = [System.Security.Principal.SecurityIdentifier]::new($ServiceSid)
    foreach ($path in @($Paths)) {
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
        $acl = Get-Acl -LiteralPath $path
        $acl.PurgeAccessRules($identity)
        Set-Acl -LiteralPath $path -AclObject $acl
    }
}

function Set-ProvenanceAcls {
    param([string]$Root, [string]$ServiceSid)
    $config = Join-Path $Root 'config'
    $endpoint = Join-Path $Root 'endpoint'
    $identity = Join-Path $Root 'identity'
    $ledger = Join-Path $Root 'ledger'
    $state = Join-Path $Root 'state'
    $enrollment = Join-Path $config 'enrollments.json'
    foreach ($path in @($Root, $config, $endpoint, $identity, $ledger, $state)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "Required service directory is missing: $path"
        }
    }
    if (-not (Test-Path -LiteralPath $enrollment -PathType Leaf)) {
        throw "Required enrollment file is missing: $enrollment"
    }
    $readOnly = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $writeState = [System.Security.AccessControl.FileSystemRights]::Modify
    $enrollmentConfig = Get-Content -Raw -LiteralPath $enrollment | ConvertFrom-Json
    $clientSids = @(
        $enrollmentConfig.agents |
            ForEach-Object { [string]$_.sid } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
    $appendLedger = $readOnly -bor `
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor `
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor `
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    Set-HardenedAcl -Path $Root -ServiceSid $ServiceSid -ServiceRights $readOnly `
        -TraverseSids $clientSids
    Set-HardenedAcl -Path $config -ServiceSid $ServiceSid -ServiceRights $readOnly
    Set-HardenedAcl -Path $endpoint -ServiceSid $ServiceSid -ServiceRights $writeState `
        -ReadSids $clientSids
    Set-HardenedAcl -Path $identity -ServiceSid $ServiceSid -ServiceRights $writeState
    Set-HardenedAcl -Path $ledger -ServiceSid $ServiceSid -ServiceRights $appendLedger
    Set-HardenedAcl -Path $state -ServiceSid $ServiceSid -ServiceRights $writeState
    Set-HardenedTreeDirectoryAcls -Path $config -ServiceSid $ServiceSid `
        -ServiceRights $readOnly
    Set-HardenedTreeDirectoryAcls -Path $endpoint -ServiceSid $ServiceSid `
        -ServiceRights $writeState -ReadSids $clientSids
    Set-HardenedTreeDirectoryAcls -Path $identity -ServiceSid $ServiceSid `
        -ServiceRights $writeState
    Set-HardenedTreeDirectoryAcls -Path $ledger -ServiceSid $ServiceSid `
        -ServiceRights $appendLedger
    Set-HardenedTreeDirectoryAcls -Path $state -ServiceSid $ServiceSid `
        -ServiceRights $writeState
    Set-HardenedTreeFileAcls -Path $config -ServiceSid $ServiceSid -ServiceRights $readOnly
    Set-HardenedTreeFileAcls -Path $endpoint -ServiceSid $ServiceSid `
        -ServiceRights $writeState -ReadSids $clientSids
    Set-HardenedTreeFileAcls -Path $identity -ServiceSid $ServiceSid -ServiceRights $writeState
    Set-HardenedTreeFileAcls -Path $ledger -ServiceSid $ServiceSid -ServiceRights $appendLedger
    Set-HardenedTreeFileAcls -Path $state -ServiceSid $ServiceSid -ServiceRights $writeState
    Set-HardenedFileAcl -Path $enrollment -ServiceSid $ServiceSid -ServiceRights $readOnly
}

function Wait-IdentityBootstrap {
    param([string]$IdentityPublicKey, [int]$Seconds = 30)
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 100
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
    } while ($service.Status -ne 'Stopped' -and (Get-Date) -lt $deadline)
    if ($service.Status -ne 'Stopped' -or -not (Test-Path -LiteralPath $IdentityPublicKey)) {
        throw 'dedicated service-token identity bootstrap did not complete cleanly'
    }
}

function Wait-ProvenanceReady {
    param(
        [string]$EndpointFile,
        [string]$ExpectedServiceSid,
        [string]$ExpectedAgentId,
        [int]$Seconds = 30
    )
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 100
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($service.Status -eq 'Stopped') {
            throw 'provenance service stopped before publishing its endpoint'
        }
        if (Test-Path -LiteralPath $EndpointFile) {
            try {
                $endpoint = Get-Content -Raw -LiteralPath $EndpointFile | ConvertFrom-Json
                $pipeName = [string]$endpoint.pipe_name
                $valid = [string]$endpoint.version -eq 'selfconnect.provenance.endpoint.v1' -and `
                    $pipeName.StartsWith('\\.\pipe\SelfConnectProvenance.v1.') -and `
                    [string]$endpoint.service_sid -eq $ExpectedServiceSid -and `
                    [string]$endpoint.service_agent_id -eq $ExpectedAgentId -and `
                    [int]$endpoint.service_pid -gt 0 -and `
                    [string]$endpoint.instance_id
                if (
                    $valid -and
                    [SelfConnect.Provenance.NativeMethods]::WaitNamedPipe($pipeName, 100)
                ) {
                    return $endpoint
                }
            } catch {
                # Retry only while the service remains running and the bounded deadline remains.
            }
        }
    } while ((Get-Date) -lt $deadline)
    throw 'provenance service did not publish a live identity-bound endpoint'
}

function Install-ProvenanceService {
    $root = Resolve-SafeRoot
    if ($AuditMode -eq 'government' -and $WormSink -notin @('s3', 'r2')) {
        throw 'government mode requires a provider-verified s3 or r2 retention sink'
    }
    if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
        throw "Python executable not found: $PythonExe"
    }
    if (-not $WheelPath -or -not (Test-Path -LiteralPath $WheelPath -PathType Leaf)) {
        throw 'Install requires -WheelPath pointing to the reviewed selfconnect-enterprise wheel'
    }
    $pythonRuntime = Resolve-ServiceRuntimeRoots
    $wheel = (Resolve-Path -LiteralPath $WheelPath).Path
    $wheelHash = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash
    Write-Host "Installing reviewed wheel SHA256=$wheelHash"
    Invoke-Native {
        & $PythonExe -m pip install --force-reinstall --no-deps $wheel
    } 'exact reviewed wheel installation'
    $serviceHostProbe = @(
        'import sys',
        'import enterprise.provenance_service as service',
        'service_class = service.SelfConnectProvenanceService',
        'print(service_class._exe_name_)',
        'raise SystemExit(0 if service_class._exe_name_ == sys.executable and service_class._exe_args_ == sys.argv[1] else 1)'
    ) -join '; '
    Invoke-Native {
        & $PythonExe -c $serviceHostProbe '-m enterprise.provenance_service'
    } 'service host verification'

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        throw "$ServiceName already exists; uninstall it before a clean install"
    }
    $registered = $false
    $runtimeAclPaths = @()
    $serviceSid = $null
    try {
        Invoke-Native {
            & $PythonExe -m enterprise.provenance_service `
                --startup delayed --username $ServiceAccount install
        } 'pywin32 service registration'
        $registered = $true
        if ($FaultAfterRegistration) {
            throw 'operator-requested post-registration acceptance fault'
        }
        Invoke-Native { sc.exe sidtype $ServiceName restricted } 'service SID restriction'
        $config = Join-Path $root 'config'
        $endpoint = Join-Path $root 'endpoint'
        $identity = Join-Path $root 'identity'
        $ledger = Join-Path $root 'ledger'
        $state = Join-Path $root 'state'
        foreach ($path in @($root, $config, $endpoint, $identity, $ledger, $state)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        $enrollment = Join-Path $config 'enrollments.json'
        if (-not (Test-Path -LiteralPath $enrollment)) {
            [IO.File]::WriteAllText(
                $enrollment,
                "{`"agents`":[],`"version`":1}`n",
                [Text.Encoding]::ASCII
            )
        }

        $serviceSid = Get-ServiceSid
        $runtimeAclPaths = @(Grant-ServiceRuntimeAccess `
            -RuntimeRoot $pythonRuntime.Application `
            -BaseRuntimeRoot $pythonRuntime.Base `
            -ServiceSid $serviceSid)
        Set-ProvenanceAcls -Root $root -ServiceSid $serviceSid

        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        New-ItemProperty -Path $serviceKey -Name ProvenanceRuntimeAclPaths `
            -PropertyType MultiString -Value $runtimeAclPaths -Force | Out-Null
        $environment = @(
            "SC_PROVENANCE_SERVICE_ROOT=$root",
            "SCENT_AUDIT_MODE=$AuditMode",
            "SCENT_WORM_SINK=$WormSink",
            'SC_PROVENANCE_BOOTSTRAP_IDENTITY=1'
        )
        New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString `
            -Value $environment -Force | Out-Null
        $identityPublic = Join-Path $identity "$ServiceName\identity.pub"
        Start-Service -Name $ServiceName
        Wait-IdentityBootstrap -IdentityPublicKey $identityPublic
        $environment = @(
            "SC_PROVENANCE_SERVICE_ROOT=$root",
            "SCENT_AUDIT_MODE=$AuditMode",
            "SCENT_WORM_SINK=$WormSink"
        )
        Set-ProvenanceAcls -Root $root -ServiceSid $serviceSid
        New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString `
            -Value $environment -Force | Out-Null
        $endpointFile = Join-Path $endpoint 'current.json'
        if (Test-Path -LiteralPath $endpointFile) {
            Remove-Item -LiteralPath $endpointFile -Force -ErrorAction Stop
        }
        Invoke-Native {
            sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/15000/restart/30000
        } 'service recovery configuration'
        Invoke-Native { sc.exe failureflag $ServiceName 1 } 'non-crash failure recovery configuration'
        $publicKeyHex = (Get-Content -Raw -LiteralPath $identityPublic).Trim()
        $agentId = (& $PythonExe -c (
            "import hashlib,sys; print('SC-' + hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest()[:8].upper())"
        ) $publicKeyHex).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $agentId) {
            throw 'service agent identity derivation failed'
        }
        Start-Service -Name $ServiceName
        Wait-ProvenanceReady -EndpointFile $endpointFile `
            -ExpectedServiceSid $serviceSid -ExpectedAgentId $agentId | Out-Null
        Write-Host "$ServiceName installed and running as $ServiceAccount ($serviceSid)"
        Write-Host "Enrollment file: $enrollment"
        Write-Host 'Restart the service after every reviewed enrollment change.'
    } catch {
        $original = $_
        $rollbackFailures = [Collections.Generic.List[string]]::new()
        if ($runtimeAclPaths.Count -gt 0 -and $serviceSid) {
            try {
                Revoke-ServiceRuntimeAccess -Paths $runtimeAclPaths -ServiceSid $serviceSid
            } catch {
                $rollbackFailures.Add(
                    "runtime ACL revocation failed: $($_.Exception.Message)"
                )
            }
        }
        if ($registered -or (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            try {
                $partial = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($partial -and $partial.Status -ne 'Stopped') {
                    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                    $partial.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
                }
                Invoke-Native {
                    & $PythonExe -m enterprise.provenance_service remove | Out-Null
                } 'partial service registration removal'
                $deadline = (Get-Date).AddSeconds(15)
                while (
                    (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and
                    (Get-Date) -lt $deadline
                ) {
                    Start-Sleep -Milliseconds 100
                }
                if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
                    throw "partial $ServiceName registration remains after removal"
                }
            } catch {
                $rollbackFailures.Add(
                    "service registration removal failed: $($_.Exception.Message)"
                )
            }
        }
        if ($rollbackFailures.Count -gt 0) {
            throw [InvalidOperationException]::new(
                "Install failed: $($original.Exception.Message); rollback failed: " +
                    ($rollbackFailures -join '; '),
                $original.Exception
            )
        }
        throw $original
    }
}

function Show-Status {
    $root = Resolve-SafeRoot
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "$ServiceName is not installed"
        return
    }
    $sid = Get-ServiceSid
    $identityPublic = Join-Path $root "identity\$ServiceName\identity.pub"
    $endpointFile = Join-Path $root 'endpoint\current.json'
    [ordered]@{
        service = $ServiceName
        state = $service.Status.ToString()
        account = $ServiceAccount
        service_sid = $sid
        root = $root
        public_key_file = if (Test-Path -LiteralPath $identityPublic) { $identityPublic } else { $null }
        public_key_file_sha256 = if (Test-Path -LiteralPath $identityPublic) {
            (Get-FileHash -LiteralPath $identityPublic -Algorithm SHA256).Hash
        } else { $null }
        endpoint_file = $endpointFile
        pipe_name = if (Test-Path -LiteralPath $endpointFile) {
            (Get-Content -Raw -LiteralPath $endpointFile | ConvertFrom-Json).pipe_name
        } else { $null }
    } | ConvertTo-Json
}

switch ($Action) {
    'Install' { Install-ProvenanceService }
    'Start' {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Show-Status
    }
    'Stop' {
        Stop-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        Show-Status
    }
    'Status' { Show-Status }
    'RepairAcl' {
        $root = Resolve-SafeRoot
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            throw "$ServiceName is not installed"
        }
        Set-ProvenanceAcls -Root $root -ServiceSid (Get-ServiceSid)
        Write-Host "Reapplied the exact service-SID ACL contract below $root"
    }
    'Uninstall' {
        $root = Resolve-SafeRoot
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $serviceSid = if ($service) { Get-ServiceSid } else { $null }
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $runtimeAclPaths = if (Test-Path -LiteralPath $serviceKey) {
            @((Get-ItemProperty -LiteralPath $serviceKey -Name ProvenanceRuntimeAclPaths `
                -ErrorAction SilentlyContinue).ProvenanceRuntimeAclPaths)
        } else { @() }
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        if ($service) {
            Invoke-Native { & $PythonExe -m enterprise.provenance_service remove } 'service removal'
        }
        if ($runtimeAclPaths.Count -gt 0 -and $serviceSid) {
            Revoke-ServiceRuntimeAccess -Paths $runtimeAclPaths -ServiceSid $serviceSid
        }
        if ($PurgeData) {
            $verified = Resolve-SafeRoot
            Remove-Item -LiteralPath $verified -Recurse -Force
        } else {
            Write-Host "Preserved provenance data at $root"
        }
    }
}
