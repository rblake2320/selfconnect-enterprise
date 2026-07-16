#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Start', 'Stop', 'Status', 'RepairAcl', 'Uninstall')]
    [string]$Action = 'Status',
    [string]$PythonExe = 'C:\Python312\python.exe',
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
    Set-HardenedTreeFileAcls -Path $config -ServiceSid $ServiceSid -ServiceRights $readOnly
    Set-HardenedTreeFileAcls -Path $endpoint -ServiceSid $ServiceSid `
        -ServiceRights $writeState -ReadSids $clientSids
    Set-HardenedTreeFileAcls -Path $identity -ServiceSid $ServiceSid -ServiceRights $writeState
    Set-HardenedTreeFileAcls -Path $ledger -ServiceSid $ServiceSid -ServiceRights $appendLedger
    Set-HardenedTreeFileAcls -Path $state -ServiceSid $ServiceSid -ServiceRights $writeState
    Set-HardenedFileAcl -Path $enrollment -ServiceSid $ServiceSid -ServiceRights $readOnly
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
    $wheel = (Resolve-Path -LiteralPath $WheelPath).Path
    $wheelHash = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash
    Write-Host "Installing reviewed wheel SHA256=$wheelHash"
    Invoke-Native {
        & $PythonExe -m pip install --force-reinstall --no-deps $wheel
    } 'exact reviewed wheel installation'
    $serviceHostProbe = @(
        'import pathlib',
        'import win32serviceutil',
        'import enterprise.provenance_service',
        'service_exe = pathlib.Path(win32serviceutil.LocatePythonServiceExe())',
        'print(service_exe)',
        'raise SystemExit(0 if service_exe.is_file() else 1)'
    ) -join '; '
    Invoke-Native { & $PythonExe -c $serviceHostProbe } 'service host verification'

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        throw "$ServiceName already exists; uninstall it before a clean install"
    }
    $registered = $false
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
        Invoke-Native {
            sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/15000/restart/30000
        } 'service recovery configuration'
        Invoke-Native { sc.exe failureflag $ServiceName 1 } 'non-crash failure recovery configuration'

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
        Set-ProvenanceAcls -Root $root -ServiceSid $serviceSid

        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $environment = @(
            "SC_PROVENANCE_SERVICE_ROOT=$root",
            "SCENT_AUDIT_MODE=$AuditMode",
            "SCENT_WORM_SINK=$WormSink"
        )
        New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString `
            -Value $environment -Force | Out-Null
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Write-Host "$ServiceName installed and running as $ServiceAccount ($serviceSid)"
        Write-Host "Enrollment file: $enrollment"
        Write-Host 'Restart the service after every reviewed enrollment change.'
    } catch {
        $original = $_
        if ($registered -or (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            try {
                $partial = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($partial -and $partial.Status -ne 'Stopped') {
                    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                    $partial.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
                }
                & $PythonExe -m enterprise.provenance_service remove | Out-Null
            } catch {
                Write-Warning "Failed to remove partial $ServiceName registration: $($_.Exception.Message)"
            }
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
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        if ($service) {
            Invoke-Native { & $PythonExe -m enterprise.provenance_service remove } 'service removal'
        }
        if ($PurgeData) {
            $verified = Resolve-SafeRoot
            Remove-Item -LiteralPath $verified -Recurse -Force
        } else {
            Write-Host "Preserved provenance data at $root"
        }
    }
}
