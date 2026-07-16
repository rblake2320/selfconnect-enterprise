#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$PythonExe = 'C:\Python312\python.exe',
    [Parameter(Mandatory = $true)]
    [string]$WheelPath,
    [string]$EvidencePath = '',
    [int]$BurstCount = 40
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'SelfConnectProvenance'
$PipeName = $null
$DeployScript = Join-Path $PSScriptRoot 'provenance_service.ps1'
$HelperSource = Join-Path $PSScriptRoot 'provenance_acceptance_client.py'
$RunId = (Get-Date -Format 'yyyyMMddHHmmss') + '-' + ([Guid]::NewGuid().ToString('N').Substring(0, 6))
$UserId = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$AgentUser = "scpa-$UserId"
$AnonymousUser = "scpx-$UserId"
$AcceptanceRoot = Join-Path $env:ProgramData "SelfConnect\ProvenanceAcceptance\$RunId"
$ServiceRoot = Join-Path $env:ProgramData "SelfConnect\Provenance-$RunId"
$Helper = Join-Path $AcceptanceRoot 'provenance_acceptance_client.py'
$ConfigPath = Join-Path $AcceptanceRoot 'config.json'
$BootstrapPath = Join-Path $AcceptanceRoot 'bootstrap.json'
$WheelBindingPath = Join-Path $AcceptanceRoot 'wheel-binding.json'
$ExercisePath = Join-Path $AcceptanceRoot 'exercise.json'
$AnonymousPath = Join-Path $AcceptanceRoot 'anonymous.json'
$DaclProbePath = Join-Path $AcceptanceRoot 'dacl-probe.json'
$BurstPath = Join-Path $AcceptanceRoot 'burst.json'
$BurstReady = Join-Path $AcceptanceRoot 'burst.ready'
$BurstGo = Join-Path $AcceptanceRoot 'burst.go'
$SquatReady = Join-Path $AcceptanceRoot 'squat.ready'
$SquatStop = Join-Path $AcceptanceRoot 'squat.stop'
$TranscriptPath = Join-Path $AcceptanceRoot 'acceptance-transcript.txt'
$ReportPath = if ($EvidencePath) {
    [IO.Path]::GetFullPath($EvidencePath)
} else {
    Join-Path $AcceptanceRoot 'acceptance-report.json'
}
$CreatedUsers = [Collections.Generic.List[string]]::new()
$TranscriptStarted = $false
$Results = [ordered]@{
    schema = 'selfconnect.provenance.acceptance.v1'
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    service = $ServiceName
    pipe = $null
    checks = [ordered]@{}
    artifacts = [ordered]@{}
    blind_spots = @(
        'No off-host WORM sink was configured for this local service-boundary drill.',
        'Remote-host named-pipe rejection requires a second Windows host and is not claimed by this drill.'
    )
}

function Invoke-Native {
    param([scriptblock]$Command, [string]$Description)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function New-DisposableUser {
    param([string]$Name)
    $password = "Sc!" + [Guid]::NewGuid().ToString('N') + 'aA1'
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $Name -Password $secure -AccountNeverExpires -PasswordNeverExpires `
        -UserMayNotChangePassword | Out-Null
    $CreatedUsers.Add($Name)
    $sid = ([System.Security.Principal.NTAccount]::new("$env:COMPUTERNAME\$Name")).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    return [pscustomobject]@{
        Credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$Name", $secure)
        Sid = $sid
    }
}

function Invoke-AsUser {
    param(
        [Management.Automation.PSCredential]$Credential,
        [string[]]$Arguments,
        [string]$Description,
        [switch]$NoWait
    )
    $stdout = Join-Path $AcceptanceRoot (([Guid]::NewGuid().ToString('N')) + '.stdout.txt')
    $stderr = Join-Path $AcceptanceRoot (([Guid]::NewGuid().ToString('N')) + '.stderr.txt')
    $process = Start-Process -FilePath $PythonExe -ArgumentList $Arguments `
        -Credential $Credential -WorkingDirectory $AcceptanceRoot -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    if ($NoWait) {
        return $process
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        $detail = if (Test-Path -LiteralPath $stderr) { Get-Content -Raw $stderr } else { '' }
        throw "$Description failed with exit code $($process.ExitCode): $detail"
    }
    return $process
}

function Get-ServiceSid {
    return ([System.Security.Principal.NTAccount]::new("NT SERVICE\$ServiceName")).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
}

function Get-AgentIdFromPublicKey {
    param([string]$PublicKeyHex)
    $bytes = New-Object byte[] ($PublicKeyHex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($PublicKeyHex.Substring($index * 2, 2), 16)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }
    return 'SC-' + (($digest[0..3] | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
}

function Wait-ServiceState {
    param([string]$State, [int]$Seconds = 45)
    (Get-Service -Name $ServiceName).WaitForStatus($State, [TimeSpan]::FromSeconds($Seconds))
}

try {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        throw "$ServiceName is already installed; acceptance requires a clean service slot"
    }
    if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
        throw "Python executable not found: $PythonExe"
    }
    $wheel = (Resolve-Path -LiteralPath $WheelPath).Path
    $wheelHash = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash.ToLowerInvariant()
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $sourceCommit = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'source commit lookup failed' }
    $sourceDirty = @(& git -C $repoRoot status --short --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $sourceDirty.Count -ne 0) {
        throw 'acceptance requires a clean source tree at one exact commit'
    }
    New-Item -ItemType Directory -Path $AcceptanceRoot -Force | Out-Null
    Copy-Item -LiteralPath $HelperSource -Destination $Helper
    & $PythonExe $Helper verify-wheel --wheel $wheel --repo-root $repoRoot `
        --output $WheelBindingPath
    if ($LASTEXITCODE -ne 0) { throw 'wheel does not match the exact clean source tree' }
    $wheelBinding = Get-Content -Raw $WheelBindingPath | ConvertFrom-Json
    $Results.checks.wheel_matches_source_commit = [bool]$wheelBinding.ok
    $Results.artifacts.wheel_source_binding = $wheelBinding
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $TranscriptStarted = $true

    $agent = New-DisposableUser -Name $AgentUser
    $anonymous = New-DisposableUser -Name $AnonymousUser
    Invoke-Native {
        icacls.exe $AcceptanceRoot /inheritance:r `
            /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" `
            "*$($agent.Sid):(OI)(CI)M" "*$($anonymous.Sid):(OI)(CI)M"
    } 'acceptance workspace ACL'

    $faultObserved = $false
    try {
        & $DeployScript -Action Install -PythonExe $PythonExe -WheelPath $wheel `
            -RootPath $ServiceRoot -AuditMode enterprise -WormSink memory `
            -FaultAfterRegistration
    } catch {
        $faultObserved = $_.Exception.Message -match 'post-registration acceptance fault'
    }
    $Results.checks.partial_install_rolls_back = $faultObserved -and `
        -not [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
    if (-not $Results.checks.partial_install_rolls_back) {
        throw 'post-registration fault did not roll back the partial service'
    }

    & $DeployScript -Action Install -PythonExe $PythonExe -WheelPath $wheel `
        -RootPath $ServiceRoot -AuditMode enterprise -WormSink memory
    $Results.checks.scm_install = (Get-Service -Name $ServiceName).Status -eq 'Running'
    $serviceConfig = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    $Results.artifacts.service_account = $serviceConfig.StartName
    $Results.artifacts.service_start_mode = $serviceConfig.StartMode
    $Results.artifacts.service_sid = Get-ServiceSid
    $Results.artifacts.client_sid = $agent.Sid
    $Results.artifacts.anonymous_sid = $anonymous.Sid
    $Results.artifacts.service_config = @(& sc.exe qc $ServiceName)
    $Results.artifacts.service_sid_type = @(& sc.exe qsidtype $ServiceName)
    $Results.artifacts.service_failure_actions = @(& sc.exe qfailure $ServiceName)
    $Results.checks.dedicated_service_account = $serviceConfig.StartName -eq "NT SERVICE\$ServiceName"

    Invoke-AsUser -Credential $agent.Credential -Description 'agent identity bootstrap' -Arguments @(
        $Helper, 'bootstrap', '--identity-dir', (Join-Path $AcceptanceRoot 'agent-identity'),
        '--name', 'provenance-acceptance-agent', '--output', $BootstrapPath
    ) | Out-Null
    $bootstrap = Get-Content -Raw $BootstrapPath | ConvertFrom-Json
    & $PythonExe -m enterprise.provenance_admin --file (Join-Path $ServiceRoot 'config\enrollments.json') `
        enroll --agent-id $bootstrap.agent_id --algorithm $bootstrap.algorithm `
        --public-key-hex $bootstrap.public_key_hex --sid $agent.Sid
    if ($LASTEXITCODE -ne 0) { throw 'agent enrollment failed' }
    & $DeployScript -Action RepairAcl -PythonExe $PythonExe -RootPath $ServiceRoot
    Restart-Service -Name $ServiceName
    Wait-ServiceState -State Running

    $endpointFile = Join-Path $ServiceRoot 'endpoint\current.json'
    $endpoint = Get-Content -Raw -LiteralPath $endpointFile | ConvertFrom-Json
    $PipeName = [string]$endpoint.pipe_name
    $Results.pipe = $PipeName
    $servicePublicKeyPath = Join-Path $ServiceRoot 'identity\SelfConnectProvenance\identity.pub'
    $servicePublicKeyHex = (Get-Content -Raw $servicePublicKeyPath).Trim()
    $serviceAgentId = Get-AgentIdFromPublicKey -PublicKeyHex $servicePublicKeyHex
    $sentinel = Join-Path $ServiceRoot 'ledger\acceptance-sentinel.dat'
    [IO.File]::WriteAllText($sentinel, "sentinel`n", [Text.Encoding]::ASCII)
    [ordered]@{
        identity_dir = (Join-Path $AcceptanceRoot 'agent-identity')
        identity_name = 'provenance-acceptance-agent'
        endpoint_file = $endpointFile
        ledger_dir = (Join-Path $ServiceRoot 'ledger')
        pipe_name = $PipeName
        sentinel_path = $sentinel
        service_agent_id = $serviceAgentId
        service_algorithm = 'ed25519'
        service_public_key_hex = $servicePublicKeyHex
        service_sid = $Results.artifacts.service_sid
        timeout_ms = 5000
    } | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

    Invoke-AsUser -Credential $agent.Credential -Description 'enrolled agent adversarial exercise' `
        -Arguments @($Helper, 'exercise', '--config', $ConfigPath, '--output', $ExercisePath) | Out-Null
    $exercise = Get-Content -Raw $ExercisePath | ConvertFrom-Json
    $Results.checks.enrolled_agent_contract = [bool]$exercise.ok
    $Results.artifacts.enrolled_agent_checks = $exercise.checks
    $Results.artifacts.valid_request_id = $exercise.valid_request_id

    Invoke-AsUser -Credential $anonymous.Credential -Description 'anonymous pipe denial' `
        -Arguments @($Helper, 'probe-connect', '--config', $ConfigPath, '--output', $AnonymousPath) | Out-Null
    $anonymousResult = Get-Content -Raw $AnonymousPath | ConvertFrom-Json
    $Results.checks.anonymous_pipe_denied = [bool]$anonymousResult.access_denied
    $Results.artifacts.anonymous_winerror = $anonymousResult.winerror

    Stop-Service -Name $ServiceName
    Wait-ServiceState -State Stopped
    $oldPipeName = $PipeName
    $squatter = Invoke-AsUser -Credential $anonymous.Credential -Description 'pipe squatter' -NoWait `
        -Arguments @($Helper, 'hold-pipe', '--config', $ConfigPath, '--ready', $SquatReady,
            '--stop', $SquatStop, '--timeout', '45', '--pipe-name', $oldPipeName)
    $readyDeadline = (Get-Date).AddSeconds(15)
    while (-not (Test-Path -LiteralPath $SquatReady) -and (Get-Date) -lt $readyDeadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $SquatReady)) { throw 'pipe squatter did not become ready' }
    Start-Service -Name $ServiceName
    Wait-ServiceState -State Running
    $rotatedEndpoint = Get-Content -Raw -LiteralPath $endpointFile | ConvertFrom-Json
    $PipeName = [string]$rotatedEndpoint.pipe_name
    $Results.checks.pipe_rotation_survives_old_name_squatting = `
        $PipeName -and $PipeName -ne $oldPipeName
    $Results.artifacts.pipe_before_restart = $oldPipeName
    $Results.artifacts.pipe_after_restart = $PipeName
    New-Item -ItemType File -Path $SquatStop -Force | Out-Null
    $squatter.WaitForExit(15000)
    if (-not $squatter.HasExited -or $squatter.ExitCode -ne 0) {
        throw 'pipe squatter did not exit cleanly'
    }
    Stop-Service -Name $ServiceName
    Wait-ServiceState -State Stopped
    Invoke-Native {
        icacls.exe $sentinel /grant '*S-1-5-32-545:M'
    } 'existing ledger-file DACL tamper injection'
    & $PythonExe $Helper verify-dacl --path $sentinel `
        --service-sid $Results.artifacts.service_sid --client-sid $agent.Sid `
        --output $DaclProbePath
    if ($LASTEXITCODE -ne 0) { throw 'DACL tamper preflight command failed' }
    $daclProbeResult = Get-Content -Raw $DaclProbePath | ConvertFrom-Json
    $Results.artifacts.dacl_tamper_preflight = $daclProbeResult
    $tamperBlocked = $false
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 2
        $tamperBlocked = (Get-Service -Name $ServiceName).Status -ne 'Running'
    } catch {
        $tamperBlocked = $true
    }
    $Results.checks.dacl_tamper_blocks_service_readiness = $tamperBlocked -and `
        [bool]$daclProbeResult.blocked -and `
        [string]$daclProbeResult.error_type -eq 'ProvenanceServiceConfigurationError'
    $tamperedService = Get-Service -Name $ServiceName
    if ($tamperedService.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        Wait-ServiceState -State Stopped
    }
    & $DeployScript -Action RepairAcl -PythonExe $PythonExe -RootPath $ServiceRoot
    Start-Service -Name $ServiceName
    Wait-ServiceState -State Running

    $burst = Invoke-AsUser -Credential $agent.Credential -Description 'restart burst' -NoWait `
        -Arguments @($Helper, 'burst', '--config', $ConfigPath, '--output', $BurstPath,
            '--count', $BurstCount.ToString(), '--workers', '8', '--retries', '40',
            '--retry-delay', '0.5', '--ready', $BurstReady, '--go', $BurstGo)
    $burstReadyDeadline = (Get-Date).AddSeconds(15)
    while (-not (Test-Path -LiteralPath $BurstReady) -and (Get-Date) -lt $burstReadyDeadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $BurstReady)) { throw 'restart burst did not become ready' }
    $serviceProcess = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $serviceProcess.ProcessId) { throw 'service process ID was not available' }
    $killedProcessId = [int]$serviceProcess.ProcessId
    Stop-Process -Id $serviceProcess.ProcessId -Force
    $stoppedDeadline = (Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 50
        $afterKill = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    } while ($afterKill.ProcessId -eq $killedProcessId -and (Get-Date) -lt $stoppedDeadline)
    if ($afterKill.ProcessId -eq $killedProcessId) {
        throw 'SCM did not observe the killed provenance service process'
    }
    New-Item -ItemType File -Path $BurstGo -Force | Out-Null
    $restartDeadline = (Get-Date).AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 250
        $restartedService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    } while ((
        $restartedService.State -ne 'Running' -or
        -not $restartedService.ProcessId -or
        $restartedService.ProcessId -eq $killedProcessId
    ) -and (Get-Date) -lt $restartDeadline)
    if ($restartedService.State -ne 'Running' -or $restartedService.ProcessId -eq $killedProcessId) {
        throw 'SCM did not restart the provenance service under a new process'
    }
    Wait-ServiceState -State Running
    $burst.WaitForExit(90000)
    if (-not $burst.HasExited -or $burst.ExitCode -ne 0) {
        throw 'restart burst did not recover successfully'
    }
    $burstResult = Get-Content -Raw $BurstPath | ConvertFrom-Json
    $Results.checks.crash_restart_burst = [bool]$burstResult.ok -and `
        [int]$burstResult.recovered_after_error_count -gt 0
    $Results.artifacts.restart_burst_count = [int]$burstResult.count
    $Results.artifacts.restart_recovered_after_error_count = [int]$burstResult.recovered_after_error_count
    $Results.artifacts.killed_service_pid = $killedProcessId
    $Results.artifacts.restarted_service_pid = [int]$restartedService.ProcessId

    Stop-Service -Name $ServiceName
    Wait-ServiceState -State Stopped
    $Results.checks.scm_stop = (Get-Service -Name $ServiceName).Status -eq 'Stopped'
    $verification = @()
    foreach ($log in Get-ChildItem -LiteralPath (Join-Path $ServiceRoot 'ledger') -Filter '*.jsonl' |
        Where-Object { $_.Name -ne 'session_index.jsonl' }) {
        $sessionId = $log.BaseName
        $ledgerVerificationPath = Join-Path $AcceptanceRoot ("ledger-$sessionId.json")
        & $PythonExe $Helper verify-ledger --path $log.FullName --session-id $sessionId `
            --public-key-hex $servicePublicKeyHex --output $ledgerVerificationPath
        if ($LASTEXITCODE -ne 0) { throw "offline verification failed for $($log.FullName)" }
        $verification += (Get-Content -Raw $ledgerVerificationPath | ConvertFrom-Json)
    }
    $Results.artifacts.chain_verification = $verification
    $Results.checks.all_chains_verify_offline = $verification.Count -gt 0 -and `
        @($verification | Where-Object { -not $_.ok }).Count -eq 0
    $indexPath = Join-Path $ServiceRoot 'ledger\session_index.jsonl'
    $indexVerificationPath = Join-Path $AcceptanceRoot 'session-index-verification.json'
    & $PythonExe $Helper verify-index --path $indexPath `
        --public-key-hex $servicePublicKeyHex --agent-id $serviceAgentId `
        --output $indexVerificationPath
    if ($LASTEXITCODE -ne 0) { throw 'offline session-index verification command failed' }
    $indexVerification = Get-Content -Raw $indexVerificationPath | ConvertFrom-Json
    $Results.artifacts.session_index_verification = $indexVerification
    $Results.checks.session_index_verifies_offline = [bool]$indexVerification.ok -and `
        [int]$indexVerification.count -gt 0
    $Results.artifacts.wheel_sha256 = $wheelHash
    $Results.artifacts.source_commit = $sourceCommit
    $Results.artifacts.deploy_script_sha256 = (
        Get-FileHash -LiteralPath $DeployScript -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $Results.artifacts.acceptance_helper_sha256 = (
        Get-FileHash -LiteralPath $HelperSource -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $Results.artifacts.ledger_acl = @(& icacls.exe (Join-Path $ServiceRoot 'ledger'))
    $Results.artifacts.enrollment_acl = @(
        & icacls.exe (Join-Path $ServiceRoot 'config\enrollments.json')
    )
    $Results.artifacts.windows_build = [Environment]::OSVersion.Version.ToString()
    $Results.artifacts.python = (& $PythonExe --version 2>&1).ToString()
} catch {
    $Results.error = $_.Exception.Message
    throw
} finally {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        $TranscriptStarted = $false
    }
    if (Test-Path -LiteralPath $TranscriptPath) {
        $Results.artifacts.transcript_sha256 = (
            Get-FileHash -LiteralPath $TranscriptPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        try {
            & $DeployScript -Action Uninstall -PythonExe $PythonExe -RootPath $ServiceRoot -PurgeData
            $Results.checks.rollback_uninstall = -not [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
        } catch {
            $Results.checks.rollback_uninstall = $false
            $Results.rollback_error = $_.Exception.Message
        }
    }
    foreach ($name in $CreatedUsers) {
        try { Remove-LocalUser -Name $name -ErrorAction Stop } catch { }
    }
    $Results.finished_at = (Get-Date).ToUniversalTime().ToString('o')
    $required = @($Results.checks.GetEnumerator() | ForEach-Object { [bool]$_.Value })
    $Results.ok = $required.Count -gt 0 -and -not ($required -contains $false) -and -not $Results.error
    $parent = Split-Path -Parent $ReportPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $Results | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "Acceptance evidence: $ReportPath"
    if (-not $Results.ok) { exit 1 }
}
