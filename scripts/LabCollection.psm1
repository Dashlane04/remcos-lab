# Collection only: specimen paths are hashed, never launched. Native calls are isolated for mock tests.
Set-StrictMode -Version Latest

function Get-LabUtcNow { return [DateTimeOffset]::UtcNow }
function Wait-LabTick { Start-Sleep -Seconds 1 }

function Invoke-LabTool {
    param([string]$Command, [string[]]$Arguments, [string]$LogPath)
    $text = & $Command @Arguments 2>&1
    $code = $LASTEXITCODE
    $text | Out-File -LiteralPath $LogPath -Encoding UTF8
    if ($code -ne 0) { throw "$Command failed with exit code $code; inspect $LogPath" }
}

function Assert-LabPrivateConnection {
    param([string]$Address, [int[]]$Ports)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Use a private IPv4 SIEM address.' }
    $octets = $ip.GetAddressBytes()
    $private = $octets[0] -eq 10 -or ($octets[0] -eq 192 -and $octets[1] -eq 168) -or
        ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31)
    if (-not $private) { throw 'Collector connections must target a private lab IPv4 address.' }
    foreach ($port in $Ports) {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $operation = $client.BeginConnect($ip, $port, $null, $null)
            try {
                if (-not $operation.AsyncWaitHandle.WaitOne(2500)) { throw "Private collector port $port is unreachable." }
                $client.EndConnect($operation)
            } finally { $operation.AsyncWaitHandle.Close() }
        } finally { $client.Dispose() }
    }
}

function Assert-LabEnvironment {
    param([string]$Forwarding, [string]$SiemAddress, [string]$DumpcapPath, [string]$EtwProvider)
    if ($env:OS -ne 'Windows_NT') { throw 'Run Windows collection inside the disposable Windows VM.' }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open an elevated Windows PowerShell terminal inside the disposable VM.'
    }
    if (-not (Test-Path -LiteralPath $DumpcapPath -PathType Leaf)) { throw 'Install Wireshark/Npcap in the VM and set DumpcapPath.' }
    foreach ($tool in @('logman.exe','tracerpt.exe','wevtutil.exe')) { Get-Command $tool -ErrorAction Stop | Out-Null }
    $groups = @(,@('Sysmon64','Sysmon'))
    if ($Forwarding -in @('Both','Splunk')) { $groups += ,@('SplunkForwarder') }
    if ($Forwarding -in @('Both','Elastic')) { $groups += ,@('Elastic Agent','elastic-agent') }
    $serviceRecords = @()
    foreach ($names in $groups) {
        $service = @(Get-Service -Name $names -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($service.Count -eq 0) { throw "Required collector service is missing: $($names -join ' / '). Complete VM setup first." }
        $wasStarted = $false
        if ($service[0].Status -ne 'Running') {
            Start-Service -InputObject $service[0] -ErrorAction Stop
            $service[0].WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            $wasStarted = $true
        }
        $serviceRecords += [ordered]@{ name = $service[0].Name; started_by_launcher = $wasStarted }
    }
    $channels = @()
    foreach ($channel in @('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')) {
        $info = Get-WinEvent -ListLog $channel -ErrorAction Stop
        if (-not $info.IsEnabled) { throw "Required channel is disabled: $channel" }
        $channels += [ordered]@{ name = $channel; enabled = $info.IsEnabled; maximum_bytes = $info.MaximumSizeInBytes }
    }
    $providerText = & logman.exe query providers $EtwProvider 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ETW provider is unavailable: $EtwProvider" }
    $ports = @()
    if ($Forwarding -in @('Both','Splunk')) { $ports += 9997 }
    if ($Forwarding -in @('Both','Elastic')) { $ports += 8220; $ports += 9200 }
    if ($ports.Count -gt 0) { Assert-LabPrivateConnection -Address $SiemAddress -Ports $ports }
    return [ordered]@{ services = $serviceRecords; channels = $channels; provider_details = ($providerText -join "`n")
        collector_ports_checked = $ports; tls_and_siem_ingestion_verified = $false
        powershell_version = $PSVersionTable.PSVersion.ToString(); active_sysmon_policy_verified = $false }
}

function Start-LabPacketCapture {
    param([string]$DumpcapPath, [int]$Interface, [int]$Duration, [string]$Directory)
    $pcap = Join-Path $Directory 'traffic.pcapng'
    # Start-Process joins ArgumentList on Windows; quote this controlled file path explicitly.
    $arguments = @('-i', [string]$Interface, '-a', "duration:$Duration", '-w', ('"' + $pcap + '"'))
    $process = Start-Process -FilePath $DumpcapPath -ArgumentList $arguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Directory 'dumpcap.stdout.log') `
        -RedirectStandardError (Join-Path $Directory 'dumpcap.stderr.log')
    # Keep the native handle while alive: Windows PowerShell 5.1 can otherwise
    # return a null ExitCode after an asynchronously launched process finishes.
    $null = $process.Handle
    return $process
}

function Test-LabPacketCapture {
    param($Process, [string]$Directory)
    $Process.Refresh()
    if ($Process.HasExited) { throw 'Packet capture exited before the observation window ended; inspect dumpcap.stderr.log.' }
    $file = Join-Path $Directory 'traffic.pcapng'
    return (Test-Path -LiteralPath $file -PathType Leaf) -and (Get-Item -LiteralPath $file).Length -gt 0
}

function Finish-LabPacketCapture {
    param($Process, [bool]$Graceful)
    $Process.Refresh()
    $forced = $false
    if (-not $Process.HasExited -and $Graceful) { [void]$Process.WaitForExit(25000); $Process.Refresh() }
    if (-not $Process.HasExited) {
        # Only the process object returned by this launch is stopped, never a global process-name match.
        $Process.Kill()
        [void]$Process.WaitForExit(5000)
        $forced = $true
    }
    return [ordered]@{ forced_stop = $forced; exit_code = $Process.ExitCode
        note = 'Review dumpcap stderr for packet/drop counts; a forced stop can leave incomplete output.' }
}

function Test-LabSysmonMarker {
    param([string]$Marker, [DateTimeOffset]$Since, [string]$Directory)
    $command = Join-Path $env:SystemRoot 'System32/cmd.exe'
    Start-Process -FilePath $command -ArgumentList @('/d','/c',"echo $Marker") -WindowStyle Hidden -Wait `
        -RedirectStandardOutput (Join-Path $Directory 'marker.stdout.txt') | Out-Null
    # Get-WinEvent's hashtable time filter can reinterpret UTC as local wall time
    # in Windows PowerShell. Match the event's explicit UTC SystemTime instead.
    $sinceUtc = $Since.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $markerXPath = "*[System[(EventID=1) and TimeCreated[@SystemTime >= '$sinceUtc']]]"
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $records = @(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $markerXPath -MaxEvents 500 -ErrorAction SilentlyContinue)
        foreach ($record in $records) {
            if ($record.ToXml().Contains($Marker)) { return $true }
        }
        Wait-LabTick
    }
    return $false
}

function Export-LabWindows {
    param([DateTimeOffset]$Start, [DateTimeOffset]$End, [string]$Directory)
    & (Join-Path $PSScriptRoot 'Export-LabEvents.ps1') -StartUtc $Start -EndUtc $End -IncludeCampaignLogs -OutputDirectory $Directory
}

function Save-LabRun {
    param($State, [string]$Directory)
    $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Directory 'run.json') -Encoding UTF8
}

function Invoke-LabCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$CaseId,
        [ValidateSet('benign-background','actual-malware')][string]$EvidenceType = 'benign-background',
        [ValidateSet('development','validation','holdout')][string]$Split = 'development',
        [ValidateSet('Both','Splunk','Elastic','Offline')][string]$Forwarding = 'Both',
        [ValidateSet('N0','N1')][string]$NetworkMode = 'N0',
        [string]$SiemAddress = '192.168.56.10', [ValidateRange(1, 128)][int]$CaptureInterface = 1,
        [ValidateRange(5, 1800)][int]$ObservationSeconds = 900, [ValidateRange(0, 120)][int]$BaselineSeconds = 30,
        [string]$CasesDirectory = 'C:\Lab\Cases', [string]$DumpcapPath = 'C:\Program Files\Wireshark\dumpcap.exe',
        [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$EtwProvider = 'Microsoft-Windows-Kernel-Process',
        [ValidatePattern('^0x[0-9A-Fa-f]{1,16}$')][string]$EtwKeywords = '0xffffffffffffffff',
        [ValidateRange(1, 5)][int]$EtwLevel = 5,
        [string]$SamplePath, [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSampleSha256
    )
    $ErrorActionPreference = 'Stop'
    $casePath = Join-Path $CasesDirectory $CaseId
    if (Test-Path -LiteralPath $casePath) { throw 'Case directory already exists; choose a fresh case ID.' }
    $specimen = $null
    if ($EvidenceType -eq 'actual-malware' -and (-not $SamplePath -or -not $ExpectedSampleSha256)) {
        throw 'For actual-malware, provide the extracted SamplePath and ExpectedSampleSha256. The collector only hashes it.'
    }
    if ($ExpectedSampleSha256 -and -not $SamplePath) { throw 'ExpectedSampleSha256 requires SamplePath.' }
    if ($SamplePath) {
        if (-not (Test-Path -LiteralPath $SamplePath -PathType Leaf)) { throw 'The extracted specimen file was not found.' }
        $hash = (Get-FileHash -LiteralPath $SamplePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ExpectedSampleSha256 -and $hash -ne $ExpectedSampleSha256.ToLowerInvariant()) { throw 'Specimen SHA-256 mismatch; collection was not started.' }
        $specimen = [ordered]@{ path = (Resolve-Path -LiteralPath $SamplePath).Path; sha256 = $hash
            expected_hash_matched = [bool]$ExpectedSampleSha256; version_verified_by_collector = $false; executed_by_collector = $false }
    }
    $preflight = Assert-LabEnvironment -Forwarding $Forwarding -SiemAddress $SiemAddress -DumpcapPath $DumpcapPath -EtwProvider $EtwProvider
    New-Item -ItemType Directory -Path $casePath -ErrorAction Stop | Out-Null
    $casePath = (Resolve-Path -LiteralPath $casePath).Path
    $networkPath = Join-Path $casePath 'network'
    $etwPath = Join-Path $casePath 'etw'
    New-Item -ItemType Directory -Path $networkPath,$etwPath | Out-Null
    $preflight.provider_details | Set-Content -LiteralPath (Join-Path $etwPath 'provider.txt') -Encoding UTF8
    $started = Get-LabUtcNow
    $session = 'RemcosLab-' + $CaseId + '-' + [Guid]::NewGuid().ToString('N')
    $state = [ordered]@{
        case_id = $CaseId; evidence_type = $EvidenceType; split = $Split; computer = $env:COMPUTERNAME
        status = 'starting'; started_utc = $started.ToString('o'); ready_utc = $null; observation_end_utc = $null; ended_utc = $null
        observation_seconds_requested = $ObservationSeconds; baseline_seconds_requested = $BaselineSeconds
        forwarding = $Forwarding; siem_address = $SiemAddress; preflight = $preflight; specimen = $specimen
        declared_network_mode = $NetworkMode; network_isolation_verified_by_launcher = $false
        marker = 'REMCOS_LAB_' + [Guid]::NewGuid().ToString('N'); local_sysmon_marker_verified = $false
        etw = [ordered]@{ session = $session; provider = $EtwProvider; keywords = $EtwKeywords; level = $EtwLevel
            started = $false; stopped = $false; decoded = $false; circular_limit_mb = 256 }
        pcap = [ordered]@{ interface = $CaptureInterface; process_id = $null; result = $null }
        errors = @(); source_gaps = @(); note = 'READY establishes local collection only; verify SIEM arrival using this case marker. Sample execution is manual.'
    }
    $packetProcess = $null
    $etwAttempted = $false
    $normalEnd = $false
    Save-LabRun -State $state -Directory $casePath
    try {
        $etwAttempted = $true
        Invoke-LabTool -Command 'logman.exe' -Arguments @('create','trace',$session,'-o',(Join-Path $etwPath 'trace.etl'),'-p',$EtwProvider,$EtwKeywords,[string]$EtwLevel,'-f','bincirc','-max','256','-ets') -LogPath (Join-Path $etwPath 'start.log')
        $state.etw.started = $true
        $packetProcess = Start-LabPacketCapture -DumpcapPath $DumpcapPath -Interface $CaptureInterface -Duration ($ObservationSeconds + $BaselineSeconds + 20) -Directory $networkPath
        $state.pcap.process_id = $packetProcess.Id
        Save-LabRun -State $state -Directory $casePath
        $captureReady = $false
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            if (Test-LabPacketCapture -Process $packetProcess -Directory $networkPath) { $captureReady = $true; break }
            Wait-LabTick
        }
        if (-not $captureReady) { throw 'Packet capture did not begin writing its output file.' }
        $state.local_sysmon_marker_verified = Test-LabSysmonMarker -Marker $state.marker -Since $started -Directory $casePath
        if (-not $state.local_sysmon_marker_verified) { throw 'The harmless process marker was not found in local Sysmon. Fix collection before specimen activity.' }
        Write-Host "Local capture started. Collecting $BaselineSeconds seconds of baseline."
        $baselineEnd = (Get-LabUtcNow).AddSeconds($BaselineSeconds)
        while ((Get-LabUtcNow) -lt $baselineEnd) {
            [void](Test-LabPacketCapture -Process $packetProcess -Directory $networkPath)
            Wait-LabTick
        }
        $state.ready_utc = (Get-LabUtcNow).ToString('o')
        $state.status = 'ready'
        Save-LabRun -State $state -Directory $casePath
        Write-Host "READY: $CaseId. PCAP + ETW active; local Sysmon marker verified."
        Write-Host "Marker: $($state.marker). Verify it in your SIEM. Perform the selected activity manually in another window."
        Write-Host "Observing for $ObservationSeconds seconds. Keep this collector window open; Ctrl+C attempts cleanup/export."
        $deadline = (Get-LabUtcNow).AddSeconds($ObservationSeconds)
        while ((Get-LabUtcNow) -lt $deadline) {
            [void](Test-LabPacketCapture -Process $packetProcess -Directory $networkPath)
            Wait-LabTick
        }
        $normalEnd = $true
    } catch {
        $state.errors += $_.Exception.Message
    } finally {
        $state.observation_end_utc = (Get-LabUtcNow).ToString('o')
        if ($packetProcess) {
            try {
                $state.pcap.result = Finish-LabPacketCapture -Process $packetProcess -Graceful $normalEnd
                if ($state.pcap.result.forced_stop -or $state.pcap.result.exit_code -ne 0) {
                    $state.errors += 'PCAP did not finish normally; review its partial output and capture log.'
                }
            } catch { $state.errors += 'Packet cleanup: ' + $_.Exception.Message }
        }
        if ($etwAttempted) {
            try {
                Invoke-LabTool -Command 'logman.exe' -Arguments @('stop',$session,'-ets') -LogPath (Join-Path $etwPath 'stop.log')
                $state.etw.stopped = $true
            } catch { $state.errors += 'ETW cleanup: ' + $_.Exception.Message }
        }
        $ended = Get-LabUtcNow
        $state.ended_utc = $ended.ToString('o')
        try {
            Export-LabWindows -Start $started -End $ended -Directory (Join-Path $casePath 'windows')
            $export = Get-Content -LiteralPath (Join-Path $casePath 'windows/manifest.json') -Raw | ConvertFrom-Json
            $state.source_gaps = @($export.channels | Where-Object { $_.status -ne 'exported' } | ForEach-Object { $_.channel })
            $sysmon = @($export.channels | Where-Object { $_.channel -eq 'Microsoft-Windows-Sysmon/Operational' -and $_.status -eq 'exported' -and $_.count -gt 0 })
            if ($sysmon.Count -eq 0) { $state.errors += 'Sysmon export is missing or empty despite the local marker.' }
        } catch { $state.errors += 'Windows export: ' + $_.Exception.Message }
        if ($state.etw.stopped -and (Test-Path -LiteralPath (Join-Path $etwPath 'trace.etl'))) {
            try {
                Invoke-LabTool -Command 'tracerpt.exe' -Arguments @((Join-Path $etwPath 'trace.etl'),'-o',(Join-Path $etwPath 'trace.xml'),'-of','XML','-summary',(Join-Path $etwPath 'summary.txt'),'-y') -LogPath (Join-Path $etwPath 'decode.log')
                $state.etw.decoded = $true
            } catch { $state.errors += 'ETW decoding: ' + $_.Exception.Message }
        } else { $state.errors += 'ETW file was not finalized; inspect the owned session and preserve available output.' }
        if (-not $normalEnd -and $state.errors.Count -eq 0) { $state.errors += 'Collection was interrupted before the requested observation interval completed.' }
        $state.status = if ($state.errors.Count -gt 0) { 'partial' } elseif ($state.source_gaps.Count -gt 0) { 'completed_with_source_gaps' } else { 'completed' }
        Save-LabRun -State $state -Directory $casePath
        $hashes = @(Get-ChildItem -LiteralPath $casePath -Recurse -File | Where-Object { $_.Name -ne 'integrity.json' } | ForEach-Object {
            [ordered]@{ path = $_.FullName.Substring($casePath.Length + 1); bytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        })
        [ordered]@{ created_utc = (Get-LabUtcNow).ToString('o'); files = $hashes } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $casePath 'integrity.json') -Encoding UTF8
        Write-Host "Collection status: $($state.status). Evidence: $casePath"
        Write-Host 'Review run.json, windows/manifest.json, dumpcap stderr, and ETW summary. Preserve EDR documents separately before rollback.'
    }
    if ($state.errors.Count -gt 0) { throw ($state.errors -join "`n") }
    return $casePath
}

Export-ModuleMember -Function Invoke-LabCollection
