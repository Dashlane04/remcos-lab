# All native tools, services, packet capture, event export, and waiting are replaced by inert mocks.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path $root ('data/raw/QA-MOCK-COLLECTION-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$module = Import-Module (Join-Path $root 'scripts/LabCollection.psm1') -Force -PassThru
& $module {
    $script:MockTick = 0
    $script:MockMode = 'success'
    $script:MockCalls = @()
    function script:Get-LabUtcNow { $script:MockTick++; return ([DateTimeOffset]'2026-10-22T03:00:00Z').AddSeconds($script:MockTick) }
    function script:Wait-LabTick {}
    function script:Assert-LabEnvironment {
        param($Forwarding,$SiemAddress,$DumpcapPath,$EtwProvider)
        $script:MockCalls += 'preflight'
        return @{ provider_details = 'SYNTHETIC MOCK provider'; synthetic = $true }
    }
    function script:Invoke-LabTool {
        param($Command,$Arguments,$LogPath)
        if ($Command -eq 'logman.exe') {
            $script:MockCalls += ('etw-' + $Arguments[0])
            if ($Arguments[0] -eq 'create') {
                $outputIndex = [Array]::IndexOf($Arguments,'-o')
                'SYNTHETIC MOCK, NOT AN ETL FILE' | Set-Content -LiteralPath $Arguments[$outputIndex + 1]
            }
        } elseif ($Command -eq 'tracerpt.exe') {
            $script:MockCalls += 'decode'
            $outputIndex = [Array]::IndexOf($Arguments,'-o')
            '<Events/>' | Set-Content -LiteralPath $Arguments[$outputIndex + 1]
        } else { throw 'Unexpected mocked native command.' }
        'SYNTHETIC MOCK COMMAND, NO NATIVE TOOL CALLED' | Set-Content -LiteralPath $LogPath
    }
    function script:Start-LabPacketCapture {
        param($DumpcapPath,$Interface,$Duration,$Directory)
        $script:MockCalls += 'pcap-start'
        'SYNTHETIC MOCK, NOT A PCAP FILE' | Set-Content -LiteralPath (Join-Path $Directory 'traffic.pcapng')
        return [pscustomobject]@{ Id = 12345; Synthetic = $true }
    }
    function script:Test-LabPacketCapture {
        param($Process,$Directory)
        if ($script:MockMode -eq 'pcap-failed') { throw 'SYNTHETIC MOCK capture failed.' }
        return $true
    }
    function script:Finish-LabPacketCapture {
        param($Process,$Graceful)
        $script:MockCalls += 'pcap-finish'
        return @{ forced_stop = -not $Graceful; exit_code = 0; synthetic = $true }
    }
    function script:Test-LabSysmonMarker {
        param($Marker,$Since,$Directory)
        $script:MockCalls += 'marker'
        return $script:MockMode -ne 'marker-failed'
    }
    function script:Export-LabWindows {
        param($Start,$End,$Directory)
        $script:MockCalls += 'export'
        New-Item -ItemType Directory -Path $Directory | Out-Null
        @{ synthetic = $true; channels = @(
            @{ channel='Microsoft-Windows-Sysmon/Operational'; status='exported'; count=1 },
            @{ channel='Microsoft-Windows-PowerShell/Operational'; status='exported'; count=0 }
        ) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Directory 'manifest.json')
    }
}

Invoke-LabCollection -CaseId MOCK-COMPLETE -CasesDirectory $testRoot -ObservationSeconds 5 -BaselineSeconds 0 -Forwarding Offline | Out-Null
$completePath = Join-Path $testRoot 'MOCK-COMPLETE'
$run = Get-Content -Raw -LiteralPath (Join-Path $completePath 'run.json') | ConvertFrom-Json
if ($run.status -ne 'completed' -or -not $run.ready_utc -or -not $run.local_sysmon_marker_verified -or -not $run.etw.stopped -or -not $run.etw.decoded) { throw 'Mock completion/readiness contract failed.' }
$calls = @(& $module { $script:MockCalls })
if ([Array]::IndexOf($calls,'etw-create') -ge [Array]::IndexOf($calls,'marker') -or [Array]::IndexOf($calls,'pcap-start') -ge [Array]::IndexOf($calls,'marker')) { throw 'Capture must start before the readiness marker.' }
$integrity = Get-Content -Raw -LiteralPath (Join-Path $completePath 'integrity.json') | ConvertFrom-Json
foreach ($entry in $integrity.files) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $completePath $entry.path) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.sha256) { throw 'Final evidence hash manifest mismatch.' }
}

foreach ($mode in @('marker-failed','pcap-failed')) {
    & $module { param($mode) $script:MockMode = $mode; $script:MockCalls = @() } $mode
    $case = 'MOCK-' + $mode
    $rejected = $false
    try { Invoke-LabCollection -CaseId $case -CasesDirectory $testRoot -ObservationSeconds 5 -BaselineSeconds 0 -Forwarding Offline | Out-Null } catch { $rejected = $true }
    $partial = Get-Content -Raw -LiteralPath (Join-Path (Join-Path $testRoot $case) 'run.json') | ConvertFrom-Json
    $calls = @(& $module { $script:MockCalls })
    if (-not $rejected -or $partial.status -ne 'partial' -or $partial.ready_utc -or 'etw-stop' -notin $calls -or 'pcap-finish' -notin $calls -or 'export' -notin $calls) { throw 'Failure must prevent READY, stop owned captures, and attempt evidence export.' }
}

& $module { $script:MockCalls = @() }
$rejected = $false
try { Invoke-LabCollection -CaseId MOCK-COMPLETE -CasesDirectory $testRoot -Forwarding Offline | Out-Null } catch { $rejected = $true }
if (-not $rejected -or @(& $module { $script:MockCalls }).Count -ne 0) { throw 'Existing evidence must be rejected before collector activity.' }

$fakeSpecimen = Join-Path $testRoot 'inert-specimen.txt'
'SYNTHETIC MOCK TEXT, NOT A SPECIMEN' | Set-Content -LiteralPath $fakeSpecimen
$rejected = $false
try { Invoke-LabCollection -CaseId MOCK-BADHASH -CasesDirectory $testRoot -EvidenceType actual-malware -SamplePath $fakeSpecimen -ExpectedSampleSha256 ('0' * 64) -Forwarding Offline | Out-Null } catch { $rejected = $true }
if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $testRoot 'MOCK-BADHASH')) -or @(& $module { $script:MockCalls }).Count -ne 0) { throw 'Wrong specimen hash must fail before any collector activity.' }
Write-Output 'PASS: mocked capture-before-ready, completion/hash manifest, failure cleanup/export, existing-case protection, and specimen-hash rejection.'
Write-Output 'All outputs are synthetic mocks; no service, event channel, ETW session, packet capture, specimen, or network port was accessed.'
