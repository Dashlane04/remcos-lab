# Contract checks with synthetic mocks only. No Windows event channel or native wevtutil is called.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$labRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path $labRoot ('data/raw/QA-MOCK-EXPORT-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$global:LabMockDisableTaskScheduler = $false
function Get-WinEvent {
    [CmdletBinding()]
    param([string]$ListLog, [string]$Path, [switch]$Oldest)
    if ($ListLog) {
        return [pscustomobject]@{
            IsEnabled = -not ($global:LabMockDisableTaskScheduler -and $ListLog -eq 'Microsoft-Windows-TaskScheduler/Operational')
            MaximumSizeInBytes = 1048576
        }
    }
    if (-not $Path) { throw 'Unexpected mock invocation.' }
    $event = [pscustomobject]@{ Synthetic = $true }
    $event | Add-Member ScriptMethod ToXml {
        return '<Event><System><Provider Name="Lab-Mock-Provider"/><EventID>9999</EventID><TimeCreated SystemTime="2026-10-22T03:01:00Z"/><Computer>SYNTHETIC-MOCK</Computer></System><EventData/></Event>'
    }
    return $event
}
function wevtutil.exe {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Operation,
          [Parameter(Position=1)][string]$Channel,
          [Parameter(Position=2)][string]$Destination,
          [Parameter(Position=3)][string]$Query)
    if ($Operation -ne 'epl' -or -not $Query.StartsWith('/q:')) { throw 'Unexpected mock export invocation.' }
    [IO.File]::WriteAllText($Destination, 'SYNTHETIC MOCK PLACEHOLDER, NOT AN EVTX FILE')
    $global:LASTEXITCODE = 0
}

$complete = Join-Path $testRoot 'complete'
& (Join-Path $labRoot 'scripts/Export-LabEvents.ps1') -StartUtc '2026-10-22T10:00:00+07:00' -EndUtc '2026-10-22T10:15:00+07:00' -IncludeCampaignLogs -OutputDirectory $complete
$manifest = Get-Content -LiteralPath (Join-Path $complete 'manifest.json') -Raw | ConvertFrom-Json
$fromText = ([DateTimeOffset]$manifest.from_utc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$toText = ([DateTimeOffset]$manifest.to_utc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
if ($manifest.channels.Count -ne 6 -or $fromText -ne '2026-10-22T03:00:00.000Z' -or $toText -ne '2026-10-22T03:15:00.000Z') { throw 'Exact-window/channel-count contract failed.' }
$security = @($manifest.channels | Where-Object { $_.channel -eq 'Security' })[0]
if ($security.xpath -notlike '*EventID=4698*' -or $security.xpath -notlike '*EventID=4702*' -or $security.xpath -notlike '*EventID=4688*') { throw 'Security event scope was not preserved.' }
foreach ($entry in $manifest.channels) {
    if ($entry.status -ne 'exported' -or $entry.count -ne 1 -or $entry.xml_sha256.Length -ne 64 -or $entry.evtx_sha256.Length -ne 64) { throw 'Mock export/hash contract failed.' }
}

$global:LabMockDisableTaskScheduler = $true
$disabled = Join-Path $testRoot 'disabled-channel'
& (Join-Path $labRoot 'scripts/Export-LabEvents.ps1') -Minutes 5 -IncludeCampaignLogs -OutputDirectory $disabled
$partial = Get-Content -LiteralPath (Join-Path $disabled 'manifest.json') -Raw | ConvertFrom-Json
$failures = @($partial.channels | Where-Object { $_.status -eq 'failed' })
if ($failures.Count -ne 1 -or $failures[0].channel -ne 'Microsoft-Windows-TaskScheduler/Operational') { throw 'Disabled source must be explicit in the manifest.' }

$rejected = $false
try { & (Join-Path $labRoot 'scripts/Export-LabEvents.ps1') -StartUtc '2026-10-22T03:00:00Z' -OutputDirectory (Join-Path $testRoot 'invalid') } catch { $rejected = $true }
if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $testRoot 'invalid'))) { throw 'An incomplete time window must fail before writing evidence.' }
$rejected = $false
try { & (Join-Path $labRoot 'scripts/Export-LabEvents.ps1') -OutputDirectory $complete } catch { $rejected = $true }
if (-not $rejected) { throw 'An existing case directory must not be overwritten.' }
Write-Output 'PASS: mocked six-channel export, UTC bounds, selected Security IDs, hashes, disabled-source reporting, and evidence-preservation guards.'
Write-Output 'All produced records are synthetic mocks; no host logs were read.'
