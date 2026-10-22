[CmdletBinding()]
param(
    [ValidateRange(1, 1440)][int]$Minutes = 10,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [DateTimeOffset]$StartUtc,
    [DateTimeOffset]$EndUtc,
    [switch]$IncludeCampaignLogs
)
$ErrorActionPreference = 'Stop'
if ($PSBoundParameters.ContainsKey('StartUtc') -xor $PSBoundParameters.ContainsKey('EndUtc')) {
    throw 'Supply StartUtc and EndUtc together, or use Minutes for a relative window.'
}
if ($PSBoundParameters.ContainsKey('StartUtc')) {
    $startTime = $StartUtc.UtcDateTime
    $endTime = $EndUtc.UtcDateTime
    if ($endTime -le $startTime) { throw 'EndUtc must be later than StartUtc.' }
} else {
    $endTime = [DateTime]::UtcNow
    $startTime = $endTime.AddMinutes(-$Minutes)
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new evidence directory; existing evidence will not be overwritten.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
$fromUtc = $startTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$toUtc = $endTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$xpath = "*[System[TimeCreated[@SystemTime >= '$fromUtc' and @SystemTime <= '$toUtc']]]"
$entries = @()
$channels = [ordered]@{
    sysmon = 'Microsoft-Windows-Sysmon/Operational'
    powershell = 'Microsoft-Windows-PowerShell/Operational'
}
if ($IncludeCampaignLogs) {
    $channels['security'] = 'Security'
    $channels['task-scheduler'] = 'Microsoft-Windows-TaskScheduler/Operational'
    $channels['defender'] = 'Microsoft-Windows-Windows Defender/Operational'
    $channels['system'] = 'System'
}
foreach ($name in $channels.Keys) {
    $channel = $channels[$name]
    try {
        $channelInfo = Get-WinEvent -ListLog $channel -ErrorAction Stop
        if (-not $channelInfo.IsEnabled) { throw 'The event channel is disabled; no policy was changed by this exporter.' }
        $channelXPath = $xpath
        if ($name -eq 'security') {
            $channelXPath = "*[System[(EventID=4688 or EventID=4698 or EventID=4702) and TimeCreated[@SystemTime >= '$fromUtc' and @SystemTime <= '$toUtc']]]"
        }
        $evtxPath = Join-Path $resolvedOutput "$name.evtx"
        & wevtutil.exe epl $channel $evtxPath "/q:$channelXPath"
        if ($LASTEXITCODE -ne 0) { throw "wevtutil export failed with exit code $LASTEXITCODE" }
        $xmlPath = Join-Path $resolvedOutput "$name.xml"
        $writer = New-Object System.IO.StreamWriter($xmlPath, $false, (New-Object System.Text.UTF8Encoding($false)))
        $count = 0
        try {
            $writer.WriteLine('<Events>')
            # Query the exported snapshot, avoiding a different live query window.
            Get-WinEvent -Path $evtxPath -Oldest -ErrorAction Stop | ForEach-Object {
                $writer.WriteLine($_.ToXml())
                $count++
            }
        } catch {
            # An empty exported log is valid evidence of no collected events.
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        } finally {
            $writer.WriteLine('</Events>')
            $writer.Dispose()
        }
        $entries += [ordered]@{
            channel = $channel; status = 'exported'; count = $count; xpath = $channelXPath
            log_enabled = $channelInfo.IsEnabled; log_max_bytes = $channelInfo.MaximumSizeInBytes
            xml = "$name.xml"; xml_sha256 = (Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash.ToLowerInvariant()
            evtx = "$name.evtx"; evtx_sha256 = (Get-FileHash -LiteralPath $evtxPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } catch {
        $entries += [ordered]@{ channel = $channel; status = 'failed'; reason = $_.Exception.Message }
    }
}
[ordered]@{
    computer = $env:COMPUTERNAME; from_utc = $fromUtc; to_utc = $toUtc
    exported_utc = [DateTime]::UtcNow.ToString('o'); include_campaign_logs = [bool]$IncludeCampaignLogs; channels = @($entries)
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $resolvedOutput 'manifest.json') -Encoding UTF8
Write-Host "Evidence exported to $resolvedOutput. Check manifest.json for unavailable channels."
if (@($entries | Where-Object { $_.status -eq 'exported' }).Count -eq 0) { throw 'No channel exported successfully; inspect manifest.json.' }
