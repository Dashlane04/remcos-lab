[CmdletBinding()]
param(
    [ValidateRange(5, 600)][int]$DurationSeconds = 30,
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$Provider = 'Microsoft-Windows-Kernel-Process',
    [ValidatePattern('^0x[0-9A-Fa-f]{1,16}$')][string]$Keywords = '0xffffffffffffffff',
    [ValidateRange(1, 5)][int]$Level = 5,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this short trace from an elevated terminal inside the Windows lab VM.'
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a fresh evidence directory.' }
$providerCheck = & logman.exe query providers $Provider 2>&1
if ($LASTEXITCODE -ne 0) { throw "The provider is not available: $Provider" }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$outPath = (Resolve-Path -LiteralPath $OutputDirectory).Path
$providerCheck | Out-File -LiteralPath (Join-Path $outPath 'provider.txt') -Encoding utf8
$sessionName = 'RemcosLab-' + [Guid]::NewGuid().ToString('N')
$etl = Join-Path $outPath 'trace.etl'
$started = [DateTime]::UtcNow
$running = $false
$stopExitCode = $null
try {
    & logman.exe create trace $sessionName -o $etl -p $Provider $Keywords $Level -f bincirc -max 256 -ets
    if ($LASTEXITCODE -ne 0) { throw 'ETW session creation failed.' }
    $running = $true
    Write-Host "Recording $Provider for $DurationSeconds seconds. Perform your selected benign activity now."
    Start-Sleep -Seconds $DurationSeconds
} finally {
    if ($running) {
        & logman.exe stop $sessionName -ets
        $stopExitCode = $LASTEXITCODE
        if ($stopExitCode -ne 0) { Write-Warning "Could not stop owned session $sessionName; inspect logman query -ets." }
    }
    [ordered]@{
        session = $sessionName; provider = $Provider; keywords = $Keywords; level = $Level
        started_utc = $started.ToString('o'); stopped_utc = [DateTime]::UtcNow.ToString('o')
        computer = $env:COMPUTERNAME; file_limit_mb = 256; collection_kind = 'bounded circular ETW trace'
        stop_exit_code = $stopExitCode
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outPath 'capture.json') -Encoding UTF8
}
if ($running -and $stopExitCode -ne 0) { throw "Trace stop failed for owned session $sessionName; resolve before decoding the ETL." }
if (-not (Test-Path -LiteralPath $etl)) { throw 'The ETL was not created; inspect capture status.' }
& tracerpt.exe $etl -o (Join-Path $outPath 'trace.xml') -of XML -summary (Join-Path $outPath 'summary.txt') -y
if ($LASTEXITCODE -ne 0) { throw 'tracerpt failed. Preserve the ETL for provider-specific decoding.' }
Get-FileHash -LiteralPath $etl -Algorithm SHA256 | Format-List | Out-File -LiteralPath (Join-Path $outPath 'sha256.txt')
Write-Host "Preserved ETL, XML, and loss summary in $outPath"
