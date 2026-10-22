[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$labRoot = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $labRoot 'infra/.env'
if (Test-Path -LiteralPath $envPath) {
    Write-Host 'infra/.env already exists; existing credentials were preserved.'
    return
}
function New-LabSecret {
    $buffer = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    # Hex is cryptographically random, shell-safe, and accepted by the setup bootstrap.
    return ([BitConverter]::ToString($buffer)).Replace('-', '').ToLowerInvariant()
}
$text = [IO.File]::ReadAllText((Join-Path $labRoot 'infra/.env.example'))
foreach ($setting in @('ELASTIC_PASSWORD', 'KIBANA_PASSWORD', 'KIBANA_ENCRYPTION_KEY', 'SPLUNK_PASSWORD')) {
    $secret = New-LabSecret
    $text = $text.Replace("${setting}=GENERATE_WITH_INITIALIZER", "${setting}=$secret")
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
# CreateNew avoids overwriting a credentials file if two initializers run concurrently.
$stream = [IO.File]::Open($envPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = $utf8.GetBytes($text)
    $stream.Write($bytes, 0, $bytes.Length)
} finally { $stream.Dispose() }
Write-Host 'Created infra/.env with fresh local passwords. No services were started.'
Write-Host 'Set LAB_SERVER_IP and DATA_BIND_IP to the private SIEM interface before live collection.'
Write-Host 'Keep this file private; do not include it in reports or commits.'
