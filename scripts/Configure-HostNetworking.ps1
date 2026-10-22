#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$Distro = 'Ubuntu',
    [Parameter(Mandatory=$true)][string]$LinuxLabRoot,
    [string]$HostAdapter = 'VMware Network Adapter VMnet1',
    [string]$AnalysisVmIp = '10.10.10.20'
)
$ErrorActionPreference = 'Stop'
$labRoot = Split-Path -Parent $PSScriptRoot
$ports = @(8220, 9200, 9997)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $WhatIfPreference) {
    throw 'Run this HOST script in Administrator PowerShell. No disposable-VM changes are performed.'
}
if ($Distro -notmatch '^[A-Za-z0-9._-]+$' -or $LinuxLabRoot -notmatch '^/[A-Za-z0-9_./-]+$') {
    throw 'Use a simple distro name and an absolute Linux lab path.'
}
$hostAddresses = @(Get-NetIPAddress -InterfaceAlias $HostAdapter -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '169.254.*' })
if ($hostAddresses.Count -ne 1) { throw 'Expected exactly one IPv4 address on the selected host-only adapter.' }
$hostAddress = $hostAddresses[0]
$hostIp = $hostAddress.IPAddress
# This inspected lab deliberately uses VMnet1 /24; do not silently reinterpret another topology.
if ($hostAddress.PrefixLength -ne 24) { throw 'The selected host-only adapter is not /24; review its actual subnet.' }
$hostBytes = ([Net.IPAddress]::Parse($hostIp)).GetAddressBytes()
$vmParsed = [Net.IPAddress]::Parse($AnalysisVmIp)
$vmBytes = $vmParsed.GetAddressBytes()
if ($vmBytes.Length -ne 4 -or $vmBytes[3] -in @(0,255) -or $AnalysisVmIp -eq $hostIp -or
    ($hostBytes[0..2] -join '.') -ne ($vmBytes[0..2] -join '.')) {
    throw 'AnalysisVmIp must be a distinct usable IPv4 address in the host-only /24 subnet.'
}
$wslJson = & wsl.exe -d $Distro -- ip -j -4 address show dev eth0
if ($LASTEXITCODE -ne 0) { throw 'Could not discover Ubuntu eth0.' }
$wslAddress = @((($wslJson -join "`n") | ConvertFrom-Json).addr_info | Where-Object { $_.scope -eq 'global' })
if ($wslAddress.Count -ne 1) { throw 'Expected exactly one global Ubuntu eth0 IPv4 address.' }
$wslIp = $wslAddress[0].local
[void][Net.IPAddress]::Parse($wslIp)
Write-Host "HOST $hostIp -> Ubuntu $wslIp; permitted VM source $AnalysisVmIp"
Write-Host 'Collector TCP ports: 8220, 9200, 9997. Other host TCP/UDP access from that VM to this host-only address will be blocked.'
if (-not $PSCmdlet.ShouldProcess($HostAdapter, 'Refresh lab-only TCP forwarding, scoped firewall rules and Ubuntu address settings')) { return }

$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$backup = Join-Path $labRoot "data\raw\maintenance-backups\host-network-$stamp"
[void](New-Item -ItemType Directory -Path $backup -Force)
& netsh.exe interface portproxy dump | Set-Content -LiteralPath (Join-Path $backup 'portproxy-before.txt') -Encoding UTF8
if ($LASTEXITCODE -ne 0) { throw 'Could not back up the existing portproxy configuration.' }
$existingRules = @(Get-NetFirewallRule -Name 'RemcosLab-*' -ErrorAction SilentlyContinue)
$existingRules | Select-Object Name,Enabled,Direction,Action | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $backup 'lab-rules-before.json') -Encoding UTF8
$priorService = Get-Service iphlpsvc | Select-Object Name,Status,StartType
$priorService | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'service-before.json') -Encoding UTF8

$proxyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
foreach ($port in $ports) {
    $property = if (Test-Path $proxyKey) { (Get-ItemProperty -LiteralPath $proxyKey).PSObject.Properties["$hostIp/$port"] } else { $null }
    $ownedRule = Get-NetFirewallRule -Name "RemcosLab-WSL-$port" -ErrorAction SilentlyContinue
    if ($property -and -not $ownedRule -and $property.Value -ne "$wslIp/$port") {
        throw "An unowned forwarding entry already uses $hostIp`:$port; refusing to replace it."
    }
}
# The helper preserves credentials and creates a private backup only when addresses change.
& wsl.exe -d $Distro -- python3 "$LinuxLabRoot/scripts/configure_addresses.py" --root $LinuxLabRoot --server-ip $hostIp --bind-ip $wslIp
if ($LASTEXITCODE -ne 0) { throw 'Ubuntu address update failed; host networking has not been changed.' }
Start-Service iphlpsvc
foreach ($port in $ports) {
    & netsh.exe interface portproxy add v4tov4 "listenaddress=$hostIp" "listenport=$port" "connectaddress=$wslIp" "connectport=$port" protocol=tcp
    if ($LASTEXITCODE -ne 0) { throw "Could not configure forwarding for port $port." }
    $ruleName = "RemcosLab-WSL-$port"
    $ruleArgs = @{
        Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Protocol = 'TCP'
        LocalAddress = $hostIp; LocalPort = $port; RemoteAddress = $AnalysisVmIp
        InterfaceAlias = $HostAdapter; Profile = 'Any'
    }
    if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $ruleName @ruleArgs | Out-Null
    } else {
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName @ruleArgs | Out-Null
    }
}
# Explicit blocks take priority over unrelated pre-existing allow rules on this address.
$blockSpecs = @(
    @{ Name = 'RemcosLab-Block-Other-Host-TCP'; Protocol = 'TCP'; LocalPort = @('1-8219','8221-9199','9201-9996','9998-65535') },
    @{ Name = 'RemcosLab-Block-Other-Host-UDP'; Protocol = 'UDP'; LocalPort = 'Any' }
)
foreach ($spec in $blockSpecs) {
    $name = $spec.Name
    $argsForRule = @{
        Direction = 'Inbound'; Action = 'Block'; Enabled = 'True'; Protocol = $spec.Protocol
        LocalAddress = $hostIp; LocalPort = $spec.LocalPort; RemoteAddress = $AnalysisVmIp
        InterfaceAlias = $HostAdapter; Profile = 'Any'
    }
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $name @argsForRule | Out-Null
    } else {
        New-NetFirewallRule -Name $name -DisplayName $name @argsForRule | Out-Null
    }
}
$report = [ordered]@{
    TimestampUtc = [DateTime]::UtcNow.ToString('o'); Distro = $Distro; LinuxLabRoot = $LinuxLabRoot
    HostAdapter = $HostAdapter; LabServerIp = $hostIp; DataBindIp = $wslIp
    PlannedAnalysisVmIp = $AnalysisVmIp; VmConfigurationVerified = $false; CollectorPorts = $ports
    BackupDirectory = $backup; Note = 'Host configuration only. Guest connectivity and SIEM ingestion require the manual VM checkpoint.'
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $labRoot 'data\raw\host-network-current.json') -Encoding UTF8
Write-Host "Host networking configured. Backup: $backup"
& netsh.exe interface portproxy show v4tov4
