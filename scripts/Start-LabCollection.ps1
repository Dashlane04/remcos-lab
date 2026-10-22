[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$CaseId,
    [ValidateSet('benign-background','actual-malware')][string]$EvidenceType = 'benign-background',
    [ValidateSet('development','validation','holdout')][string]$Split = 'development',
    [ValidateSet('Both','Splunk','Elastic','Offline')][string]$Forwarding = 'Both',
    [ValidateSet('N0','N1')][string]$NetworkMode = 'N0',
    [string]$SiemAddress = '192.168.56.10',
    [ValidateRange(1, 128)][int]$CaptureInterface = 1,
    [ValidateRange(5, 1800)][int]$ObservationSeconds = 900,
    [ValidateRange(0, 120)][int]$BaselineSeconds = 30,
    [string]$CasesDirectory = 'C:\Lab\Cases',
    [string]$DumpcapPath = 'C:\Program Files\Wireshark\dumpcap.exe',
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$EtwProvider = 'Microsoft-Windows-Kernel-Process',
    [ValidatePattern('^0x[0-9A-Fa-f]{1,16}$')][string]$EtwKeywords = '0xffffffffffffffff',
    [ValidateRange(1, 5)][int]$EtwLevel = 5,
    [string]$SamplePath,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSampleSha256
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCollection.psm1') -Force
Invoke-LabCollection @PSBoundParameters
