# Inert regression for a VM whose local time zone differs from UTC.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$module=Import-Module (Join-Path $root 'scripts\LabCollection.psm1') -Force -PassThru
& $module {
    $script:MarkerQueryChecked=$false
    function script:Start-Process { param($FilePath,$ArgumentList,[switch]$Wait,$WindowStyle,$RedirectStandardOutput) }
    function script:Get-WinEvent {
        param($LogName,$FilterXPath,$MaxEvents,$ErrorAction)
        if ($LogName -ne 'Microsoft-Windows-Sysmon/Operational' -or
            $FilterXPath -notlike "*EventID=1*" -or
            $FilterXPath -notlike "*@SystemTime >= '2026-10-22T13:10:00.0000000Z'*") {
            throw 'Marker query must identify Event ID 1 using the correct UTC instant, independent of local wall time.'
        }
        $script:MarkerQueryChecked=$true
        $record=New-Object PSObject
        $record | Add-Member ScriptMethod ToXml { return '<Event>SYNTHETIC_TIMEZONE_MARKER</Event>' }
        return $record
    }
    $found=Test-LabSysmonMarker -Marker SYNTHETIC_TIMEZONE_MARKER -Since ([DateTimeOffset]'2026-10-22T06:10:00-07:00') -Directory $env:TEMP
    if (-not $found -or -not $script:MarkerQueryChecked) { throw 'Offset-time marker regression failed.' }
}
'PASS: offset timestamp matches the UTC event query; no process or real event log was accessed.'
