#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpectedComputerName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$SysmonSha256,
    [string]$LabRoot = 'C:\Lab\remcos-soc-lab'
)
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne $ExpectedComputerName) { throw 'Computer-name guard failed; run only in the intended disposable VM.' }
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights are required inside the disposable VM.' }
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$records=Join-Path 'C:\Lab\SetupRecords' "collectors-$stamp"
[void](New-Item -ItemType Directory -Path $records,'C:\Lab\Tools' -Force)
$sysmonSource=Join-Path $LabRoot 'Sysmon64.exe'
$msi=Join-Path $LabRoot 'splunkforwarder-10.4.0-f798d4d49089-windows-x64.msi'
$expectedMsi='2FE8D69D526C3B04071EA4CDD96262D0B235EAC24D658DEE31A87D2998D1D0C5'
foreach ($item in @(@{Path=$sysmonSource;Hash=$SysmonSha256;Signer='Microsoft'},@{Path=$msi;Hash=$expectedMsi;Signer='Splunk'})) {
    if ((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash -ne $item.Hash) { throw "Installer hash mismatch: $($item.Path)" }
    $signature=Get-AuthenticodeSignature -LiteralPath $item.Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch $item.Signer) { throw "Unverified installer signature: $($item.Path) / $($signature.Status)" }
}
$sysmon='C:\Lab\Tools\Sysmon64.exe'
if (Test-Path -LiteralPath $sysmon) {
    if ((Get-FileHash -LiteralPath $sysmon -Algorithm SHA256).Hash -ne $SysmonSha256) { throw 'An existing different Sysmon tool must be reviewed before replacement.' }
} else { Copy-Item -LiteralPath $sysmonSource -Destination $sysmon }
$sysmonConfig=Join-Path $LabRoot 'configs\sysmon\sysmon-lab.xml'
$installedSysmon=@(Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue)
if ($installedSysmon.Count) {
    & $sysmon -c $sysmonConfig
} else {
    & $sysmon -accepteula -i $sysmonConfig
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon installation/configuration failed: $LASTEXITCODE" }
Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -ne Running | Start-Service
& wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /ms:268435456
if ($LASTEXITCODE -ne 0) { throw 'Could not set Sysmon log capacity.' }

$policyPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$priorPolicy=Get-ItemProperty -LiteralPath $policyPath -ErrorAction SilentlyContinue
@{Path=$policyPath;Existed=($null -ne $priorPolicy);EnableScriptBlockLogging=$priorPolicy.EnableScriptBlockLogging} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $records 'powershell-policy-before.json') -Encoding UTF8
[void](New-Item -Path $policyPath -Force)
[void](New-ItemProperty -LiteralPath $policyPath -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force)
foreach ($channel in @('Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational')) {
    & wevtutil.exe sl $channel /e:true /ms:67108864
    if ($LASTEXITCODE -ne 0) { throw "Could not enable $channel" }
}

if (-not (Get-Service SplunkForwarder -ErrorAction SilentlyContinue)) {
    # Installer-generated UF credentials are separate from Windows/SSH credentials.
    # No Windows password, server password or enrollment token is passed/stored here.
    $arguments=@('/i',('"'+$msi+'"'),'AGREETOLICENSE=Yes','SPLUNKUSERNAME=admin','GENRANDOMPASSWORD=1',
        'USE_VIRTUAL_ACCOUNT=1','GROUPPERFORMANCEMONITORUSERS=0','LAUNCHSPLUNK=0','SERVICESTARTTYPE=auto',
        '/quiet','/norestart','/L*v',('"'+(Join-Path $records 'forwarder-install-private.log')+'"'))
    $installer=Start-Process -FilePath msiexec.exe -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
    if ($installer.ExitCode -notin @(0,3010)) { throw "Universal Forwarder install failed: $($installer.ExitCode). Inspect the private installer log locally." }
}
$forwarder='C:\Program Files\SplunkUniversalForwarder'
$local=Join-Path $forwarder 'etc\apps\remcos_lab\local'
[void](New-Item -ItemType Directory -Path $local -Force)
foreach ($name in @('inputs.conf','outputs.conf','limits.conf')) {
    $existing=Join-Path $local $name
    if (Test-Path -LiteralPath $existing) { Copy-Item -LiteralPath $existing -Destination (Join-Path $records ($name+'.before')) }
}
Copy-Item -LiteralPath (Join-Path $LabRoot 'configs\splunk\forwarder\inputs.conf') -Destination (Join-Path $local 'inputs.conf')
Copy-Item -LiteralPath (Join-Path $LabRoot 'configs\splunk\forwarder\limits.conf') -Destination (Join-Path $local 'limits.conf')
$outputText=[IO.File]::ReadAllText((Join-Path $LabRoot 'configs\splunk\forwarder\outputs.conf.example'))
$outputText=$outputText.Replace('192.168.56.10:9997','10.10.10.1:9997')
[IO.File]::WriteAllText((Join-Path $local 'outputs.conf'),$outputText,(New-Object Text.UTF8Encoding($false)))
$service=Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'"
if ($service.StartName -eq 'NT SERVICE\SplunkForwarder') {
    $readers=Get-LocalGroup -SID 'S-1-5-32-573'
    $members=@(Get-LocalGroupMember -Group $readers.Name)
    if (-not ($members | Where-Object Name -eq 'NT SERVICE\SplunkForwarder')) {
        Add-LocalGroupMember -Group $readers.Name -Member 'NT SERVICE\SplunkForwarder'
    }
}
Set-Service SplunkForwarder -StartupType Automatic
Restart-Service SplunkForwarder
$report=[ordered]@{
    TimestampUtc=[DateTime]::UtcNow.ToString('o');Computer=$env:COMPUTERNAME
    SysmonVersion=(Get-Item -LiteralPath $sysmon).VersionInfo.FileVersion
    SysmonSha256=(Get-FileHash -LiteralPath $sysmon -Algorithm SHA256).Hash
    SysmonPolicySha256=(Get-FileHash -LiteralPath $sysmonConfig -Algorithm SHA256).Hash
    ForwarderVersion=(Get-Item -LiteralPath (Join-Path $forwarder 'bin\splunk.exe')).VersionInfo.ProductVersion
    ForwarderServiceIdentity=$service.StartName;ForwarderTarget='10.10.10.1:9997'
    Services=@(Get-Service Sysmon64,Sysmon,SplunkForwarder,sshd -ErrorAction SilentlyContinue | Select-Object Name,Status)
    Note='Installation/configuration only. Indexed benign event and private network isolation must be verified separately.'
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $records 'collector-install.json') -Encoding UTF8
$report | ConvertTo-Json -Depth 5
