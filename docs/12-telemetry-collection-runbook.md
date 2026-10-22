# Telemetry collection with this lab

Prepared 22 October 2026. This runbook matches the files in this repository. Actual host/VM setup and verified results are recorded on [the applied-machine page](setup/00-current-status-and-vm-step.md); the original scaffold is now partially deployed. Run endpoint commands only inside your disposable Windows VM. Existing setup instructions are in [Splunk](02-splunk.md), [Elastic](03-elastic.md), and [Windows/ETW](04-windows-etw.md).

Use [the canonical setup chain](SETUP.md) for installation and normal operation. This page is the manual reference for explaining/troubleshooting evidence paths. PowerShell capture/export blocks below run in the Windows VM; the normalization/import blocks explicitly run in Ubuntu Bash.

## 1. Understand the four evidence paths

```text
Windows VM
  Sysmon driver/service -> Windows Sysmon Operational log
  Windows PowerShell   -> Windows PowerShell Operational log
  Other Windows sources -> Security / TaskScheduler / Defender / System
           |
           +-> Splunk Universal Forwarder -> private TCP 9997 -> Splunk remcos_lab
           +-> Elastic Agent Windows integration -> private TLS 9200 -> Windows data streams
           +-> Export-LabEvents.ps1 -> EVTX + XML + manifest -> offline normalization

  Elastic Defend -> its own endpoint events / protection alerts -> Elasticsearch
  Selected ETW provider -> bounded ETL -> tracerpt XML + summary -> separate investigation
  Endpoint network interface -> dumpcap -> PCAPNG -> Wireshark / flow comparison

  Fleet Server TLS 8220: agent enrollment/policy/control, distinct from event output to 9200
```

Forwarding does not create the events. Sysmon policy, Windows logging/audit settings, and endpoint protection policy determine what is generated; the shipper transports the enabled sources. PCAP, ETL, EVTX, normalized JSON, native EDR alerts, and your custom detections are separate artifacts with different meanings.

## 2. Exact coverage of the supplied configuration

| Evidence | Current scaffold behavior | What to check |
| --- | --- | --- |
| Sysmon process/network/DNS | XML enables 1/5, 3, 22 | Service running; policy active; actual events contain the process/connection fields |
| Sysmon registry | XML enables 12/13/14 | TargetObject and process GUID present |
| Sysmon files | 11 limited to paths containing Users, ProgramData, or Windows Temp | Files elsewhere may not produce the event in this profile |
| Sysmon injection leads | 8 and 25 enabled where generated | Neither guarantees observation of every injection technique |
| ImageLoad / ProcessAccess | Broad 7/10 collection disabled by empty include rules | Absence is expected under this profile |
| Splunk live inputs | Sysmon and Windows PowerShell Operational enabled; checkpoint catch-up plus new-event collection | Receiver/forwarder health, ingestion lag and original-time parsing |
| Security / TaskScheduler / Defender / System | Not all enabled as live inputs in the starter | `-IncludeCampaignLogs` preserves them offline if available; enable/test additional live inputs deliberately |
| Elastic Windows integration | Sysmon/PowerShell must be selected in the enrolled policy | Dataset, policy revision, field names, actual delivery |
| Elastic Defend | Separate endpoint component and policy | Healthy component; events/alerts retained separately from Sysmon |
| ETW | Short manual script, not continuous ingestion | Provider/keywords/level, usable ETL, loss and circular-buffer limits |
| PCAP | Requires Wireshark/Npcap or a verified external sensor | Correct interface; actual visibility; captured/drop counts |

The Sysmon event meanings and optional collectors are described in the [Microsoft reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). The table above describes this repository's chosen profile, not every capability of Sysmon.

## 3. Preflight inside the Windows VM

Assume the repository is copied to `C:\Lab\remcos-soc-lab`. Adjust tool paths and the private SIEM address to your actual VM setup. For the first pilot, use **Windows PowerShell 5.1**, because the supplied event inputs/exporter target `Microsoft-Windows-PowerShell/Operational`. PowerShell 7 uses its own provider/channel and is not automatically covered.

```powershell
Set-Location C:\Lab\remcos-soc-lab
$PSVersionTable.PSVersion
Get-Service | Where-Object { $_.Name -in @('Sysmon','Sysmon64','SplunkForwarder','Elastic Agent','elastic-agent') } |
    Select-Object Name,Status
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Windows Defender/Operational',Security,System |
    Select-Object LogName,IsEnabled,RecordCount,MaximumSizeInBytes
```

Run elevated when inspecting/exporting Security or capturing ETW. Service status alone does not prove that events reach the SIEM.

Display the active Sysmon configuration and hash the intended XML:

```powershell
C:\Lab\Tools\Sysmon64.exe -c
Get-FileHash configs/sysmon/sysmon-lab.xml -Algorithm SHA256
```

If Sysmon was not installed/configured, complete the setup guide first; displaying `-c` does not apply the XML. Retain its displayed active-policy output in the run notes. Do not confuse the hash of a file on disk with proof that this policy is active.

Enable Windows PowerShell **Script Block Logging** in the VM's Group Policy settings as described in the Windows setup guide, then start a new 5.1 session. Verify 4104 after a harmless script. PowerShell 7 logging differences are documented [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows).

For a campaign run, inspect TaskScheduler Operational. If disabled, enabling that channel is a deliberate VM configuration step:

```powershell
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

Security 4688 needs process-creation auditing; its command line needs the separate command-line policy. Security 4698/4702 need the appropriate task-related audit settings. Use the prerequisites in the [comparative protocol](08-comparative-traffic-telemetry-protocol.md). `-IncludeCampaignLogs` never enables auditing or channels. Record changes before taking the clean collection snapshot.

Check only the private collector ports that you actually use:

```powershell
Test-NetConnection 10.10.10.1 -Port 9997
Test-NetConnection 10.10.10.1 -Port 8220
Test-NetConnection 10.10.10.1 -Port 9200
```

A TCP connection to 9200 does not validate TLS, enrollment, or event delivery. The scaffold defaults data ports to localhost until `DATA_BIND_IP` is configured on the SIEM server. Keep public egress blocked during specimen collection; permit only required private collector/services. Synchronize/measure clocks before the isolated run and record any remaining offset.

## 4. First collect a benign pilot

Complete this before handling a sample. Use a new case ID for every collection. In elevated **terminal B**, create the case directories:

```powershell
Set-Location C:\Lab\remcos-soc-lab
$caseId = 'BASE-003'
$caseRoot = Join-Path C:\Lab\Cases $caseId
if (Test-Path -LiteralPath $caseRoot) { throw 'Choose a new case ID.' }
New-Item -ItemType Directory -Path $caseRoot | Out-Null
New-Item -ItemType Directory -Path (Join-Path $caseRoot 'network') | Out-Null
```

In **terminal A**, list capture interfaces and start a bounded capture. These variables are local to terminal A; repeat the path there:

```powershell
$caseRoot = 'C:\Lab\Cases\BASE-003'
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
```

Select the actual lab NIC from that list. Replace the example interface number `1` below. Capturing on another VM without routing/mirroring does not guarantee visibility of this endpoint's traffic.

```powershell
& 'C:\Program Files\Wireshark\dumpcap.exe' -i 1 -a duration:300 -w "$caseRoot\network\traffic.pcapng"
```

Keep terminal A open. It stops after five minutes or Ctrl+C. Check its packet/drop summary afterward. The capture initially includes SIEM/Fleet traffic; label it during analysis rather than deleting it from raw evidence. [dumpcap options](https://www.wireshark.org/docs/man-pages/dumpcap.html)

If ETW is part of this pilot, start it in elevated **terminal C** immediately before the activity:

```powershell
Set-Location C:\Lab\remcos-soc-lab
logman query providers Microsoft-Windows-Kernel-Process
./scripts/Capture-Etw.ps1 -DurationSeconds 60 -Provider Microsoft-Windows-Kernel-Process -OutputDirectory C:\Lab\Cases\BASE-003\etw
```

The helper stops only its own trace and decodes it afterward. Its default all-keyword mask is exploratory, so keep this pilot short. The 60-second ETW window will cover only a subset of the longer pilot; its capture JSON records that boundary.

Back in **terminal B**, after confirming capture has started:

```powershell
$runStartUtc = [DateTimeOffset]::UtcNow
Start-Sleep -Seconds 20
$activityStartUtc = [DateTimeOffset]::UtcNow
$workloadRoot = Join-Path $env:LOCALAPPDATA "RemcosLab\$caseId"
./scripts/Invoke-BenignWorkload.ps1 -DurationSeconds 120 -OutputDirectory $workloadRoot
Start-Sleep -Seconds 30
$runEndUtc = [DateTimeOffset]::UtcNow
[ordered]@{
    case_id = $caseId
    evidence_type = 'benign-background'
    start_utc = $runStartUtc.ToString('o')
    activity_start_utc = $activityStartUtc.ToString('o')
    end_utc = $runEndUtc.ToString('o')
    computer = $env:COMPUTERNAME
    workload_source_path = $workloadRoot
} | ConvertTo-Json | Set-Content "$caseRoot\run.json" -Encoding UTF8
./scripts/Export-LabEvents.ps1 -StartUtc $runStartUtc -EndUtc $runEndUtc -IncludeCampaignLogs -OutputDirectory "$caseRoot\windows"
Copy-Item -LiteralPath $workloadRoot -Destination "$caseRoot\workload" -Recurse
```

The benign helper launches harmless processes and writes local text files. Its working directory is under the VM user's LocalAppData so the supplied Sysmon file-creation filter includes it; `C:\Lab\Cases` itself is outside that file filter. The helper files are copied into the case after the observation window. Without `-LocalHttpUrl` it deliberately generates no application network traffic; only existing system/collector connections may be visible. To check network attribution, repeat in a separate case with a private harmless HTTP endpoint from the [workload plan](07-workload-plan.md). A failed connection probe is not equivalent to a successful connection or C2.

For a 4104 check, run a short harmless command in a new Windows PowerShell 5.1 session within the recorded window and verify the resulting event locally. Do not expect the synthetic fixture's exact event counts or detection hits from this real benign pilot.

After the export finishes, stop PCAP with Ctrl+C if still running and inspect its summary. Export/file hashing generates additional events after `$runEndUtc`; those fall outside the selected Windows activity interval. Record the wider PCAP/ETW boundaries rather than assuming every artifact covers identical times.

## 5. Verify the evidence before importing

Expected files under the case root:

```text
BASE-003/
  run.json
  network/traffic.pcapng
  workload/BENIGN-.../session.json and harmless helper files
  windows/manifest.json
  windows/sysmon.evtx + sysmon.xml
  windows/powershell.evtx + powershell.xml
  windows/security.evtx + security.xml                 if available
  windows/task-scheduler.evtx + task-scheduler.xml     if available
  windows/defender.evtx + defender.xml                 if available
  windows/system.evtx + system.xml                     if available
  etw/trace.etl + trace.xml + summary.txt + capture.json + provider.txt + sha256.txt
```

The workload subdirectory has a generated name; inspect the actual output. ETW exists only if you ran that step. Read the Windows manifest first:

```powershell
$manifest = Get-Content "$caseRoot\windows\manifest.json" -Raw | ConvertFrom-Json
$manifest.channels | Format-Table channel,status,count,reason -AutoSize
Get-FileHash "$caseRoot\network\traffic.pcapng" -Algorithm SHA256
```

`exported` with zero records and `failed` are different results. Investigate the reason for each failed channel. The exporter reads XML from the exported EVTX snapshot, so its XML and EVTX cover the same query selection; the manifest hashes both. Its Security export includes only 4688/4698/4702, not the entire Security log.

Inspect sample events in Event Viewer or `Get-WinEvent -Path ...`; confirm UTC, host, provider, command line, process GUID, and destination fields against the original event XML. Do not clear Windows logs between cases: clean-snapshot resets and recorded time windows provide separation without destroying evidence.

## 6. Verify live delivery in both SIEMs

On the analyst/SIEM machine, set an absolute search window matching `run.json` and select the correct endpoint. In Splunk's **Remcos Lab** app:

```spl
`remcos_sysmon`
| stats count by host_id event_code
```

For process-level inspection:

```spl
`remcos_sysmon`
| search event_code="1"
| table _time host_id image command_line process_guid
```

For the other configured live source:

```spl
index=remcos_lab sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
| table _time host _raw
```

The starter's broad XML field extractions apply to Sysmon; PowerShell may need raw XML inspection or an appropriate add-on for richer fields. Live forwarding does not automatically attach a case ID: constrain live searches by host and the recorded window. When comparing counts, also specify the provider/channel/event IDs and allow forwarding to catch up.

In Elastic Discover, inspect the **live** Windows streams and matching absolute window:

```kql
event.dataset : "windows.sysmon_operational" and host.name : "YOUR-WINDOWS-HOST"
```

Use your actual host name. Check the corresponding PowerShell dataset selected in Fleet; do not assume a dataset name without inspecting arriving events. Separately inspect endpoint data:

```kql
data_stream.dataset : endpoint.events.* and host.name : "YOUR-WINDOWS-HOST"
```

Check Fleet agent health, the endpoint security component, effective policy revision, and incoming timestamps. An enrolled agent can still fail output delivery because of a CA/address problem. A missing endpoint event is not automatically a shipping failure: compare the configured event coverage and any prevention action first.

## 7. Preserve a reproducible offline comparison dataset

Copy the case evidence into Ubuntu while retaining hashes, following [setup step 7](setup/07-evidence-and-detection.md). The examples here assume the preserved Ubuntu copy is `~/remcos-soc-lab/data/raw/cases/BASE-003`. Normalization needs Python, not access to the active Windows event channels.

**Run in: SIEM / Ubuntu Bash.**

```bash
cd ~/remcos-soc-lab
python3 scripts/normalize_events.py data/raw/cases/BASE-003/windows/sysmon.xml --output data/normalized/BASE-003-sysmon.ndjson --case-id BASE-003 --evidence-type benign-background --split development
```

Normalize other successfully exported XML files separately, choosing distinct output filenames but the same case/evidence/split labels. Do not force a PowerShell, Security, or ETW provider into the Sysmon dataset. The normalizer preserves non-Sysmon payloads under `winlog.event_data`; it does not promise Sysmon-style convenience fields for those providers.

For Splunk offline ingestion, copy that NDJSON **once** into this repository's `data/import` on the SIEM machine; the container monitors that mount. Do not copy raw executable/PCAP/ETL artifacts into the monitored input.

**Run in: SIEM / Ubuntu Bash.**

```bash
cp -n data/normalized/BASE-003-sysmon.ndjson data/import/BASE-003-sysmon.ndjson
```

In Splunk, restrict the replay query to the offline source and case so it does not count the live copy as another event:

```spl
index=remcos_lab sourcetype="remcos:json" labels.case_id="BASE-003"
| stats count by 'winlog.provider_name' 'event.code'
```

For Elastic offline ingestion, use the existing authenticated importer and the public lab CA:

**Run in: SIEM / Ubuntu Bash.**

```bash
python3 scripts/import_elastic.py data/normalized/BASE-003-sysmon.ndjson --url https://localhost:19200 --ca infra/certs/ca.crt --username elastic --index remcos-lab-events
```

The Ubuntu analyst endpoint is TLS localhost port 19200; remote endpoint traffic uses forwarded 9200. The importer prompts for the password. In Discover use the **offline** data view `remcos-lab-*`, the original absolute time window, and:

```kql
labels.case_id : "BASE-003" and event.dataset : "windows.sysmon_operational"
```

Do not search a combined live+offline data view and interpret both copies as independent observations. When evaluating an included hunt, add the offline case constraint to the same search; for a live hunt use the explicit host/time window. Preserve original event times rather than retiming old evidence to trigger a current rule.

## 8. Preserve Elastic Defend evidence separately

`Export-LabEvents.ps1` preserves Windows event channels; it does **not** export all Elastic Defend endpoint documents or Kibana security alerts. EVTX files alone therefore do not preserve the full EDR experiment.

Before reverting an endpoint snapshot, confirm the relevant data reached Elasticsearch. In Discover, save the case-scoped endpoint query and export the selected event table/JSON where the installed interface permits it. Record query, indices, host, UTC bounds, time of export, policy, and event/alert IDs. Retain the server data volume. CSV reports can omit nested fields or hit row limits, so use JSON/search exports for evidence needing those fields and record any truncation.

For a small raw endpoint export, Kibana Dev Tools can run this **read-only** query after you replace the host and timestamps with the actual case values:

```json
GET logs-endpoint.events.*/_search
{
  "size": 1000,
  "track_total_hits": true,
  "query": {"bool": {"filter": [
    {"term": {"host.name": "YOUR-WINDOWS-HOST"}},
    {"range": {"@timestamp": {"gte": "2026-10-22T03:00:00Z", "lte": "2026-10-22T03:15:00Z"}}}
  ]}},
  "sort": [{"@timestamp": "asc"}]
}
```

These timestamps are syntax examples only. Save the response as JSON alongside the case. Compare `hits.total.value` to the returned hit count; a response containing only 1000 of more hits is incomplete. Use an appropriate paginated/PIT export or record the limitation. If the endpoint streams do not exist or you lack permission, investigate that condition rather than treating it as zero endpoint activity. [Search API reference](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search)

Export relevant native security alerts from Security/Alerts separately, retaining their status/action and associated event references. Your custom rule results must be saved separately too; a native EDR alert is not validation of the custom SPL/KQL/EQL hunt.

## 9. What ETW adds and how to handle it

Choose a question such as: *Does this provider add process lifecycle or image context that helps explain a Sysmon/network discrepancy?* Use the same available provider/keywords/level and comparable short windows for both specimens.

The helper produces a circular ETL capped at 256 MB, provider details, actual start/stop times, decoded XML, and tracerpt's summary. Review lost events/buffers and whether the circular file could have overwritten early data. A zero loss count alone does not establish full-window retention. The helper captures no universal API history and guarantees no specific injection event.

For an XML format the normalizer supports:

**Run in: SIEM / Ubuntu Bash, after transferring the ETW evidence.**

```bash
python3 scripts/normalize_events.py data/raw/cases/BASE-003/etw/trace.xml --output data/normalized/BASE-003-etw.ndjson --case-id BASE-003 --evidence-type benign-background --split development --dataset lab.etw
```

If conversion rejects the tracerpt envelope or fields are incomplete, keep the ETL/XML and inspect them in Windows Performance Analyzer or write a provider-specific adapter. Do not call an unsuccessful/empty conversion a successful trace analysis. The supplied Sysmon hunts intentionally exclude `lab.etw`.

ETW's System/Execution PID may identify the event emitter rather than the process described in its payload. The normalizer retains it as `winlog.process.pid`. Resolve provider-specific target fields and process lifetimes before correlating with Sysmon. Join using run ID + host + verified process identity + time; a PID alone can be reused.

## 10. Move from the pilot to paired specimen cases

After the benign pilot works, use separate clean-snapshot cases such as `P49-01` and `P70-01`. Verify the [specimens](10-sample-provenance.md), then follow the [full comparative protocol](08-comparative-traffic-telemetry-protocol.md).

- Use the same collection profile, network mode, observation length, background activity, protection policy, and relevant VM settings. Record actual differences instead of patching the specimens to force equal behavior.
- A suggested full observation window is 2 minutes before the selected activity, 10 minutes observing it, and 3 minutes afterward. Start PCAP beforehand with a slightly longer bounded duration, and record actual times. ETW can remain a shorter targeted window.
- Capture the activity time just before the manually controlled specimen experiment. This runbook supplies collection commands, not an automatic malware launcher. If protection stops a stage, retain that result and explain what was never reached.
- Record actual-malware labels only for genuine collected specimen activity, with the verified specimen hash in the case manifest. Keep source-reported campaign stages and synthetic fixtures distinct.
- Export Windows evidence with exact bounds, retain endpoint events/alerts, wait for evidence delivery, copy/hash local evidence out of the VM, and only then revert the snapshot. Preserve SIEM volumes across cases.

For analysis, first establish what happened locally, then check whether the shipper delivered it, then examine field extraction/detection behavior. A SYN in PCAP does not guarantee Sysmon event 3; no DNS event is plausible for a direct-IP connection. A signed hollowed host's on-disk hash is not the injected payload's hash. TLS/configuration can prevent readable application traffic without indicating collection failure.

## 11. Case acceptance checklist

- [ ] Case ID, specimen/configuration (where applicable), VM snapshot, policy, and UTC window recorded.
- [ ] Required sources enabled and a harmless marker verified locally and in the chosen SIEM path.
- [ ] PCAP capture point/interface and packet/drop summary checked.
- [ ] Windows export manifest reviewed: failures distinguished from zero-event windows; hashes retained.
- [ ] ETW provider/window/loss/retention reviewed if used.
- [ ] Elastic Defend documents/alerts preserved separately if used.
- [ ] No double counting across live versus offline copies, providers, or repeated cases.
- [ ] Relevant process/flow joins and discrepancies entered in the companion templates.
- [ ] Evidence copied out and verified before endpoint rollback.

For each discrepancy, distinguish generation/policy, shipping delay/failure, field mapping, environment/configuration, and actual behavioral differences. The detailed register and flow/timeline templates are linked from the comparative protocol.
