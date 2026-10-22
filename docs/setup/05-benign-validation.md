# Step 5 — Pass the benign collection checkpoint

Previous: [Step 4](04-windows-endpoint.md) | [Setup index](../SETUP.md) | Next: [Step 6](06-specimen-collection.md)

Do this before specimen work and again after major collection/network changes. Start only the selected stack from step 3. The collector verifies local readiness, while browser searches establish delivery to the SIEM.

## VM: start the Splunk-phase pilot

In an elevated Windows VM terminal, use the actual dumpcap interface and fresh case ID:

Select the current host-only adapter from `dumpcap -D` and pass its number explicitly to the generic collector. Adapter numbering can change when interfaces are disconnected. Verify routes and connectivity separately; see the [reference validation record](00-current-status-and-vm-step.md).

**Run in: VM / Administrator PowerShell, terminal A.**

```powershell
Set-Location C:\Lab\remcos-soc-lab
./scripts/Start-LabCollection.ps1 -CaseId BASE-SPL-01 -Forwarding Splunk -SiemAddress 10.10.10.1 -CaptureInterface 1 -ObservationSeconds 120 -BaselineSeconds 15
```

The collector checks installed services/channels and private TCP 9997, starts ETW/PCAP, creates a harmless process marker, confirms its Sysmon event locally, records the baseline, then prints READY. Keep this terminal open. Failure before READY is a setup failure to investigate, not an invitation to start the specimen anyway.

After READY, run benign work in a second VM terminal:

**Run in: VM / PowerShell, terminal B.**

```powershell
Set-Location C:\Lab\remcos-soc-lab
./scripts/Invoke-BenignWorkload.ps1 -DurationSeconds 60 -OutputDirectory "$env:LOCALAPPDATA\RemcosLab\BASE-SPL-01"
```

The helper files are created under a user directory to match the Sysmon file-creation filter. It does not create startup persistence or injection. Without its optional private HTTP URL it generates no application network traffic; ordinary collector/system traffic may still appear in PCAP.

## Browser: find the exact marker in Splunk

Use the Remcos Lab app, the endpoint host, and the actual collection window. Replace the placeholder with the whole `REMCOS_LAB_...` value printed by the collector:

**Run in: HOST browser / Splunk search.**

```spl
`remcos_sysmon`
| search command_line="*REPLACE_WITH_EXACT_PRINTED_MARKER*"
| table _time host_id image command_line process_guid
```

Also inspect process/network/DNS counts and the Windows PowerShell raw events. The bundled Sysmon XML fallback fields are not a full Windows add-on, and PowerShell 4104 requires its logging policy to be enabled separately. Confirm event contents against local Windows XML, not only a dashboard count.

## VM + browser: Elastic-phase pilot, when resources permit

Complete the Elastic/Fleet setup, stop Splunk on Ubuntu, and select an independently recorded case:

**Run in: VM / Administrator PowerShell, terminal A.**

```powershell
./scripts/Start-LabCollection.ps1 -CaseId BASE-EL-01 -Forwarding Elastic -SiemAddress 10.10.10.1 -CaptureInterface 1 -ObservationSeconds 120 -BaselineSeconds 15
```

After READY, repeat harmless activity in terminal B using a corresponding LocalAppData directory. The collector checks 8220/9200 for this phase and does not require the stopped Splunk service. It starts selected installed services if necessary, but it does not install/configure agents or prove TLS output delivery.

**Run in: HOST browser / Elastic Discover, actual live Sysmon data view and time window.**

```kql
event.dataset : "windows.sysmon_operational" and process.command_line : "*REPLACE_WITH_EXACT_PRINTED_MARKER*"
```

If the actual live integration exposes command lines under `winlog.event_data.CommandLine`, inspect that field instead. Verify Fleet/endpoint component health and separately inspect `endpoint.events.*` data and any native alerts. Offline fixture records do not establish Defend health.

## VM: inspect the saved case

Default case root is `C:\Lab\Cases\CASE-ID`. The collector saves PCAPNG, ETL/decoded XML where available, six-source Windows EVTX/XML, run metadata, and final file hashes. It records source failures and attempts cleanup/export on failure. A forced capture stop can leave partial data; a hard shell/VM termination cannot guarantee cleanup.

**Run in: VM / PowerShell after collection ends.**

```powershell
$caseRoot = 'C:\Lab\Cases\BASE-SPL-01'
(Get-Content "$caseRoot\run.json" -Raw | ConvertFrom-Json) | Select-Object case_id,status,started_utc,ready_utc,ended_utc,source_gaps
(Get-Content "$caseRoot\windows\manifest.json" -Raw | ConvertFrom-Json).channels | Format-Table channel,status,count,reason -AutoSize
```

Adjust the case ID for the Elastic phase. `completed_with_source_gaps`, zero records, and failed channels are different outcomes. Read packet/drop diagnostics and ETW's summary; circular retention/loss and provider-specific fields still need review.

## Acceptance checkpoint

- Local Sysmon marker found; same original marker/host/time found in the selected live SIEM.
- Command lines, process GUIDs, timestamps, and applicable file/connection fields checked against original events.
- Required PowerShell logging verified; available campaign-channel audit settings and gaps recorded.
- Packet interface/content and ETW decoding/retention reviewed.
- Windows export and integrity manifests present; case preserved before rollback.
- Fleet/Defend checked separately if this phase uses it.

Only then take the clean collection snapshot for that phase and continue to [step 6](06-specimen-collection.md). Sensor/protection differences between the Splunk-only and Elastic/Defend phases must be recorded; they are not version differences in Remcos.

For optional private HTTP traffic, see the [controlled background workload reference](../07-workload-plan.md). Its Ubuntu bind address and the endpoint-facing forwarded address differ in this topology.
