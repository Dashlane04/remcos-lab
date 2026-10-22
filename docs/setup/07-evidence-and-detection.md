# Step 7 — Preserve, normalize, investigate, and report

Previous: [Step 6](06-specimen-collection.md) | [Setup index](../SETUP.md)

This step distinguishes original Windows evidence, live SIEM copies, offline normalized copies, ETW, packet evidence, native EDR alerts, and custom detection results. Do not count duplicate representations as independent observations.

## Browser: preserve live evidence before rollback

Use the original host and UTC window from `run.json`. Verify buffered events reached the chosen SIEM before reverting. Save relevant queries/results and native alert references with the actual policy and collection profile.

Elastic Defend data are separate from Windows EVTX. Preserve relevant `endpoint.events.*` documents and native alerts from the Elastic phase, including action/status and event IDs. A Discover CSV can omit nested fields or be truncated; use an appropriate JSON/paginated export where needed and record limits. The [manual telemetry reference](../12-telemetry-collection-runbook.md) includes a read-only endpoint search and export caveats. Offline Windows replay cannot recreate absent live Defend evidence.

## HOST: retrieve a case from the Windows VM

Use the already verified VM SSH connection. Retrieve only the case/evidence directory; the collector does not copy the specimen into it.

**Run in: HOST / PowerShell.**

```powershell
$hostCases = 'C:\LabSource\remcos-soc-lab\data\raw\cases'
New-Item -ItemType Directory -Path $hostCases -Force | Out-Null
scp.exe -o StrictHostKeyChecking=yes -r 'test@10.10.10.20:C:/Lab/Cases/P49-SPL-01' $hostCases
```

Choose a new destination for a repeated transfer rather than merging inconsistent case versions. Preserve `integrity.json` and verify file hashes after copying. Original raw evidence remains immutable; label/normalization outputs are separate files. Review raw logs before publication because script logs can contain sensitive text.

## SIEM / Ubuntu Bash: bring the preserved case into Linux storage

**Run in: SIEM / Ubuntu Bash.**

```bash
cd ~/remcos-soc-lab
mkdir -p data/raw/cases
cp -an '/mnt/c/LabSource/remcos-soc-lab/data/raw/cases/P49-SPL-01' data/raw/cases/
```

This preserves an existing destination instead of overwriting it. If the case already exists, stop and compare integrity rather than treating a merged/partial copy as a new complete case. Verify the preserved manifest before rollback. Then the Windows VM can be reverted or powered off as appropriate for the next phase.

## SIEM / Ubuntu Bash: normalize Windows XML

**Run in: SIEM / Ubuntu Bash.**

```bash
python3 scripts/normalize_events.py data/raw/cases/P49-SPL-01/windows/sysmon.xml --output data/normalized/P49-SPL-01-sysmon.ndjson --case-id P49-SPL-01 --evidence-type actual-malware --split development
```

Use `benign-background` for the benign cases and the correct split for held-back evaluation. The label is a declaration, not proof of execution. The normalizer preserves original timestamps/provider fields and source hashes; only Sysmon's provider receives the convenience mappings. Normalize each other exported XML separately without forcing it into the Sysmon dataset.

For compatible ETW XML use `--dataset lab.etw`; retain the original ETL and inspect provider fields/loss. An emitting PID is not automatically the payload's target PID. A rejected tracerpt envelope requires a provider-specific adapter, not a silently empty import.

## SIEM + browser: offline Splunk analysis

Start the Splunk phase as in step 3. Copy each normalized file once to the monitored import directory:

**Run in: SIEM / Ubuntu Bash.**

```bash
cp -n data/normalized/P49-SPL-01-sysmon.ndjson data/import/P49-SPL-01-sysmon.ndjson
```

**Run in: HOST browser / Splunk, the actual original time range.**

```spl
index=remcos_lab sourcetype="remcos:json" labels.case_id="P49-SPL-01"
| stats count by 'winlog.provider_name' 'event.code'
```

When applying the supplied SPL hunts, add the offline sourcetype/case constraint to the same search so live and imported copies are not double counted. For live investigation use the actual host/time window; live forwarding does not automatically add this offline case label.

## SIEM + browser: replay the same Windows evidence in Elastic

On this resource-limited host, preserve evidence and stop Splunk before starting Elastic. Fleet can stay off for pure offline analysis; a live Defend phase is a separate experiment.

**Run in: SIEM / Ubuntu Bash.**

```bash
bash scripts/start-siem.sh --stack splunk --stop
bash scripts/start-siem.sh --stack elastic --fleet off --live
python3 scripts/import_elastic.py data/normalized/P49-SPL-01-sysmon.ndjson --url https://localhost:19200 --ca infra/certs/ca.crt --username elastic --index remcos-lab-events
```

The importer prompts for credentials and validates TLS. In Discover choose offline data view `remcos-lab-*`, original event times, and:

**Run in: HOST browser / Elastic Discover.**

```kql
labels.case_id : "P49-SPL-01" and event.dataset : "windows.sysmon_operational"
```

The catalog at `detections/elastic/hunts.json` is explanatory JSON, not a directly importable Kibana rule object. Use KQL for its filters and an EQL query/rule for its sequence; validate real mappings and time fields. Offline indices differ from live `logs-windows.sysmon_operational-*` data streams.

## Evaluate and compare

R1 is a broad Run/RunOnce-write hunt; R2 looks for watchdog-related `EXEpath` writes; R3 correlates a Run write and a same-process connection within five minutes. They are hypotheses, not family attribution. A disabled feature, missing sensor, blocked stage, or process handoff can explain a missing match. Validate applicable observations and benign alternatives rather than forcing every rule to fire.

Use held-back benign/specimen cases after tuning. Record event volume, duration, matched/missed cases, query time, and gaps; replay query time is not live alert latency. Keep built-in EDR alerts, custom behavior matches, and any later specimen-derived YARA findings separate.

Compare 4.9.3 and 7.0.4 using run ID + host + verified process identity + time. Classify differences as payload, configuration, delivery, environment/protection, collection/pipeline, or unresolved. The final native payload and the campaign's document/.NET loader are distinct analysis layers.

Complete the companion sample/run, process-flow, timeline, discrepancy, IOC, validation, and case-report templates. Raw binaries and evidence stay private; publish sanitized, reproducible findings. See [validation methodology](../05-validation.md) and the [comparative protocol](../08-comparative-traffic-telemetry-protocol.md).

**Finish checkpoint:** original artifacts and hashes preserved, live/offline sources distinguished, meaningful rule evaluation completed, discrepancies explained, and claims limited to the work actually observed. For the next run return to [step 6](06-specimen-collection.md); for a new deployment return to [the setup index](../SETUP.md).
