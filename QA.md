# Verification

Publication-copy checks passed on 22 October 2026: 19 Python unit tests, the fake-Docker Bash suite, three mocked PowerShell suites, and syntax parsing of all 11 PowerShell source/test files. Repository links and the candidate source files were also checked for missing targets, private lab credentials, and binary content.

The reference deployment passed a benign live Sysmon/PowerShell forwarding check, local ETW/PCAP collection and guest-reboot recovery. Raw case evidence and credentials are private and are not shipped. See the [reference validation record](docs/setup/00-current-status-and-vm-step.md).

## Remcos 4.9.3 Pro YARA validation

On 23 October 2026, run `YARA49-20261023-01` used yara-python 4.5.4 in the isolated Windows VM for read-only file/buffer scanning. Both rules compiled with warnings treated as errors. There were 134 inputs, 268 explicit rule evaluations, zero scan errors and zero expectation failures. The source rules' SHA-256 is recorded in the [validation summary](detections/yara/validation-summary.json); the published rules retain those exact bytes.

Only one independent malware specimen was tested. The renamed copy is not a second positive specimen; OS reference files came from a previously exposed VM. The decoded-content rule deliberately also matches benign analyst notes containing all four IOCs. No 7.0.4 Pro, family-wide, process-memory or population false-positive-rate claim follows from this run. See the [full input matrix and repeat guide](detections/yara/README.md).

R4–R6 were exercised through actual Splunk searches of imported scan metadata and an earlier live Sysmon process-start record. YARA scanned in the VM; Splunk did not execute YARA or block the specimen. The private analysis report preserves the original UI screenshots; they and raw telemetry are not part of this source-only repo update. R1–R3 behavior hunts remain experimental and have not been live-validated.

## Reproducible local checks

**Ubuntu Bash, from repository root:**

```bash
python3 -m unittest discover -s tests -v
bash tests/test_start_siem.sh
```

**Windows PowerShell, from repository root:**

```powershell
.\tests\test_exporter.ps1
.\tests\test_collection.ps1
.\tests\test_marker_time.ps1
```

The Python, fake-Docker and PowerShell checks exercise parsing, normalization, evidence labels, address updates, acquisition error paths, exporter bounds and mocked collection lifecycle. They do not execute malware or prove live EDR coverage. Validate real ingestion with a fresh benign marker on your own deployment.

The public source omits machine-bound network/capture wrappers. The host forwarding script requires an explicit Linux repository path. Private settings, sample archives, raw telemetry and local deployment histories are excluded.
