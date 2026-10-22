# Verification

Publication-copy checks passed on 22 October 2026: 19 Python unit tests, the fake-Docker Bash suite, three mocked PowerShell suites, and syntax parsing of all 11 PowerShell source/test files. Repository links and the candidate source files were also checked for missing targets, private lab credentials, and binary content.

The reference deployment passed a benign live Sysmon/PowerShell forwarding check, local ETW/PCAP collection and guest-reboot recovery. Raw case evidence and credentials are private and are not shipped. See the [reference validation record](docs/setup/00-current-status-and-vm-step.md).

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
