# Reference deployment validation

[README](../../README.md) | [Setup guide](../SETUP.md) | [Benign validation](05-benign-validation.md)

The original reference deployment was validated on 22 October 2026. Its private credentials, host identities, adapters, snapshots, and raw evidence are not distributed in this repository. Configure and validate your own system before collection.

| Component | Observed reference result |
| --- | --- |
| Splunk 10.4.0 | Healthy native Ubuntu Docker container; host UI reachable |
| Sysmon 15.22 / UF 10.4.0 | Real Sysmon and Windows PowerShell events indexed |
| Benign local collection | ETW decoded, PCAP completed, Windows EVTX/XML exported |
| Example short benign window | 199 packets, zero reported drops; 7,067 ETW events, zero reported lost |
| Windows exports in that window | 77 Sysmon and 9 PowerShell records |
| End-to-end marker | Exact harmless process marker indexed with process fields |
| Reboot recovery | Collection and live forwarding validated after a guest reboot |
| Evidence preservation | 100 original case-file hashes verified across preserved copies |

These figures describe a short setup check, not production capacity, malware behavior, or detection coverage. Earlier failed attempts were retained as partial cases.

## Daily operation

1. Verify the private guest adapter, address, disconnected alternate adapters and absence of default routes.
2. Refresh host forwarding if Ubuntu eth0 changed; use the explicit Linux repository path required by `Configure-HostNetworking.ps1`.
3. Start Splunk in Ubuntu using `bash scripts/start-siem.sh --stack splunk --live`.
4. Run the generic Windows collector with explicit `-Forwarding Splunk`, `-SiemAddress`, and the current private adapter's `-CaptureInterface`.
5. Match the exact marker in Splunk; preserve files and verify hashes before rollback.

## Remaining evaluation

Remcos execution/version comparison, detection false-positive/false-negative evaluation, production workload testing, and Elastic/Fleet/Defend deployment are not established by the reference benign checks. Sysmon 15.22 ran on a Windows 10 build in that deployment; record the vendor-support compatibility limitation described in the source documentation when reproducing it.
