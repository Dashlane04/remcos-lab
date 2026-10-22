# Setup guide

Use the [repository README](../README.md) for the architecture, reference addresses, startup, capture, and verification commands. This ordered chain provides the detailed installation and analysis steps.

| Step | Guide | Runs on |
| --- | --- | --- |
| 1 | [Host and Ubuntu preparation](setup/01-host-and-wsl.md) | HOST + SIEM |
| 2 | [Private network and forwarding](setup/02-network.md) | HOST + SIEM + VM |
| 3 | [SIEM services](setup/03-siem-services.md) | SIEM + host browser |
| 4 | [Windows sensors and shippers](setup/04-windows-endpoint.md) | VM |
| 5 | [Benign validation](setup/05-benign-validation.md) | VM + Splunk |
| 6 | [Specimen collection](setup/06-specimen-collection.md) | VM |
| 7 | [Preservation and detection evaluation](setup/07-evidence-and-detection.md) | HOST + SIEM |

## Conventions

- HOST: Windows PowerShell from the Windows checkout. `C:\LabSource\remcos-soc-lab` is an example checkout path; adapt it.
- SIEM: Ubuntu Bash at `~/remcos-soc-lab`, using native Ubuntu Docker.
- VM: Administrator Windows PowerShell 5.1 at `C:\Lab\remcos-soc-lab`.
- Reference host-only network: host `10.10.10.1/24`, guest `10.10.10.20/24`; discover Ubuntu eth0 instead of copying an old address.
- `/home/analyst` is an example Linux home. Use your own Ubuntu username and path.
- Start one SIEM stack at a time on a constrained host. No Windows collection script runs in Ubuntu.

[Validation status](setup/00-current-status-and-vm-step.md) · [Comparison protocol](08-comparative-traffic-telemetry-protocol.md) · [Sources](SOURCES.md)
