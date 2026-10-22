# Topology reference: WSL2 SIEM and disposable Windows endpoint

Start with the [ordered setup index](SETUP.md). This page is a reference, not a competing installation sequence.

| Role | Selected environment |
| --- | --- |
| Host | Everyday Windows; browser, host-only forwarding, file transfer |
| SIEM | Ubuntu WSL2 with its existing native Docker Engine; Bash/Python commands |
| Endpoint | Disposable Windows VM; Sysmon, shippers, ETW, packet capture |

The inspected host has about 16 GiB RAM and a 4000 MB WSL cap. Use [step 1's resource plan](setup/01-host-and-wsl.md) and start one SIEM phase at a time. Compose memory ceilings are not vendor minimums or guaranteed consumption.

For the current native-WSL/NAT design, `LAB_SERVER_IP` is the host-only address advertised to the Windows VM, while `DATA_BIND_IP` is Ubuntu's eth0 address. The private values may differ. [Step 2](setup/02-network.md) defines the selected network, forwarding, TLS identity, and restart handling.

Sysmon/PowerShell logs go through Windows shippers. Elastic Defend is a separate endpoint component. ETW and PCAP remain separate evidence artifacts until explicitly decoded/imported. A shared event stored in two SIEMs is a cross-platform comparison, not two independent observations.

UIs stay loopback-only at 8000/5601; Ubuntu's Elastic analyst API uses loopback 19200. Endpoint-facing services use the three explicitly forwarded private ports. This guide does not use Docker Desktop networking or change host firewall/egress policy automatically.

Actual image, integration, Windows, Sysmon, and license versions must be recorded when deployed. The existing version pins have not been pulled or runtime-validated here. See [sources](SOURCES.md) and the [comparison protocol](08-comparative-traffic-telemetry-protocol.md).
