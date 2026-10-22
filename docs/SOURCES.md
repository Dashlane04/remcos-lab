# Sources and setup references

Checked 22 October 2026. Technical setup is based on primary documentation; interfaces and licensing can change. Record what you actually deploy. The source links do not imply that this starter was endorsed by HTB, Microsoft, Elastic, or Splunk.

## CDSA-aligned learning

- [HTB CDSA introduction: Elastic/Splunk SIEM operations](https://www.hackthebox.com/blog/defensive-security-analyst-certification)
- [HTB Security Monitoring & SIEM Fundamentals](https://academy.hackthebox.com/course/preview/security-monitoring--siem-fundamentals)
- [HTB Windows Event Logs & Finding Evil: Sysmon and ETW](https://academy.hackthebox.com/course/preview/windows-event-logs--finding-evil)

The lab practices these tool families; it is not a replica of the CDSA exam environment and does not include exam content.

## Splunk

- [Official Docker setup](https://splunk.github.io/docker-splunk/SETUP.html)
- [Official Docker repository and terms requirements](https://github.com/splunk/docker-splunk)
- [Container releases](https://github.com/splunk/docker-splunk/releases)
- [Windows Event Log collection](https://docs.splunk.com/Documentation/Splunk/latest/Data/MonitorWindowseventlogdata)
- [inputs.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.5-configuration-file-reference/inputs.conf)

Use Splunk's official download/install documentation for the selected Windows Universal Forwarder release; it is installed inside the endpoint VM. Inspect the actual license before enabling scheduled alerts or increasing ingestion.

## Elastic

- [TLS Docker Compose reference](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-compose)
- [Fleet Server container deployment](https://www.elastic.co/docs/reference/fleet/elastic-agent-container)
- [Elastic Agent environment options](https://www.elastic.co/docs/reference/fleet/agent-environment-variables)
- [Fleet TLS configuration](https://www.elastic.co/docs/reference/fleet/secure-connections)
- [Elastic Agent installation](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html)
- [Elastic Defend installation, capabilities, and licensing](https://www.elastic.co/docs/reference/integrations/endpoint)

## Windows telemetry

- [Sysmon installation, schema, filtering, and event meanings](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [ETW provider discovery and traces](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-tracing-for-windows-simplified)
- [logman trace options](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-create-trace)
- [tracerpt ETL decoding](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracerpt)

## Remcos research

- [Elastic 4.9.3 Pro, part one: configuration, persistence, injection](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-one)
- [Elastic, part two: watchdog and communication](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-two)
- [Elastic, part three: fields and command handling](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-three)
- [Elastic, part four: detections and hunting](https://security-labs.elastic.co/security-labs/dissecting-remcos-rat-part-four)
- [Elastic's existing configuration extractor](https://github.com/elastic/labs-releases/tree/main/extractors/remcos)
- [Fortinet 7.0.4 Pro campaign, 14 January 2026](https://www.fortinet.com/blog/threat-research/new-remcos-campaign-distributed-through-fake-shipping-document)

Keep the campaign loader separate from the native Remcos payload when attributing behavior. The two versions do not establish an architectural rewrite by themselves. A requested archive's reference hash is not local payload verification; complete the acquisition manifest only after the relevant checks.

The [sample provenance guide](10-sample-provenance.md) records exact source hashes, acquisition limitations, the separate Triage fallback, and local verification steps. The [reference register](../templates/sample-reference-register.csv) lists intended specimens; it does not imply acquisition or verification.

## Acquisition and collection runbook references

- [MalwareBazaar official API: authentication, exact-hash lookups, encrypted ZIP downloads](https://bazaar.abuse.ch/api/)
- [abuse.ch authentication portal](https://auth.abuse.ch/)
- [Wireshark dumpcap: interfaces, bounded capture, PCAPNG output](https://www.wireshark.org/docs/man-pages/dumpcap.html)
- [PowerShell logging and separate PowerShellCore event provider](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Windows wevtutil channel settings and EVTX exports](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [Elasticsearch search API and total-hit reporting](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search)

See [sample acquisition](11-sample-acquisition.md) and the [telemetry runbook](12-telemetry-collection-runbook.md) for this project's exact file paths and commands.

## Startup and capture automation

- [Docker Compose service startup](https://docs.docker.com/reference/cli/docker/compose/up/)
- [Start-Process argument quoting and window options](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-5.1)

The [launcher guide](13-start-and-capture.md) separates SIEM container health, local Windows collection readiness, and actual SIEM ingestion. Its simulated tests do not replace a benign pilot on the installed VM.

## Canonical WSL2 setup chain

Start at [docs/SETUP.md](SETUP.md). The inspected Ubuntu instance uses a native Docker daemon, while the Windows CLI has a separate Desktop context. The selected NAT/portproxy recipe must not be mixed with Desktop or mirrored-mode networking assumptions.

- [Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking)
- [Windows portproxy reference](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy)
- [Docker Desktop backend architecture, for distinguishing it from the native Ubuntu engine](https://docs.docker.com/desktop/features/networking/)
- [Docker published-address behavior](https://docs.docker.com/engine/network/port-publishing/)
- [Elastic Docker prerequisites and kernel mapping count](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod)

`LAB_SERVER_IP` names the endpoint-facing TLS address, while `DATA_BIND_IP` is an address on the actual Docker host. The new loopback analyst port 19200 keeps Ubuntu imports separate from endpoint-facing port 9200. No host networking/memory settings are changed by this documentation update.
# Applied-machine configuration references

- [Microsoft: WSL global settings, memory, swap, reclaim and restart behavior](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).
- [Splunk Docker security policy: home ownership enforcement and Docker-created volumes](https://github.com/splunk/docker-splunk/security/policy). This lab disables the recursive ownership pass because its app is read-only; it relies on Docker's image-initialized named-volume ownership and checks service startup.

- [Splunk UF Windows installation flags](https://help.splunk.com/en/data-management/forward-data/universal-forwarder-manual/10.4/install-the-universal-forwarder/install-a-windows-universal-forwarder).
- [Microsoft-maintained winget manifest for the official UF 10.4.0 installer URL/hash](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/s/Splunk/UniversalForwarder/10.4.0/Splunk.UniversalForwarder.installer.yaml).
- [Splunk event-log checkpoint and current_only semantics](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/inputs.conf).
- [Splunk ingestion throughput limits](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/limits.conf).
