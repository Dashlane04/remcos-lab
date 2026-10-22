# Background activity and controlled traffic

Optional workload reference. Follow [the canonical setup chain](SETUP.md) and [the benign checkpoint](setup/05-benign-validation.md) first. Server commands here run in Ubuntu Bash; workload/capture commands run inside the disposable Windows VM.

Start with three separately recorded benign sessions, then hold one additional session back for validation. These are learning-lab targets, not a claim of production realism or a fixed event-count benchmark.

| Session | Activity | Evidence to preserve |
| --- | --- | --- |
| BASE-001 | Open/close normal applications, edit text, copy small files, run the benign helper | UTC window, Sysmon export, expected process tree |
| BASE-002 | Browse and download a harmless file from a controlled private lab HTTP server | Host logs, HTTP access log, optional packet capture |
| BASE-003 | Use a legitimate installer/updater in a clean VM during preparation, if available | Provenance, startup changes, benign alerts, actual collection policy |
| HOLDOUT-001 | A new combination of normal actions after rules are frozen | Separate export, unused until validation |

An installer that creates a Run value is a useful benign challenge for R1. Do not create real malware-like persistence to force the helper to match. Use the synthetic fixture for mechanical query tests and original recorded specimen evidence for malware validation.

## Generate actual private-lab HTTP activity

On Ubuntu, bind Python's server to its current eth0 address and serve only the harmless fixture directory. **Run in: SIEM / Ubuntu Bash.**

```bash
cd ~/remcos-soc-lab
WSL_BIND_IP=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
python3 -m http.server 8080 --bind "$WSL_BIND_IP" --directory fixtures
```

In the native-WSL/NAT arrangement, the endpoint uses a Windows-host forwarded address, not the Ubuntu bind address. The core setup forwards only 9997/8220/9200. Add 8080 only for this optional benign session, using the same current WSL address and endpoint source restriction as [setup step 2](setup/02-network.md). Keep the server visible so you can stop it with Ctrl+C. Do not serve your home directory, sample storage, credentials, or raw case evidence.

**Run in: HOST / Administrator PowerShell, after reviewing the addresses.**

```powershell
$labHostIp = '10.10.10.1'
$analysisVmIp = '10.10.10.20'
$labWslIp = ((wsl.exe -d Ubuntu -- ip -4 -o addr show dev eth0) -split '\s+')[3].Split('/')[0]
netsh.exe interface portproxy add v4tov4 "listenaddress=$labHostIp" listenport=8080 "connectaddress=$labWslIp" connectport=8080
New-NetFirewallRule -Name 'RemcosLab-WSL-HTTP' -DisplayName 'RemcosLab-WSL-HTTP' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $labHostIp -LocalPort 8080 -RemoteAddress $analysisVmIp -Profile Any
if (Get-NetFirewallRule -Name 'RemcosLab-Block-Other-Host-TCP' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'RemcosLab-Block-Other-Host-TCP' -LocalPort @('1-8079','8081-8219','8221-9199','9201-9996','9998-65535')
}
```

If that named rule already exists, inspect/update it rather than creating ambiguous duplicates. The scoped TCP block installed by the automatic host setup takes precedence over allows; the last lines temporarily exclude only 8080 from that block. Running the normal host refresh script restores the default block, so repeat this optional preparation only for the controlled HTTP case. Start a separate collection case declared N1 for this controlled service. **Run in: VM / PowerShell**, during that case's ready window:

```powershell
Set-Location C:\Lab\remcos-soc-lab
./scripts/Invoke-BenignWorkload.ps1 -DurationSeconds 120 -OutputDirectory "$env:LOCALAPPDATA\RemcosLab\BASE-HTTP-01" -LocalHttpUrl http://10.10.10.1:8080/README.md
```

The helper accepts only explicit private/loopback IPv4 HTTP URLs and does not follow redirects. It records the URL in its session manifest. This produces genuine benign process/network telemetry; the events are not fabricated. A repeated two-minute local transfer still does not represent enterprise browsing, external TLS, user diversity, or production throughput.

Preserve the server access log when needed, export the corresponding Windows interval, and label the capture `benign-background`. If collecting packets, use your lab packet-capture tool and record its interface/filter/time window. A PCAP alone does not supply registry or process evidence.

After preserving the optional session, stop the visible Python server in Ubuntu. Remove only this optional owned forwarding/rule. **Run in: HOST / Administrator PowerShell.**

```powershell
netsh.exe interface portproxy delete v4tov4 listenaddress=10.10.10.1 listenport=8080
Remove-NetFirewallRule -Name 'RemcosLab-WSL-HTTP'
if (Get-NetFirewallRule -Name 'RemcosLab-Block-Other-Host-TCP' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'RemcosLab-Block-Other-Host-TCP' -LocalPort @('1-8219','8221-9199','9201-9996','9998-65535')
}
```

## Keep two measurements separate

- **Detection usefulness:** observed malicious scenarios, benign alerts, missed behavior, analyst explanation, and held-back cases.
- **Capacity:** event rate, ingest bytes, lag, search runtime, dropped events, and resource use at a stated load.

The included helper exercises collection; it is not a load-testing tool. Replaying many duplicates is a capacity experiment only, with duplicates labeled and excluded from detection-coverage claims. Never describe a lab rate as production-tested capacity without the corresponding workload and measurements.
