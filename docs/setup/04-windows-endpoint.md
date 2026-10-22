# Step 4 — Prepare the disposable Windows endpoint

Previous: [Step 3](03-siem-services.md) | [Setup index](../SETUP.md) | Next: [Step 5](05-benign-validation.md)

All installation, policy, Sysmon, ETW, and shipper commands here run in the **disposable Windows VM**. The two explicitly labeled transfer blocks run on the **Windows host**. Ubuntu only serves data/configuration through its existing setup.

## HOST: transfer public lab files

Enable OpenSSH in the disposable guest during preparation and verify its SSH host key through the VM console. Run from the Windows repository root; create the destination before copying.

**HOST / PowerShell:**

```powershell
$vmUser = Read-Host 'VM SSH user'
ssh.exe -o StrictHostKeyChecking=yes "${vmUser}@10.10.10.20" 'powershell.exe -NoProfile -Command "New-Item -ItemType Directory -Path C:\Lab\remcos-soc-lab -Force | Out-Null"'
scp.exe -o StrictHostKeyChecking=yes -r .\scripts .\configs .\fixtures "${vmUser}@10.10.10.20:C:/Lab/remcos-soc-lab/"
```

Transfer only public configuration/scripts. Do not transfer `infra/.env`, private CA keys, service tokens or acquisition credentials. For the optional Elastic phase, export and copy only the public `ca.crt` to `C:\Lab\remcos-lab-ca.crt` in the VM; see [SIEM setup](03-siem-services.md).

## VM: Sysmon, PowerShell, ETW, and packets

Download vendor tools during the preparation phase, verify the Sysmon signature, and place it under `C:\Lab\Tools`. Apply the supplied policy in an elevated VM terminal:

**Run in: VM / Administrator PowerShell.**

```powershell
Set-Location C:\Lab\remcos-soc-lab
Get-AuthenticodeSignature C:\Lab\Tools\Sysmon64.exe
C:\Lab\Tools\Sysmon64.exe -s
C:\Lab\Tools\Sysmon64.exe -accepteula -i C:\Lab\remcos-soc-lab\configs\sysmon\sysmon-lab.xml
```

For an existing Sysmon installation, use `-c` with the policy instead of installing it twice. Display the active configuration and hash the intended file:

**Run in: VM / Administrator PowerShell.**

```powershell
C:\Lab\Tools\Sysmon64.exe -c
Get-FileHash configs/sysmon/sysmon-lab.xml -Algorithm SHA256
```

Record schema compatibility against the actual binary. The profile includes process start/stop, connections, DNS, registry changes, selected file paths, remote threads, and process tampering where generated. Broad ImageLoad/ProcessAccess are disabled. A disabled/no-event source is not evidence a technique never occurred.

In the VM's Group Policy editor enable Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging. Start a new **Windows PowerShell 5.1** session and later verify 4104 in `Microsoft-Windows-PowerShell/Operational`. PowerShell 7 uses another provider/channel and is not automatically covered by these inputs.

For campaign context, enable TaskScheduler Operational if needed. Enable Audit Process Creation and its separate command-line policy for Security 4688; enable the appropriate Other Object Access Events auditing for 4698/4702. Record effective policies; the exporter never enables them. Keep Defender/Elastic protection policies recorded and unchanged by the collection scripts.

**Run in: VM / Administrator PowerShell.**

```powershell
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
logman query providers Microsoft-Windows-Kernel-Process
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
```

Install Wireshark/Npcap in the VM beforehand. Choose the actual private-network interface number from dumpcap's output and retain it in the case notes. Do not assume interface 1 without checking.

## VM: Splunk Universal Forwarder — Splunk phase

Install a supported Windows Universal Forwarder from Splunk, then create its lab app directory and copy the inputs/output template:

**Run in: VM / Administrator PowerShell.**

```powershell
$forwarderLocal = 'C:\Program Files\SplunkUniversalForwarder\etc\apps\remcos_lab\local'
New-Item -ItemType Directory -Path $forwarderLocal -Force | Out-Null
Copy-Item C:\Lab\remcos-soc-lab\configs\splunk\forwarder\inputs.conf "$forwarderLocal\inputs.conf"
Copy-Item C:\Lab\remcos-soc-lab\configs\splunk\forwarder\limits.conf "$forwarderLocal\limits.conf"
Copy-Item C:\Lab\remcos-soc-lab\configs\splunk\forwarder\outputs.conf.example "$forwarderLocal\outputs.conf"
notepad "$forwarderLocal\outputs.conf"
```

Set the receiver to **`10.10.10.1:9997`**, not Ubuntu's changing eth0 address. The template uses plain Splunk TCP only inside this private lab path. Broader/shared networks require a separately configured TLS receiver. Sysmon and Windows PowerShell inputs are enabled; Security is disabled and TaskScheduler/Defender/System are not all live inputs. Enhanced exports preserve those available channels separately.

**Run in: VM / Administrator PowerShell.**

```powershell
Restart-Service SplunkForwarder
Test-NetConnection 10.10.10.1 -Port 9997
```

The current template uses `start_from=oldest` and `current_only=0`: it resumes from checkpoints, catches up on unprocessed retained events after downtime, then follows new events. Old/new specimen cases still require explicit host/time/marker scoping. The lab-only limits file removes the default 256 KB/s UF ingestion throttle for burst catch-up; measure lag and resources rather than assuming real-time arrival. Complete the Splunk benign checkpoint in step 5.

## Browser + VM: Elastic Agent and Defend — Elastic phase

In the HOST browser's Fleet UI, create an endpoint policy `remcos-windows-lab`, separate from the Fleet Server policy. Add Elastic Defend and the Windows integration's Sysmon/Windows PowerShell inputs. Verify the chosen policy/license and preserve default protection behavior. Do not duplicate one channel through two integrations.

Use Fleet's Add agent wizard to obtain the supported Windows install command and endpoint enrollment token. Run that command in the VM's elevated terminal using the configured URL `https://10.10.10.1:8220` and `--certificate-authorities=C:\Lab\remcos-lab-ca.crt`. The actual command/token comes from your instance; no reusable token is supplied in this repository. Configure output CA trust separately in Fleet as step 3 describes. Do not bypass TLS checks.

Verify both the agent and endpoint security component are healthy, and that the expected Windows and endpoint datasets actually arrive. Agent service status alone is not EDR health. Complete step 5 with `-Forwarding Elastic`, which does not require the stopped Splunk receiver.

**Checkpoint:** the chosen phase's shipper, local logging policies, Sysmon configuration, ETW provider, packet interface, and TLS settings are known. Take a clean collection snapshot once the benign checkpoint is proven. Continue to [step 5](05-benign-validation.md).
