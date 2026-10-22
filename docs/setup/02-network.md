# Step 2 — Connect the Windows VM to native Docker in WSL

Previous: [Step 1](01-host-and-wsl.md) | [Setup index](../SETUP.md) | Next: [Step 3](03-siem-services.md)

For this machine's applied host/guest configuration and validated operating commands, see [current status and daily operation](00-current-status-and-vm-step.md). The refresh script replaces the manual host-forwarding block below for repeat use.

This is the network plan for the inspected **native Ubuntu Docker Engine under WSL NAT**. It is not the Docker Desktop or mirrored-mode recipe.

## Address roles

| Name | Meaning | Lab example / inspected value |
| --- | --- | --- |
| Host-only Windows address | Address the disposable VM uses for collectors; TLS certificates name this address | Existing VMware VMnet1 adapter: `10.10.10.1` |
| Analysis VM address | Disposable endpoint on that host-only network | Proposed `10.10.10.20`; configure/verify it, do not assume it already exists |
| Ubuntu eth0 address | Where native Docker publishes its data ports | Inspected `172.19.102.172`; discover it each time, not a permanent value |

The inspected VMnet8 address `192.168.102.1` belongs to the NAT-side adapter; this chain uses the host-only VMnet1 network instead. Your transfer helper's old VM IP may therefore need updating after you change the VM adapter/address.

```text
Windows VM 10.10.10.20
    -> Windows host-only address 10.10.10.1:9997 / :8220 / :9200
    -> Windows TCP portproxy, scoped firewall rule
    -> Ubuntu eth0 CURRENT_WSL_IP:same-port
    -> native Docker published port -> selected SIEM container
```

## VM: prepare the private adapter

Use the hypervisor's host-only network corresponding to VMnet1, choose an unused address in its actual subnet, and leave the analysis VM without an Internet gateway during specimen work. Verify the VMnet1 subnet mask and DHCP range rather than guessing them. Disconnect any second NAT/bridged adapter during collection. Do preparation downloads separately, then take a clean collection snapshot.

Do not enable Windows Internet Connection Sharing or route specimen traffic through WSL. The host-only network still reaches the host: restrict allowed host services deliberately and verify that the VM cannot reach unrelated host services or the Internet. The launcher does not enforce those boundaries.

## SIEM / Ubuntu Bash: discover the bind address and edit `.env`

**Run in: SIEM / Ubuntu Bash.**

```bash
ip -4 -o addr show dev eth0
cd ~/remcos-soc-lab
nano infra/.env
```

Edit only the applicable non-secret values; preserve passwords and existing tokens:

**File: SIEM `infra/.env` — example values, replace the WSL address with the current eth0 address.**

```dotenv
LAB_SERVER_IP=10.10.10.1
DATA_BIND_IP=172.19.102.172
```

`LAB_SERVER_IP` is the address advertised to the Windows endpoint and included in certificate SANs. `DATA_BIND_IP` belongs to Ubuntu, which owns the native Docker daemon. **They differ in this topology.** Do not use the Docker bridge address (for example `172.17.0.1`), wildcard `0.0.0.0`, or the Windows host address as the Ubuntu bind address.

Set the advertised TLS address before first Elastic startup. If certificates already exist for a different advertised address, editing `.env` does not regenerate them. Preserve existing evidence and plan certificate replacement/re-enrollment; do not delete volumes to make a setup error disappear.

## HOST / Administrator PowerShell: create the TCP forwarding

The example below configures only the three named TCP listeners on the host-only address. It does not expose the UIs, Docker API, or Splunk management port.

**Run in: HOST / Administrator PowerShell.**

```powershell
$labHostIp = '10.10.10.1'
$analysisVmIp = '10.10.10.20'
$labWslIp = ((wsl.exe -d Ubuntu -- ip -4 -o addr show dev eth0) -split '\s+')[3].Split('/')[0]
[void][Net.IPAddress]::Parse($labWslIp)
Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $labHostIp
```

Verify the printed adapter is the intended host-only interface and that both selected addresses are correct before continuing. Then:

**Run in: HOST / Administrator PowerShell.**

```powershell
Start-Service iphlpsvc
foreach ($port in @(9997,8220,9200)) {
    & netsh.exe interface portproxy add v4tov4 "listenaddress=$labHostIp" "listenport=$port" "connectaddress=$labWslIp" "connectport=$port"
    if ($LASTEXITCODE -ne 0) { throw "Port forwarding failed for $port" }
    $ruleName = "RemcosLab-WSL-$port"
    if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $labHostIp -LocalPort $port -RemoteAddress $analysisVmIp -Profile Any
    } else {
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $labHostIp -LocalPort $port -RemoteAddress $analysisVmIp -Profile Any
    }
}
netsh.exe interface portproxy show v4tov4
```

This block is the manual reference. The later automatic configuration session applied equivalent collector forwards plus explicit blocks for other TCP/UDP ports from the selected VM to the host-only IPv4 address; see the current-status page. These rules do not audit or protect every other host address or protocol.

After a WSL restart, re-discover eth0, update only `DATA_BIND_IP` if it changed, refresh these portproxy targets, and recreate the selected services through the launcher. Keep `LAB_SERVER_IP` stable so the endpoint URL/certificate identity remains stable.

## VM: verify reachability after the chosen services start

The forwarding rules can be prepared now. Verify the selected backend in step 3 independently of the Windows portproxy listener.

Port 19200 is a separate Ubuntu-loopback-only Elasticsearch analyst endpoint for Python imports. It is not part of the Windows portproxy list. UIs stay on Ubuntu loopback ports 8000/5601.

**Run in: VM / PowerShell after step 3.**

```powershell
Test-NetConnection 10.10.10.1 -Port 9997
Test-NetConnection 10.10.10.1 -Port 8220
Test-NetConnection 10.10.10.1 -Port 9200
```

For the Splunk phase verify 9997; for the Elastic/Fleet phase verify 8220/9200. Windows portproxy listeners can accept TCP handshakes even when their backends are stopped. A successful `Test-NetConnection` therefore establishes only TCP reachability to the forwarder, not backend health, TLS/enrollment, or ingestion. Verify container/application health and the indexed benign marker separately.

Keep browser UI access separate: localhost inside the analysis VM means that VM, not your host. Try the host's localhost access only after startup; if WSL localhost forwarding is unavailable, use an SSH tunnel to Ubuntu for the UI, with TLS checked against `localhost`. Do not expose 8000/5601 to the malware network just to fix browser access.

**Checkpoint:** addresses, private network, memory plan, forwarding, and certificate identity are recorded. Proceed to [step 3](03-siem-services.md); return here to run the relevant port tests.

Sources: [WSL NAT networking](https://learn.microsoft.com/en-us/windows/wsl/networking), [Windows portproxy](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy), [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/).
