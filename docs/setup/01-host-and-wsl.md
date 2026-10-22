# Step 1 — Prepare the Windows host and Ubuntu

[Setup index](../SETUP.md) | Next: [Step 2 — Network](02-network.md)

Use the [reference validation record](00-current-status-and-vm-step.md) for observed results. Inspect your own resources and running services before changing WSL settings.

## HOST / PowerShell: confirm the distro and working copy

**Run in: HOST / PowerShell.**

```powershell
wsl.exe --list --verbose
```

Use an Ubuntu WSL2 distribution. Clone the repository into `~/remcos-soc-lab`; `C:\LabSource\remcos-soc-lab` is an example Windows checkout. Preserve existing local credentials, data and certificates when updating a configured copy.

If setting up a genuinely absent Ubuntu copy, copy it from the Windows source once. Do not merge an old `.env`, data directory, or certificate tree into an already configured Linux copy. Later documentation updates should synchronize only the files changed.

## SIEM / Ubuntu Bash: verify the actual Docker engine

**Run in: SIEM / Ubuntu Bash.**

```bash
cd ~/remcos-soc-lab
python3 --version
docker context show
docker info --format '{{.OperatingSystem}}'
docker compose version
docker ps --format '{{.Names}} {{.Status}}'
```

On inspection this returned context `default` and an Ubuntu Docker server. Use that native Ubuntu engine consistently for this chain. Switching Windows Docker contexts does not automatically switch Ubuntu's native daemon or transfer its volumes. Do not install a second engine merely to follow these instructions.

If that native daemon is stopped and the distro uses systemd, start it inside Ubuntu:

**Run in: SIEM / Ubuntu Bash.**

```bash
sudo systemctl start docker
docker info
```

If the service is missing or the active server is Docker Desktop instead, stop at this checkpoint and identify the backend. The network recipe in step 2 is specifically for the existing native-engine/NAT arrangement. Do not silently combine it with Desktop or mirrored-network instructions.

## HOST: plan memory before starting containers

Observed host RAM is about 16 GiB; the current WSL limit is 4000 MB. The Compose memory limits are ceilings, not reservations or a guarantee that a stack fits. Elasticsearch also has an explicit 2 GiB Java heap, and Kibana/Fleet need additional memory.

Use this order:

1. Start with **Splunk only** for the first endpoint collection and Windows/ETW learning.
2. Stop Splunk before starting Elasticsearch/Kibana. You can compare the same preserved Windows evidence offline in Elastic while the Windows VM is powered off.
3. Add live Fleet/Elastic Defend as a separate phase when resource measurements show enough headroom. Offline replay does not reproduce EDR prevention or create endpoint events.

If increasing WSL's cap, edit `%USERPROFILE%\.wslconfig` on the Windows host while preserving its unrelated settings. For a Splunk-first pilot, 6 GB is a planning starting point; an Elastic phase may need 8 GB or more depending on actual use. With a 16 GB host, concurrent Windows VM and Elastic must be measured carefully. These are planning estimates, not vendor minimums.

After saving work and stopping your containers, applying a `.wslconfig` change requires restarting WSL. This also stops Ubuntu's native Docker daemon:

**Run in: HOST / PowerShell, only after preserving work.**

```powershell
wsl.exe --shutdown
```

Reopen Ubuntu, start Docker as needed, and re-check its address in step 2; WSL NAT addresses can change. No host memory settings were changed by preparing this guide.

## SIEM / Ubuntu Bash: initialize settings without PowerShell

**Run in: SIEM / Ubuntu Bash.**

```bash
cd ~/remcos-soc-lab
bash scripts/start-siem.sh --stack splunk --check-only
chmod 600 infra/.env
```

This initializes missing secrets and validates Compose without starting containers. It preserves an existing `.env`. Do not run `Initialize-Lab.ps1` here and do not paste the settings file into chat or a report.

**Checkpoint:** Ubuntu's lab path and Docker backend are known, resources are planned, and configuration-only validation succeeds. Continue to [step 2](02-network.md).
