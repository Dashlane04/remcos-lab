# Start and capture: use the ordered setup chain

The authoritative entry point is now [**Lab setup: start here**](SETUP.md). This page preserves the old link; it is no longer a second installation sequence.

| Task | Canonical step |
| --- | --- |
| Prepare Ubuntu, Docker, and resources | [1: host and WSL](setup/01-host-and-wsl.md) |
| Connect the Windows VM to native WSL Docker | [2: network and addresses](setup/02-network.md) |
| Start one SIEM phase and configure Fleet/TLS | [3: SIEM services](setup/03-siem-services.md) |
| Install/configure Windows collectors and shippers | [4: endpoint](setup/04-windows-endpoint.md) |
| Verify local capture and actual SIEM delivery | [5: benign checkpoint](setup/05-benign-validation.md) |
| Begin a verified specimen case | [6: specimen collection](setup/06-specimen-collection.md) |
| Preserve evidence, import, detect, and compare | [7: investigation](setup/07-evidence-and-detection.md) |

Ubuntu runs Bash/Python/Docker. The Windows host runs WSL inspection, port forwarding, and transfer commands. The disposable VM runs PowerShell sensors/collection. Every canonical command block identifies which machine owns it.

The inspected Ubuntu server uses its native Docker daemon, not Windows Docker Desktop. Start stacks in phases on the 16 GB host; the old default launch of both SIEMs is not the recommended path for this machine.
