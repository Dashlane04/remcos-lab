# Step 3 — Start and configure the SIEM services

Previous: [Step 2](02-network.md) | [Setup index](../SETUP.md) | Next: [Step 4](04-windows-endpoint.md)

All server commands on this page run in **Ubuntu Bash**, from `~/remcos-soc-lab`. Browser actions are performed on the Windows host. PowerShell remains on the host/endpoint pages, not in Ubuntu.

## A. Splunk-first phase

**Run in: SIEM / Ubuntu Bash.**

```bash
cd ~/remcos-soc-lab
bash scripts/start-siem.sh --stack splunk --live --check-only
bash scripts/start-siem.sh --stack splunk --live
```

The launcher creates/starts Splunk, checks its UI and receiver health, and preserves its volume. Initial image pulls need server Internet access and may take time. Starting the image accepts the license/general terms configured in Compose; review the vendor terms first.

Open `http://localhost:8000` in the **HOST browser** if localhost forwarding works. Log in as `admin`, using the private password in Ubuntu's `infra/.env`. Read it locally when needed; do not post it. The bundled app creates index `remcos_lab`, TCP receiver 9997, JSON ingestion, limited Sysmon XML field extractions, and the `remcos_sysmon` macro. It is not Splunk Enterprise Security or a complete CIM implementation.

Check the fixture path once:

**Run in: SIEM / Ubuntu Bash.**

```bash
python3 scripts/normalize_events.py fixtures/synthetic-sysmon.xml --output data/import/synthetic-smoke.ndjson --case-id SYN-001 --evidence-type synthetic --split development
```

Use a fresh output filename/case only for an actual new test; do not repeatedly copy one fixture and count duplicates as new evidence. The converter refuses an existing output. In the **Remcos Lab app**, select All time for the fixed-date fixture:

**Run in: HOST browser / Splunk search.**

```spl
index=remcos_lab sourcetype="remcos:json" labels.case_id="SYN-001"
| stats count by 'labels.evidence_type' 'event.dataset' 'event.code'
```

Expected total: four synthetic records. This establishes a fixture ingestion/parser path, not live malware detection. Return to step 2 to test TCP 9997 from the endpoint, then complete the Splunk portion of step 4 and step 5.

## B. Elastic/Fleet phase — stop Splunk first on this host

Collect/preserve your Splunk pilot before changing phases. Stop its container without removing its volume:

**Run in: SIEM / Ubuntu Bash.**

```bash
bash scripts/start-siem.sh --stack splunk --stop
sysctl vm.max_map_count
```

Check the selected Elastic release's [Docker production prerequisites](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod). Apply the documented mapping-count value in Ubuntu only if needed; this is a WSL kernel setting, not a Windows VM setting. The current documentation specifies `1048576`:

**Run in: SIEM / Ubuntu Bash, if the documented prerequisite is unmet.**

```bash
sudo sysctl -w vm.max_map_count=1048576
```

Revisit the step 1 memory plan. Do not treat the previously observed 4 GB WSL cap as sufficient for Elasticsearch, Kibana, Fleet, and a live endpoint. For an offline Elastic phase the Windows VM can be shut down after evidence preservation.

Start Elasticsearch/Kibana with Fleet deliberately disabled until its policy/token exist:

**Run in: SIEM / Ubuntu Bash.**

```bash
bash scripts/start-siem.sh --stack elastic --fleet off --live
docker compose --env-file infra/.env -f infra/docker-compose.yml cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt infra/certs/ca.crt
```

The setup service creates the CA and certificates and configures the Kibana service password. It uses `LAB_SERVER_IP` for the external IP SAN. An existing certificate is reused; changing an address does not reissue it. The copied `ca.crt` is public; keep private CA keys inside their local private volume.

Open `https://localhost:5601` in the **HOST browser**. Trust the public lab CA in the analyst browser as appropriate; use `elastic` and its locally stored password. Retain localhost for this UI certificate name. For browser forwarding problems use the network troubleshooting in step 2 rather than disabling TLS.

### Browser: prepare Fleet before starting its container

1. In Kibana, open Management -> Fleet. Allow the SIEM to fetch the required integration packages.
2. Create a Fleet Server policy and record its ID.
3. Generate a **Fleet Server service token**, not an endpoint enrollment token.
4. In Fleet settings, use `https://10.10.10.1:8220` as the endpoint-facing Fleet host, replacing the address only if your recorded plan differs.
5. Set the Elasticsearch output to `https://10.10.10.1:9200` and configure its CA trust. `es01` is a container DNS name; the Windows endpoint cannot use it as its output host.
6. In the output's advanced YAML, provide the **public** CA PEM under `ssl.certificate_authorities`, using the supported output syntax. The endpoint enrollment CA and output CA configuration are separate requirements.

**Edit in: HOST browser / Fleet Elasticsearch output advanced YAML.** Replace the placeholder with the complete public certificate, retaining indentation:

```yaml
ssl.certificate_authorities:
  - |
    -----BEGIN CERTIFICATE-----
    REPLACE_WITH_COMPLETE_PUBLIC_CA_CERTIFICATE_BODY
    -----END CERTIFICATE-----
```

Use the actual `infra/certs/ca.crt` exported above; do not paste a CA private key or leave the placeholder in the saved output.

Save the policy ID and service token in Ubuntu's local `.env`:

**Run in: SIEM / Ubuntu Bash.**

```bash
nano infra/.env
```

Set `FLEET_SERVER_POLICY_ID` and `FLEET_SERVER_SERVICE_TOKEN`, preserving unrelated settings. Then:

**Run in: SIEM / Ubuntu Bash.**

```bash
bash scripts/start-siem.sh --stack elastic --fleet on --live
```

Verify Fleet Server becomes Healthy in Kibana. Return to step 2 and check 8220/9200 from the Windows VM, then perform the Elastic portion of step 4. Browser login or a healthy container does not prove endpoint data delivery.

### Optional offline fixture import — no Windows PowerShell needed

**Run in: SIEM / Ubuntu Bash.**

```bash
python3 scripts/normalize_events.py fixtures/synthetic-sysmon.xml --output data/normalized/elastic-smoke.ndjson --case-id SYN-EL-001 --evidence-type synthetic --split development
python3 scripts/import_elastic.py data/normalized/elastic-smoke.ndjson --url https://localhost:19200 --ca infra/certs/ca.crt --username elastic --index remcos-lab-events
```

The importer prompts for the password and checks TLS. Create a Discover data view `remcos-lab-*` using `@timestamp`, select the fixture's original time range, and filter `labels.case_id : "SYN-EL-001"`. Four fixture records are a smoke check, not EDR validation.

Ubuntu uses the added loopback-only analyst port **19200**. The remote Windows endpoint still uses port **9200** through the host-only forwarding path. This avoids relying on a changing WSL IP in a TLS certificate or incorrectly assuming an eth0-only published port is also listening on Ubuntu localhost.

## Browser access fallback

If the host can reach Ubuntu's private eth0 address but WSL's localhost forwarding is unavailable, use an SSH tunnel to an already configured Ubuntu SSH service. This is an optional connectivity remedy, not an instruction to install/expose SSH automatically.

**Run in: HOST / PowerShell, with your current WSL address.**

```powershell
ssh.exe -N -L 8000:127.0.0.1:8000 -L 5601:127.0.0.1:5601 analyst@172.19.102.172
```

Use the actual Ubuntu user/address, an unused local port if necessary, and verified SSH host keys. Only the active SIEM's UI needs to be reachable. Do not point the browser at the untrusted analysis endpoint.

**Checkpoint:** chosen SIEM's health, login, relevant endpoint-facing port, and fixture ingestion work. For live Elastic, Fleet policy/output/CA are configured. Continue to [step 4](04-windows-endpoint.md).
