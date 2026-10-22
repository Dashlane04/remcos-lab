# Step 6 — Register and collect specimen cases

Previous: [Step 5](05-benign-validation.md) | [Setup index](../SETUP.md) | Next: [Step 7](07-evidence-and-detection.md)

Use the collection/protection profile that passed step 5. Complete the comparison within a consistent phase; do not compare an old specimen under Splunk-only policy with a newer one under different EDR policy and attribute every difference to version.

## HOST: transfer the already downloaded old archive

The old target is **4.9.3 Pro** and the newer target is **7.0.4 Pro**. Obtain the intended encrypted archive separately; repository availability and exact specimen selection require independent verification. No sample is included here.

**Run in: HOST / PowerShell.**

```powershell
scp.exe -o StrictHostKeyChecking=yes 'C:\LabSource\Incoming\0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5.zip' 'VM_USER@10.10.10.20:C:/Lab/Incoming/Remcos-4.9.3-Pro/'
```

Replace `VM_USER` with the guest account and create the destination directory first. Use the verified VM host key established in step 4. SCP preserves the encrypted archive; it does not extract or execute the upload.

## VM: verify provenance before execution

Inside the disposable VM, use an AES-compatible archive tool to extract the old ZIP with its repository password `infected` into a separate specimen directory. Compare the contained EXE's SHA-256 with the expected hash below; record native PE structure, architecture, embedded version evidence, source, and disk versus reconstructed-memory representation. An archive member's name or declared size does not prove its contents. See [specimen provenance](../10-sample-provenance.md).

Record any Defender/EDR prevention during preparation. Extraction or hashing can trigger a detection before the main collector starts; preserve those earlier Windows/EDR records separately instead of claiming the later ETW window covers them. Do not change protections to force later stages to run.

For 7.0.4, the Fortinet campaign hash is not confirmed available on MalwareBazaar and the user could not find it there. The documented Triage alternative is a separate specimen; obtain access, verify its actual bytes/version, and record that selection. Do not relabel it as Fortinet's shipping-document campaign payload. The [acquisition reference](../11-sample-acquisition.md) is optional; re-downloading the already present old ZIP is unnecessary.

## SIEM: start the selected phase only

**Run in: SIEM / Ubuntu Bash, after checking whether the WSL bind address changed.**

```bash
cd ~/remcos-soc-lab
bash scripts/start-siem.sh --stack splunk --live
```

For a separate live Elastic phase, stop Splunk and use `--stack elastic --fleet on --live` after completing enrollment. An offline Elastic replay phase does not need the Windows VM or live Fleet. Keep volumes and stored evidence across case restarts.

## VM: start collection before manual specimen activity

Restore the clean snapshot for the chosen profile and use a fresh case ID. Replace interface/path if your verified preparation differs:

**Run in: VM / Administrator PowerShell.**

```powershell
Set-Location C:\Lab\remcos-soc-lab
./scripts/Start-LabCollection.ps1 -CaseId P49-SPL-01 -EvidenceType actual-malware -Forwarding Splunk -SiemAddress 10.10.10.1 -CaptureInterface 1 -NetworkMode N0 -SamplePath 'C:\Lab\Specimens\4.9.3\0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5.exe' -ExpectedSampleSha256 '0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5'
```

The collector only reads the sample to verify its hash; it never launches it. For `actual-malware`, both the extracted path and expected payload hash are required. A mismatch fails before collection. `-NetworkMode N0` records your declared blocked-egress mode; it does not configure or verify isolation.

Defaults: 30 seconds of baseline, then 900 seconds observing after READY. Wait for READY, then perform the selected specimen activity manually from the intended user/integrity context in another window. Record actual trigger time, parent process, policy, and result. READY is not proof malware executed. Use N1 only for deliberately documented private controlled services; a TCP sink accepting a connection is not a full Remcos session.

For a repeat old case use a fresh ID such as `P49-SPL-02`; for the verified newer native payload use `P70-SPL-01` with its own verified path/hash. Keep same-profile conditions comparable. If using a distinct Elastic/Defend profile, use separate IDs such as `P49-EL-01` and repeat both versions under it.

## VM: finish, preserve, then revert

Keep the collector window open. Normal completion stops only its owned ETW session, finalizes packet capture, exports the UTC Windows interval, decodes ETW where possible, and creates `run.json`/`integrity.json`. Review source gaps, packet drops, and trace loss/retention. Failed/partial collection is a recorded result, not complete coverage.

Ctrl+C attempts cleanup/export. A hard shell/VM termination cannot guarantee it. For a confirmed abandoned case inspect and stop only its recorded session:

**Run in: VM / Administrator PowerShell, only for recovery of that abandoned case.**

```powershell
$abandonedCase = Get-Content C:\Lab\Cases\P49-SPL-01\run.json -Raw | ConvertFrom-Json
logman query $abandonedCase.etw.session -ets
logman stop $abandonedCase.etw.session -ets
```

Do not stop unrelated system traces. Recovery does not recreate missing exports. Keep original ETL/PCAP/EVTX even when decoding fails.

**Checkpoint:** specimen manifest, actual observation/result, case hashes, Windows logs, PCAP/ETW, and applicable EDR evidence are preserved. Follow [step 7](07-evidence-and-detection.md) before reverting the endpoint; the Windows exporter does not preserve all Elastic Defend documents/alerts by itself.
