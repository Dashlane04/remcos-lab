# Download the two reference samples as encrypted ZIPs

Optional acquisition reference. Start at [the setup index](SETUP.md). PowerShell examples run on the **Windows HOST** except the explicitly labeled VM extraction/hash step. If you already have the intended encrypted archive, proceed to [step 6](setup/06-specimen-collection.md).

No malware or authentication key is included in this repository. The helper uses your own MalwareBazaar Auth-Key and requests only the exact reference hashes. It does not extract or execute a sample.

**Payload verification:** an archive member's filename or encryption metadata does not establish the enclosed payload's identity. Verify its contained-file hash and version inside the disposable VM and retain the acquisition record privately.

**7.0.4 availability:** availability of the exact Fortinet payload on MalwareBazaar is not confirmed. The helper cannot obtain a specimen absent from that repository. See the [separate source-reported Triage candidates](10-sample-provenance.md) for the comparison track; neither is the exact campaign payload. No fallback is substituted automatically.

## 1. Obtain access and run the downloader

Use the [abuse.ch authentication portal](https://auth.abuse.ch/) to obtain your own MalwareBazaar Auth-Key, subject to the service's access terms. Keep it local and out of source files and reports.

In an interactive PowerShell terminal on your acquisition/analyst machine, run:

```powershell
Set-Location 'C:\LabSource\remcos-soc-lab'
python scripts/download_samples.py
```

The hidden prompt asks for the Auth-Key. The script uses it only in memory for the authenticated request. It does not install a package, store the key, extract an archive, execute a sample, or change endpoint protection settings. It contacts only the official API URL and refuses HTTP redirects.

By default it requests exactly these two source-referenced hashes, each in its own repository-provided encrypted ZIP:

| Reported version | Expected payload SHA-256 |
| --- | --- |
| 4.9.3 Pro | `0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5` |
| 7.0.4 Pro | `94ca3beeb0dfd3f02fe14de2e6fb0d26e29beb426aee911422b08465afbd2faa` |

To check repository presence without fetching sample bytes:

```powershell
python scripts/download_samples.py --check-only
```

To request one version only:

```powershell
python scripts/download_samples.py --versions 4.9.3
python scripts/download_samples.py --versions 7.0.4
```

Both Python and authenticated network access must work on the acquisition machine. The helper does not bypass authentication or repository access controls.

## 2. Interpret the output

Default output directory:

```text
remcos-soc-lab/data/raw/sample-archives/
```

Successful downloads are named `remcos-VERSION-pro-SHA256.zip`. A unique `acquisition-....json` records the requested payload hash, repository metadata, ZIP hash, member names/encryption flags, timestamps, and success or failure. The directory is excluded from Git by the existing raw-data policy.

The helper first checks the repository's metadata for the exact requested hash. It then rejects JSON/HTML error responses, malformed/non-ZIP results, unencrypted file members, and oversized responses. These are structural checks, not decryption or payload verification. It never substitutes the alternate Triage specimen if the exact campaign hash is unavailable.

| Result | Meaning / next step |
| --- | --- |
| `encrypted_archive_saved` | ZIP saved; payload still needs hashing inside the VM |
| `metadata_found_only` | Repository metadata found; no sample archive downloaded |
| HTTP 401/403 | Check your key/account access; no successful acquisition is established |
| `hash_not_found` / `file_not_found` | Exact specimen unavailable through that request; keep this limitation |
| Existing destination | Existing ZIP preserved; choose a fresh `--output` directory if repeating acquisition |

The script may save one version while the other fails. Check each result. Do not populate the acquired-sample manifest just because a metadata query succeeded.

## 3. Transfer and verify inside the disposable VM

Keep the repository ZIPs encrypted during transfer; the documented archive password is **`infected`**. MalwareBazaar documents AES-encrypted ZIPs, so use an archive tool supporting that format. The standard Python ZIP reader and PowerShell `Expand-Archive` are not suitable assumptions for decrypting these archives. [Official API and ZIP documentation](https://bazaar.abuse.ch/api/)

1. Transfer the ZIPs and their acquisition JSON using your lab's temporary transfer medium, such as a read-only attached ISO. Keep your Auth-Key and analyst credentials off the specimen VM.
2. On the VM, compare each ZIP's SHA-256 to `archive_sha256` in the acquisition report. This checks transport integrity, not the enclosed payload's identity.
3. Disconnect the transfer/share from the host before specimen activity. Keep the analysis VM on the private, controlled lab network described in the topology guide.
4. Inside the disposable VM, use the archive tool to extract one ZIP into a distinct specimen directory, entering `infected` when prompted. A prevention/quarantine result is evidence to record; do not silently weaken protections.
5. Hash the extracted file itself and compare it with the corresponding complete payload hash above:

   ```powershell
   Get-ChildItem C:\Lab\Specimens\4.9.3 -File | Get-FileHash -Algorithm SHA256
   Get-ChildItem C:\Lab\Specimens\7.0.4 -File | Get-FileHash -Algorithm SHA256
   ```

6. Record native PE structure, embedded version evidence, and disk versus memory-dump/rebuilt representation using the [provenance checklist](10-sample-provenance.md). A matching download hash does not prove that a memory dump is directly runnable.
7. Populate [sample-manifest.csv](../templates/sample-manifest.csv) with the actual acquisition and verification results. Keep extracted binaries and raw evidence out of the public repository.

Preserve the two original encrypted ZIPs separately. A single combined ZIP adds another packaging layer without improving specimen identity or encryption; the helper therefore retains the original per-specimen archives.

After specimen verification, use the [telemetry collection runbook](12-telemetry-collection-runbook.md).
