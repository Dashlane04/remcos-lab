# Exact sample references and local verification

Checked 22 October 2026. **No malware binaries were downloaded, opened, or executed during this preparation.** The references below establish source provenance; local hash, PE, version, and execution checks remain pending.

## Primary comparison pair

### Remcos 4.9.3 Pro: Elastic analysis reference

SHA-256:

```text
0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5
```

- [Elastic part one](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-one) identifies the studied build as 4.9.3 Pro, x86 C++.
- [Elastic part four](https://security-labs.elastic.co/security-labs/dissecting-remcos-rat-part-four) lists this exact hash as its analysis reference.
- [Elastic extractor README](https://github.com/elastic/labs-releases/blob/main/extractors/remcos/README.md) uses the same hash in its example and lists version 4.9.3 support. It shows a 514048-byte input. The extractor repository is a tooling reference, not a confirmed malware download location.
- [Joe Sandbox report 1378305](https://www.joesandbox.com/analysis/1378305) independently identifies the submitted executable by this hash. Its original filename is `F6118A965E44EE55E708EDF7ADCDC1DF.exe`; filenames are not specimen identity.

Use this as the intended native-agent baseline. Native PE structure, embedded version, and suitability for direct execution still need to be checked on the actual acquired file.

### Remcos 7.0.4 Pro: exact Fortinet campaign payload

SHA-256:

```text
94ca3beeb0dfd3f02fe14de2e6fb0d26e29beb426aee911422b08465afbd2faa
```

- [Fortinet's report, 14 January 2026](https://www.fortinet.com/blog/threat-research/new-remcos-campaign-distributed-through-fake-shipping-document) lists this hash under **Remcos payload**, separately from the Word, RTF, and VBScript hashes.
- The report describes a 32-bit Microsoft Visual C++ executable without packer protection, dumped from the PowerShell process's memory, and identifies `7.0.4 Pro` in its static analysis.
- Treat it as a source-identified native payload reference. The report's memory-dump analysis does not establish that an arbitrary exported dump is a directly runnable, original disk PE. Check the actual artifact representation before dynamic comparison.

This is the hash required to claim analysis of that specific campaign payload. A different 7.0.4 sample is a separate specimen.

**Availability update, 22 October 2026:** the user could not find this exact hash on MalwareBazaar. Record that as a user-reported lookup result; repository availability has not been independently verified through an authenticated query here. The Fortinet IOC establishes specimen identity, not MalwareBazaar hosting. Do not hold the version-comparison study up waiting for this particular campaign specimen.

## Separate 7.0.4 Pro fallback candidate

[Triage report 260226-nwxjlacw4a](https://tria.ge/260226-nwxjlacw4a) lists `wealthwise_X_pe_unpacked.exe` and an extracted configuration version of **7.0.4 Pro**:

```text
29648ce421e80a3d573bdae593d86c53343933373b400c8ce781dd22fbc82176
```

Search-indexed Triage report content was available; direct report retrieval failed in this session. The name suggests an unpacked PE, but a name and sandbox configuration are not local verification. Do not label this file as Fortinet's shipping-document campaign payload.

For acquisition, open that Triage report in your browser and use its original-sample **Download** option if your account has access. Triage documents that its UI adds ZIP/encryption, whereas its API returns the submitted sample without that additional wrapping. Because this study calls for encrypted transfer archives, prefer the UI workflow and verify the resulting package and contained-file hash. Actual download permission for this report remains unverified. [Triage sample download documentation](https://tria.ge/docs/cloud-api/samples/)

A second source-reported version candidate is [Triage 251006-f4n87awsfw](https://tria.ge/251006-f4n87awsfw), SHA-256 `078d9a06629463d4481f83c0189ba3a8d94648eab75584574a89441d1e5d48b2`, whose extracted configuration reports 7.0.4 Pro. The submission also shows dropped-executable behavior; inspect the original versus recovered agent relationship before using it as a native-payload baseline. Neither candidate's MalwareBazaar availability is established.

## Acquisition status and procedure

The research pages and sandbox reports are evidence links, not verified direct-download links. MalwareBazaar lookups for the two primary hashes were inaccessible through the browsing tool. No successful binary download or current repository availability has been established. Do not assume absence from one repository means the specimen does not exist.

A later direct API request returned HTTP 401 without an Auth-Key. The separately requested [local acquisition helper](11-sample-acquisition.md) now prompts privately for that key and attempts the exact pair; it does not bypass authentication or establish availability before a successful request.

1. Search a research repository or sandbox account you can access using the complete SHA-256. Obtain the submitted file matching that hash; if using an extracted child/dump instead, record its separate hash and parent relationship.
2. Keep the acquisition archive and specimen in a dedicated local-only location in the isolated analysis environment. Do not extract onto the everyday host or put binaries in the public repository.
3. Calculate SHA-256 before analysis and compare all 64 hexadecimal characters with the reference. Hash the contained file, not just its ZIP archive.
4. Inspect actual content: DOS/PE signatures, x86 machine type, section/resource layout, and CLR data directory. Native versus managed is a PE-structure finding; `.exe` alone establishes neither. A native wrapper can also contain another payload.
5. Locate and cross-reference the embedded version, inspect the `SETTINGS` resource, and record configuration fields with their evidence. A stray version string alone is insufficient to identify the executing component.
6. Record whether the file is an original disk PE, unpacked/rebuilt PE, raw memory image, or another representation. Capture any reconstruction steps and hash each result separately.
7. Complete [sample-manifest.csv](../templates/sample-manifest.csv). Leave acquisition/version verification blank until performed; the separate [source-reference register](../templates/sample-reference-register.csv) is prefilled with research targets only.

No campaign download URLs need to be contacted to do the study. If the exact campaign payload remains unavailable, retain that limitation and use the fallback as a clearly separate version-level case.

## Delivery artifacts for the blog

Fortinet reports these additional stage hashes:

| Reported stage | SHA-256 |
| --- | --- |
| Word lure: `BL DRAFT ITL13746259.docx` | `7798059d678bca13eeeebb44a8db3588e4aa287701aede94b094b18f33b58f84` |
| RTF remote template: `w.doc` | `a35dd25cd31e4a7cca528dbfff37b5cdbb4076aac28b83fd4da397027402badd` |
| VBScript/VBE stage | `e915ce8f7271902fa7d270717a5c08e57014528f19c92266f7b192793d40972f` |

The reported chain is Word remote template -> exploit-bearing RTF -> VBScript -> PowerShell -> image-carried .NET loader -> native Remcos injected into `colorcpl.exe`. The file named `optimized_MSI.png` contains JPEG data and appended Base64-encoded .NET content; this is not evidence that the native Remcos agent is itself a .NET program or a JPEG. Describe appended encoded data accurately rather than assuming image-pixel steganography.

Attribute document exploitation, image staging, and loader-created scheduled-task persistence to this delivery chain unless payload analysis demonstrates otherwise. Malicious content carried in a common format does not make the document legitimate. If you only have the report, publish a cited delivery-chain review; reserve "I extracted/observed" for artifacts you personally examined.

For a brief source-verified specimen list, import the reference register as CSV. It intentionally does not populate the acquisition manifest or claim local validation.
