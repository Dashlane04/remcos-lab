# YARA rules for Remcos 4.9.3 Pro

These are **experimental rules for the specific older Remcos 4.9.3 Pro specimen** analyzed in this lab. They are not validated against Remcos 7.0.4 Pro or other builds.

```text
Sample SHA-256: 0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5
Sample size:    494592 bytes (native x86 PE)
Rules SHA-256:  9a9ba2e2012bdec652756bd559615f667bd1a893fa055d0a956c36a2a798d47e
```

The published rules retain the exact bytes used in the recorded validation. [Machine-readable validation summary](validation-summary.json).

`remcos493_lab.yar` contains two deliberately separate scopes:

- `Remcos_493Pro_Settings_RC4_x86`: experimental native-file rule combining a parsed x86 PE, version string, RT_RCDATA/SETTINGS resource, and the reviewed RC4 KSA bytes inside an executable section. One independent malware specimen has been tested. The sample hash is metadata, not a condition.
- `Remcos_493_Case_DecodedConfig_IOCs`: case-specific content rule for a small decoded buffer. It requires both domains, the registry namespace, and the log filename. It also matches benign notes containing those same IOCs. It does not identify malware on its own and does not match the encrypted native payload in this test.

The on-disk rules do not demonstrate process-memory scanning, packed-delivery detection, other Remcos builds, or the 7.0.4 campaign. Resource-format checks establish a plausible layout; YARA does not decrypt that resource here.

## Actual validation

Run `YARA49-20261023-01` used yara-python 4.5.4 inside the isolated Windows VM on 23 October 2026, 09:54:49–09:54:50 UTC. The sample was read, not executed. Both rules compiled without warnings.

| Input | Native rule | Decoded-content rule |
|---|---|---|
| Original native sample | Match | No match |
| Renamed copy, identical SHA-256 | Match | No match |
| RC4-decoded SETTINGS, 1,264-byte in-memory buffer | No match | Match |
| 64 x86 and 64 x64 local OS reference files | No matches | No matches |
| Invalid-PE control containing version/resource-name/KSA bytes | No match | No match |
| Domains-only control | No match | No match |
| Benign IOC-notes control containing all four artifacts | No match | Match, as expected |

There were 134 inputs, 268 explicit rule evaluations, zero scan errors, and zero expectation failures. Only 64 reference files met the native rule's x86 PE/size guards. These are local OS references on a previously exposed VM, not a vetted clean-room corpus. The renamed copy is the same positive specimen, not an independent sample. These results do not establish a population false-positive rate or family coverage.

The separate domain-literal trial missed the native sample and matched the decoded buffer and benign notes, demonstrating the input-format problem.

## Repeat in the Windows VM

Prepare Python 3.10+ and the dependencies in the disposable VM before isolating it. The recorded run used Python 3.13.16 and yara-python 4.5.4. From the VM's repository root during preparation:

```powershell
python.exe -m pip install -r .\detections\yara\requirements.txt
```

The helper also requires `pefile` and a 64-bit Python interpreter to access the recorded System32/SysWOW64 reference sets as intended. Disconnect the VM's Internet-capable adapters before working with the specimen.

Use a **new run ID and output directory** each time. The helper refuses to overwrite a prior run. Keep the original specimen inside the disposable VM.

```powershell
$sample = 'C:\Lab\Samples\Remcos-4.9.3-Pro\0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5.exe'
$runId = 'YARA49-NEW-RUN'
python.exe C:\Lab\remcos-soc-lab\scripts\validate_yara493.py --sample $sample --rules C:\Lab\remcos-soc-lab\detections\yara\remcos493_lab.yar --output "C:\Lab\Analysis\$runId" --run-id $runId
```

Set `$sample` to the specimen's actual location. This validator deliberately accepts only the exact SHA-256 above and recovered configuration hash; it is not a generic Remcos unpacker. The helper reads the original, verifies its SHA-256, performs an independent RC4 known-answer check, verifies the recovered plaintext's existing hash, and scans files/buffers. It keeps key material and decoded settings out of its output. A renamed binary copy stays in the guest output directory: **retrieve only the explicitly named JSON/NDJSON files**, not that directory recursively.

## Review the results in Splunk

The installed Splunk configuration monitors `/opt/remcos/import` (mounted from the Ubuntu lab's `data/import`) for `.ndjson` files as `remcos:json` in `remcos_lab`. YARA runs in the VM; Splunk searches its structured scan results. This is a one-shot metadata import, not native SPL file scanning or a continuously deployed YARA sensor.

Retrieve `$runId.ndjson`, `validation.json`, and checksums through the established private VM connection. Verify them before copying the NDJSON once to Ubuntu's `~/remcos-soc-lab/data/import/`. Do not transfer the binary or decrypted settings to Splunk.

For the captured run:

```spl
index=remcos_lab sourcetype="remcos:json" event.dataset="lab.yara"
labels.case_id="YARA49-20261023-01" earliest=1792749240 latest=1792749360
| stats count dc(event.id) as distinct_events dc(input.id) as inputs
    count(eval('rule.matched'="true")) as matches
    count(eval('event.outcome'="failure")) as errors
    count(eval('test.passed'="false")) as failed_tests by labels.input_group
```

Match-only output cannot establish that a negative control was scanned. The helper therefore emits one event per input/rule, recording explicit no-match and error outcomes. `test.expected_match` is the declared test expectation; `rule.matched` is the actual YARA result. `event.id` identifies a rule evaluation, not an independent file.

Use [R4](../splunk/R4-yara-native-match.spl), [R5](../splunk/R5-yara-validation-coverage.spl), and [R6](../splunk/R6-yara-sysmon-hash-correlation.spl). Their run IDs and time bounds describe this recorded experiment; update them for a new scan. The correlation links the later file scan to an earlier process-start hash and is not a live detection-latency measurement. Per-input duration in the metadata includes reading, hashing, PE parsing, and matching.

## References

- [YARA PE module](https://yara.readthedocs.io/en/stable/modules/pe.html): parsed resources and executable section bounds. Named resource strings are exposed as UTF-16 bytes in this interface.
- [yara-python](https://yara.readthedocs.io/en/stable/yarapython.html): strict compilation, buffer scanning, timeouts, and string-match witnesses.
