# Remcos comparative traffic and Windows telemetry protocol

Version 1.0 | 22 October 2026 | Planned protocol, not an analysis result

Research/experiment reference. Complete [the ordered WSL2 setup chain](SETUP.md) first. Capture/export commands belong to the Windows VM; normalization and optional offline tshark analysis below use Ubuntu Bash after evidence transfer.

This is an observation and evidence-analysis protocol for the existing Splunk/Elastic lab. It supplies no malware launcher, exploit recreation, controller, or protection-bypass instructions. Use the setup guides first. Only collection/export commands below are provided.

## 1. Define the comparison before collecting data

Your primary question:

> Under documented, comparable conditions, what network activity and Windows evidence do selected Remcos 4.9.3 Pro and 7.0.4 Pro specimens produce, and which observed differences are attributable to payload, configuration, delivery, environment, or collection?

Keep two tracks:

| Track | Compare | Permitted conclusion |
| --- | --- | --- |
| Payload | Recovered native 4.9.3 and 7.0.4 agents, using the same observation procedure | Differences between the studied specimens, after accounting for config/policy |
| Campaign | Original recorded delivery-chain evidence, or an available original chain in the controlled lab | Differences in these delivery cases; not automatically changes to the Remcos agent |

Elastic's baseline analysis concerns a native x86 C++ payload and configuration-dependent behaviors. [Old payload reference](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-one)

Fortinet's January 2026 case documents Word/RTF, VBScript/PowerShell, an external .NET loader, scheduled-task persistence, and injection into `colorcpl.exe`. Its final agent is 7.0.4 Pro. Those delivery components are campaign evidence, not proof that Remcos became .NET. [Campaign reference](https://www.fortinet.com/blog/threat-research/new-remcos-campaign-distributed-through-fake-shipping-document)

Do not compare an old unpacked EXE directly with the new Word document and call every difference a version change. If the old campaign chain is unavailable, mark that comparison unavailable.

## 2. Register specimens and configuration

Create a sample manifest before execution or replay. Record:

- Outer artifact and recovered payload SHA-256 separately; source/report URL; acquisition date; architecture; embedded version evidence.
- Whether the artifact is packed, unpacked on disk, or reconstructed from memory; how it was obtained; any changes to bytes or headers.
- Relevant configuration values and confidence: destinations/ports, per-destination TLS flag, retry setting, installation/persistence flags, injection/watchdog options, capture flags, configured paths/names, and certificate-related blobs.
- Which fields are independently recovered vs copied from a reference; a JSON/hash reference to the extracted config; unresolved fields.

Use semantic field names in comparisons. Do not assume a field index, separator, or encoding is identical across versions. Match fields to their use in code or reliable decoded evidence. Do not patch samples to force equal behavior; stratify the experiment by actual enabled settings instead.

For the newer reference case, Fortinet identifies payload SHA-256 `94ca3beeb0dfd3f02fe14de2e6fb0d26e29beb426aee911422b08465afbd2faa`. An unrelated 7.0.4 specimen is valid research material but is not automatically that campaign's payload. Treat any old-version specimen reference as a candidate until the payload edition/version is verified. [Published sample identifiers](https://www.fortinet.com/blog/threat-research/new-remcos-campaign-distributed-through-fake-shipping-document)

## 3. Freeze the environment

Use one clean disposable endpoint snapshot, with the collection stack already tested. Record Windows/Office build and patches (if relevant), user/integrity level, agent versions, audit settings, Sysmon XML hash, integration version, effective EDR policy, Defender status/signature version, VM resources, snapshot identity, and network configuration.

Use the same user, working-directory convention, observation length, background-workload recipe, network mode, and collection profile for the payload comparison. Record the immediate parent/launch context instead of assuming it is identical. Windows protection/signature updates and integration changes between cases are confounders; record them and avoid silent changes.

Keep default protection settings. If execution is prevented, capture the prevention result and stop at that boundary. Do not silently weaken a policy to obtain later stages. Use original recorded evidence for stages you cannot observe. A modern patched Office version failing to reproduce an old exploit is an environment/result limitation, not evidence of a Remcos architecture difference.

Use UTC throughout. Before each run, record endpoint and sensor times and measure their offset with a shared harmless marker. Do not require Internet time synchronization during malware collection. A restored VM can repeat record numbers, PIDs, or identities: join using **run ID + host + process identity + time**, not a globally assumed record ID.

## 4. Choose a network mode explicitly

| Mode | Conditions | What it supports | What it does not establish |
| --- | --- | --- | --- |
| N0 blocked | No external egress; only necessary private collector traffic | DNS/connect attempts, local behavior, prevention | Successful C2 or later commands |
| N1 controlled services | Private sink/DNS/service under your control; original destinations and all redirection documented | Routing/retry/handshake observations, some local transfer behavior | A sink accepting TCP is not a real Remcos conversation |
| N2 original recording | Provenanced historical PCAP plus matching host logs where available | Passive analysis of observed sessions | Current reachability or reproduction of missing host behavior |

Start with N0 or original recordings. Never enable uncontrolled Internet access to reach an old C2. Do not recreate the Word exploit or contact the article's live URLs to fill missing stages. Missing historical infrastructure is an acceptable limitation.

In N1, record the original configured destination, DNS question/answer, lab-mapped address, service behavior, and whether TLS validation succeeded. A lab sink certificate/address is **lab infrastructure**, not a threat IOC. A failed handshake can change retry behavior and suppress application data.

Capture the endpoint NIC directly or use a verified routing/mirroring capture point. A second VM on the same virtual switch does not necessarily see unicast traffic between other machines. Verify visibility with benign traffic in both directions before a specimen run.

Keep the complete capture for the selected endpoint/interface initially. SIEM/Fleet traffic on 9200/8220/9997 is background to label during analysis, not something to erase from raw evidence. If the SIEM machine also hosts the sink, do not exclude its entire IP. Account for IPv6 or state explicitly that the measured interface/run was IPv4-only.

## 5. Prepare the collection matrix

Check source availability first; an absent event is meaningful only if the relevant sensor/audit policy was enabled and functioning.

| Source | Collect | Supports | Important limitation |
| --- | --- | --- | --- |
| Sysmon Operational | 1/5 process start/stop; 3 connections; 11 file creation; 12/13/14 registry; 22 DNS; 8 and 25 where generated | Process/flow attribution, artifacts, selected injection indicators | 8 is remote-thread evidence, not universal injection coverage; 25 is not guaranteed |
| Windows Security | 4688; 4698/4702 when auditing is enabled | Independent process/task context and task XML | Command lines and task auditing require their respective policies |
| PowerShell Operational | 4104 script blocks; 4103 if module logging is deliberately enabled | Script content and some execution context | Fragmentation, host/version differences, and pre-execution blocking affect visibility |
| TaskScheduler Operational | Enable the channel; retain its window, task/action/instance fields | Task lifecycle and executions | Event schemas/IDs must be checked against the installed Windows provider |
| Defender Operational | Original detections/actions including 1116/1117 when present | Why a stage may have been prevented | Read actual action/status; 1117 does not universally mean successful quarantine |
| Elastic Defend | Relevant endpoint events, alerts, policy state, event/action/outcome | Additional behavior/protection evidence | EDR event collection may be selective; native alerts are separate from your rules |
| PCAPNG | Full endpoint capture at the verified capture point | DNS, TCP/TLS/HTTP metadata, timing and byte counts | Does not provide registry changes or automatically identify the responsible process |
| Optional ETW | Short same-provider/keyword/level window | Provider-specific deeper process evidence | Emitting PID is not necessarily target PID; no universal API trace |

Sysmon's [official event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) documents these event types and the optional/noisy nature of several collectors. Keep baseline collection unchanged across the two payload cases. If adding filtered ImageLoad/ProcessAccess for a focused question, make a separate enhanced profile and repeat both cases; the starter intentionally does not broadly enable those sources.

For 4688, enable **Audit Process Creation** and **Include command line in process creation events** inside the VM if needed. For 4698/4702, enable **Audit Other Object Access Events** success auditing. Record effective settings before the run. Do not infer successful audit setup merely from a SIEM input being enabled. [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), [4702](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702)

PowerShell logging modes differ: 4104 is script-block logging, 4103 is module logging. [Microsoft reference](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/debug-customscriptextension-runcommand-scripts)

The default forwarder template has Security collection disabled and lacks TaskScheduler/Defender inputs. For this protocol, preserve these through the enhanced exporter and import the normalized records offline, or explicitly configure/test live inputs and required fields. The Windows integration's Sysmon input alone does not collect every channel in this matrix.

## 6. Experiment matrix

Start with the companion `templates/comparison-run-matrix.csv`. Suggested scoped plan:

| Cases | Track | Repeats | Purpose |
| --- | --- | --- | --- |
| BASE-01 / BASE-02 | Background, no malware | Two fresh sessions | Idle + normal application/network noise and collection health |
| P49-01..03 | Old native payload | Three independent clean-snapshot runs if feasible | Initial behavior and variability |
| P70-01..03 | New native payload | Three under the same conditions | Comparable behavior and variability |
| C70-01 | Original new campaign evidence | One provenanced recording/run initially | Delivery-chain process/task/network context |
| HOLDOUT-* | Unused benign or additional specimen evidence | At least one if available | Test frozen rules and conclusions |

For a one-week project, one run per payload plus one repeat each is a defensible smaller case study. If you cannot repeat, disclose that timing/absence claims have weak support. Original recorded campaign evidence stays labeled as recorded; a synthetic replay is not another independent execution.

Use a default 15-minute observation: two-minute pre-window, ten-minute observation after the manual start/recorded trigger, three-minute tail. This is a lab choice, not a Remcos requirement. Longer config-driven delays need a longer new run, with the same duration for the paired comparison. A 30-second trace cannot prove that a minutes-long action never occurs.

Keep network/protection modes separate in the matrix. Do not aggregate a blocked old payload and a successfully connected new payload as if conditions matched.

## 7. Run procedure

### Before the trigger

1. Assign run ID, specimen ID, track, network mode, evidence type, and development/holdout split.
2. Restore the verified clean endpoint snapshot. Use only one active clone with a given enrolled endpoint identity. Check agent health and current policy after restore.
3. Confirm the network route/collector allowlist and the packet capture point. Record clock offsets, adapter/MAC/IP, Windows/agent versions, snapshot, and collector configuration hashes.
4. Start packet capture; record its interface, filter, tool version, and storage limits. Start the pre-window and benign time marker. Confirm live delivery or a readable local event.
5. If ETW is needed, use the same short window/provider parameters for both cases. In another terminal, run `Capture-Etw.ps1` around the selected phase. Record trace loss and any overhead.
6. Record the exact UTC trigger time and original artifact/start context. The specimen start itself is manually controlled by your analysis procedure; this protocol provides no executable trigger command.

### During observation

7. Keep a timestamped observer log: first process, file/registry/task creation, first DNS/SYN, protection alert, and terminal condition. Do not edit artifacts, terminate a process, reboot, alter networking, or inject extra user activity mid-run unless that is a separately labeled experiment.
8. Record whether each stage was attempted, observed, prevented, or unreachable. A TCP handshake is not a C2 registration. A native EDR alert may precede a SIEM alert; keep original event time and ingest/alert time separate.
9. Stop early if containment/collection fails, disk limits are reached, or unexpected external routing is observed. Preserve the partial case and its failure reason instead of silently retrying under the same run ID.

### After observation

10. Allow the predefined tail to finish. Stop only your owned ETW/packet sessions. Preserve capture statistics and any packet loss.
11. Export the exact UTC run window **before reverting**. Export original EVTX, compatible XML, EDR events/alerts/policy, packet capture, observer log, and selected relevant artifact metadata/task XML. Optional memory/dump evidence is a separate step with its collection method and hash recorded.
12. Hash all evidence and write the run manifest. Copy it to private evidence storage. Confirm the export succeeded before reverting the endpoint snapshot for the next run.

### Collection command examples

Choose the packet interface using `dumpcap -D`. In a separate capture terminal on the verified sensor/endpoint, use an appropriate interface ID (replace `2`) and a fresh output path:

```powershell
dumpcap -i 2 -a duration:900 -s 0 -w C:\Lab\Cases\P49-01\raw\network.pcapng
```

Create the case directory first. This broad capture may include unrelated traffic if the chosen interface serves multiple hosts; preserve the filter/interface choice. Afterward, analyze a working copy and restrict display/query scope to the endpoint. If storage cannot hold a full 15-minute capture, measure a shorter paired window or document truncation rather than silently overwriting earlier evidence. [dumpcap reference](https://www.wireshark.org/docs/man-pages/dumpcap.html)

After the run, inside the Windows VM:

```powershell
./scripts/Export-LabEvents.ps1 -StartUtc '2026-10-22T03:00:00Z' -EndUtc '2026-10-22T03:15:00Z' -IncludeCampaignLogs -OutputDirectory ./data/raw/P49-01/windows
```

Replace the example times with your recorded run interval; include both bounds. The new switch exports six channels where available: Sysmon, PowerShell, selected Security events (4688/4698/4702), TaskScheduler, Defender, and System. It does not enable audit policies or channels. Inspect `manifest.json` for failed/disabled channels and event counts; a created folder is not proof of successful collection.

For each preserved exported XML file, **run in SIEM / Ubuntu Bash**, from `~/remcos-soc-lab` after evidence transfer:

```bash
python3 scripts/normalize_events.py data/raw/P49-01/windows/sysmon.xml --output data/normalized/P49-01-sysmon.ndjson --case-id P49-01 --evidence-type actual-malware --split development
python3 scripts/normalize_events.py data/raw/P49-01/windows/security.xml --output data/normalized/P49-01-security.ndjson --case-id P49-01 --evidence-type actual-malware --split development
```

Use `actual-malware` only for a verified real case; use the appropriate benign/synthetic label otherwise. The converter defaults non-Sysmon providers to `windows.eventlog`, preserving provider/channel/fields. Do not force Security/ETW records into the Sysmon dataset. Import with the existing Splunk monitored-folder or authenticated Elastic importer procedure. Keep raw EVTX/PCAP authoritative; normalize working copies.

For practical SIEM ingestion, normalized `@timestamp` uses millisecond precision; `winlog.time_created_raw` retains the original SystemTime string, including higher precision. Use original timestamps and packet references for finer ordering, and report genuinely simultaneous/ambiguous events rather than inventing an order from ingestion time.

## 8. Analyze the network first

Work from broad flow inventory to the selected conversation:

1. List DNS questions, returned answers/rcode, destinations/ports, connection starts/ends, bytes each direction, durations, and first/last observed times. Include IP-only destinations and unsuccessful attempts.
2. Label each flow: known collector, benign background, delivery/download, candidate payload connection, local controlled service, or unresolved. State why. Do not identify Remcos from a port alone.
3. For delivery evidence, map redirects/downloads to timestamps and source processes where supported. Distinguish an original URL from a lab-mapped service and content actually recovered from PCAP versus only present in a script/config.
4. Classify transport evidence: DNS only; SYN attempts; TCP established; TLS ClientHello; negotiated TLS; application bytes; confirmed application message if readable. Report the highest stage actually supported.
5. Compute attempt intervals per destination, then median/range over repeats. Separate OS TCP retransmissions from fresh application connections. Do not call every repeated packet a beacon.
6. Record negotiated TLS version/cipher when visible, SNI if present, handshake errors, and certificates only if actually available. No SNI/certificate visibility is not proof of no TLS.

Useful Wireshark display filters:

```text
dns
tcp.flags.syn == 1 && tcp.flags.ack == 0
tls.handshake.type == 1
tcp.analysis.retransmission
tcp.stream eq 0
```

Replace stream 0 with the selected stream. A display filter selects evidence for analysis; it does not change the original capture. If a nonstandard port is not dissected correctly, verify bytes and use Decode As deliberately, recording that choice.

Optional offline summaries: **run in SIEM / Ubuntu Bash**, from the working copy's network-evidence directory, with tshark installed:

```bash
tshark -r network.pcapng -q -z conv,tcp
tshark -r network.pcapng -Y dns -T fields -e frame.number -e frame.time_epoch -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e dns.qry.name -e dns.a -e dns.aaaa -e dns.flags.rcode -E header=y -E separator=, -E quote=d
```

Export results as derived evidence with the tool version and exact command. Check available fields in the installed version before automation. [Wireshark guide](https://www.wireshark.org/docs/wsug_html/)

### Application-protocol comparison, if plaintext is genuinely available

Keep this optional. Both published analyses describe the same magic value `0x00ff0424` / little-endian bytes `24 04 ff 00`, a size field, command identifier, and message data. TLS was already available in the older version. These are starting hypotheses to verify, not evidence that the newer specimen changed transport. [Old communication analysis](https://www.elastic.co/security-labs/threat-command/dissecting-remcos-rat-part-two), [new packet discussion](https://www.fortinet.com/blog/threat-research/new-remcos-campaign-distributed-through-fake-shipping-document)

On a reassembled readable TCP/application stream, compare header width/endianness, what the length includes, registration-message identifier, field encodings/separators, and the selected metadata fields. Preserve stream offsets and raw bytes. TCP segments/TLS records are not equivalent to application messages. Do not search raw encrypted TCP packets for the magic and interpret its absence as a changed protocol.

Keep recorded wire bytes, a dump observed before encryption, a source article's reproduced plaintext example, and your own synthetic fixture as different evidence types. Do not send controller commands to obtain more functionality for this project.

### TLS boundary

The configuration's RC4 key is not a TLS traffic key. An embedded certificate or private key does not automatically decrypt a captured session. Modern forward-secret TLS generally requires appropriate session secrets; arbitrary native applications need not honor `SSLKEYLOGFILE`. TLS 1.3 also encrypts authentication messages after ServerHello. If keys/plaintext are unavailable, retain a metadata-level comparison and state that limitation. [Wireshark TLS decryption](https://wiki.wireshark.org/TLS), [TLS 1.3 specification](https://www.rfc-editor.org/rfc/rfc8446)

## 9. Correlate flows to processes and Windows artifacts

Use the packet 5-tuple and timestamps to locate Sysmon network events; then pivot through process GUID and process-start evidence. Use a clock tolerance measured in the benign pilot, not an unexplained fixed assumption. Account for NAT/sink address translation. If attribution is ambiguous, mark it unresolved.

Failed connection attempts may appear in PCAP without a corresponding Sysmon connection event. An IP-literal destination or a cached name can also produce no new DNS query. Neither absence, by itself, means that the payload performed no network activity. Keep optional ETW provider choices tied to the question: Kernel-Process events alone do not establish reflection-loaded CLR assembly behavior.

Build the following chain, with evidence references at each edge:

```text
original artifact -> parent/child process -> file/registry/task action
                  -> network connection -> DNS/TLS/flow observation
                  -> optional EDR/ETW corroboration
```

For every candidate flow, answer:

- Which PID/GUID and process image owned the connection? What was its parent and user/integrity context?
- Is the image hash from a file on disk, or do you have separate memory evidence? A signed container process's disk hash is not the injected payload's hash.
- Was there a matching process start before the connection? If not, did capture start late, did telemetry drop, or was a pre-existing process used?
- Which registry/task/file evidence occurred before or after it? Is the behavior enabled in the recovered config?
- Does a protection action explain an aborted chain? Read Defender 1117's action/status instead of assuming every occurrence is quarantine. [Defender event meanings](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

Security 4688 PIDs can be hexadecimal; Sysmon commonly reports numeric values differently. Normalize representation and bound the join to the process lifetime. A task's TaskName, task XML, subject/client-process fields where present, and subsequent execution provide stronger context than a task name alone. A COM-based task registration need not create `schtasks.exe`.

PowerShell script blocks may be split: group by host/run and ScriptBlockId, check fragment order/count, and preserve originals. A decoded script string indicates available content; it does not establish that every branch executed. Reflection-loaded .NET code need not generate a normal disk DLL-load event. A lack of Sysmon 8 does not refute section-mapping/context-change injection.

Use `templates/flow-process-correlation.csv` for this join and `templates/telemetry-timeline.csv` for the chronological narrative. Keep source event times separate from SIEM ingestion/alert times. Different SIEM field names or dashboard counts are pipeline questions until the raw evidence establishes an execution difference.

## 10. Classify discrepancies before interpreting them

For each discrepancy, fill `templates/discrepancy-register.csv` and follow this order:

1. **Scope:** same artifact layer, run window, enabled behavior, and network/protection mode?
2. **Collection:** sensor/channel enabled, configuration matching, no rollover/drops, clock offset accounted for?
3. **Pipeline:** raw event present but SIEM missing/renamed/truncated/delayed/duplicated, or wrong query time/index?
4. **Environment:** Windows/Office patches, integrity level, DNS/service availability, certificate validation, EDR action?
5. **Configuration:** feature flags, target paths/processes, destinations, timing?
6. **Delivery:** wrapper/loader behavior rather than the native agent?
7. **Payload:** repeatable remaining difference supported by config/code or independent observations?

Use one or more primary classification values: `collection`, `pipeline`, `environment`, `configuration`, `delivery`, `payload-candidate`, `unresolved`. Observed status is separate: `present`, `not-observed`, `not-collected`, `prevented`, `not-applicable`.

Examples:

| Observation | First explanation to test | Evidence needed before a stronger claim |
| --- | --- | --- |
| New case has a task, old case a Run value | Different loader/config | Task XML/creator context, native config/code |
| New case has no Sysmon 8 | Technique or visibility differs | Process tampering/memory/EDR evidence and effective collection policy |
| New case uses TLS | Old case's TLS flag/network mode may differ | Both configs and actual handshake observations |
| One SIEM misses an event | Data-view, parser, time-range, or ingest issue | Raw EVTX plus both indexed records and settings |
| No 4698 for new case | Audit disabled, case incomplete, or no task created | Audit settings, original task evidence, blocked-stage timeline |

Repeat an implicated case with **one documented factor** changed only when needed. Do not modify the sample or silently pool differently instrumented runs. If the cause cannot be isolated, report an observed specimen/campaign difference without calling it an architectural transition.

## 11. Build an IOC/evidence package

Use `templates/ioc-register.csv`. For every entry retain type/value, source run, original evidence reference, first/last seen, status, confidence, scope, and caveat.

Distinguish:

- Exact sample/artifact SHA-256: reliable identifier for those bytes; limited generalization.
- Network destination: `configured-only`, `observed-attempt`, or `observed-session`; never silently merge those claims.
- Domain/URL/path/task/mutex: note configurability and whether it belongs to loader, payload, or lab infrastructure.
- Certificate fingerprint: identify whether extracted from config, observed peer/client certificate, or the lab service; do not conflate them.
- Behavioral detection: a separate rule/hypothesis with prerequisites and benign alternatives; it is not a literal IOC string.

Retain exact values privately, publish defanged network indicators where appropriate, and document duplicates/shared infrastructure. Do not label every domain contacted by Word, Windows, Splunk, or Elastic as an attacker IOC. A hash/name on its own cannot establish the rest of an execution chain.

## 12. Validate and report

Freeze the rule/query and its telemetry requirements before opening held-back evidence. Evaluate R1/R2/R3 from the starter where applicable; add campaign-specific task/script hypotheses only after checking fields and benign alternatives. Do not judge a scheduled-task case solely by a Run-key rule.

Count applicable observed scenarios, missing-telemetry cases, matches, misses, benign alerts, endpoint-hours, event volume, and live vs replay latency separately. Report per-run variability rather than fabricated population statistics. Synthetic matches remain smoke checks. Repeated captures from one specimen are useful reproducibility checks, not independent family-wide sample coverage.

Final outputs:

1. A version/campaign scope statement and environment/config table.
2. Two process/traffic-flow diagrams with original event/packet references.
3. A network comparison table and joined Windows timeline.
4. A discrepancy register distinguishing confirmed causes from hypotheses.
5. A scoped IOC register and tested behavior hunts, with false positives/gaps.
6. Reproduction steps and preserved-evidence hashes; sanitized excerpts for the public report.

A defensible conclusion might be: "In these two specimens, the campaign loader changed observable process and persistence artifacts; the studied payload messages retained the documented framing. TLS payload content was not recovered, so command-level differences remain unresolved." Only use that wording if your own evidence actually supports it.

## Per-run completion checklist

- [ ] Correct artifact layer and version verified; payload/config hashes recorded.
- [ ] Snapshot, privileges, Windows/agent versions, collection/protection policies fixed and recorded.
- [ ] Network mode/capture visibility/clock offset checked; no uncontrolled egress.
- [ ] Exact UTC window and trigger context recorded; independent run ID assigned.
- [ ] Raw PCAP/EVTX/optional ETL and EDR exports preserved before revert.
- [ ] Failed/disabled sources, packet/event loss, and prevented stages recorded.
- [ ] Process/flow joins include time and identity, with ambiguity explicit.
- [ ] IOC origin and discrepancy classification supported by raw evidence.
- [ ] Rules evaluated on separate benign/held-back evidence; no synthetic coverage claims.
