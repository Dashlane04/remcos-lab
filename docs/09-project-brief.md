# Inside Remcos: Comparative Reverse Engineering and Windows Detection Engineering

Expanded project brief, 22 October 2026. Status: planned study with an existing lab scaffold; no malware results yet.

## Purpose

Investigate how selected Remcos 4.9.3 Pro and 7.0.4 Pro behaviors appear in Windows and network evidence, then build and evaluate detection queries in Splunk and Elastic Security. Use ETW for a specific visibility question rather than collecting an unexplained trace as a checklist item.

This is a focused, intensive lab study. It does not require complete recovery of the RAT's command set, kernel reversing, a working attacker controller, or a claim of an architectural rewrite. A finding of continuity is useful if supported by evidence.

## Research questions

1. How does each verified native payload locate and decode its configuration? Which selected fields can be supported by code and output?
2. Which startup, persistence, process, and connection behaviors are observed under the recorded configuration and protection policy?
3. Which behaviors originate in the campaign's scripts/.NET loader, and which can be attributed to the Remcos payload?
4. What can PCAP, Sysmon, Windows logs, selected ETW providers, and Elastic Defend each establish or miss?
5. Do the same detection conditions work in Splunk and Elastic on equivalent evidence, and what benign activity also matches?

## Work packages and evidence

| Package | Work | Required output |
| --- | --- | --- |
| 1. Specimen provenance | Acquire through a research repository with access; verify hashes, native PE identity, version, and disk/memory representation | Completed sample manifest; source and verification notes |
| 2. Focused RE | Trace configuration loading and selected startup/persistence/network paths in both payloads | Annotated functions, call paths, config field table, small reproducible extraction result |
| 3. Campaign breadth | Study available Word/RTF, VBScript, PowerShell, image-carried data, and .NET loader artifacts separately | Delivery diagram; stage hashes; observed versus source-reported annotations |
| 4. Dynamic evidence | Collect controlled native-payload runs and Windows baselines; correlate processes and flows; investigate one ETW visibility question | Hashed PCAP/EVTX/XML/ETL evidence, run matrix, normalized timeline, discrepancy register |
| 5. Detection engineering | Translate selected evidence into SPL and KQL/EQL; optionally develop an evidence-based YARA rule | Rule rationale, required fields, known limitations, development and held-back results |
| 6. Investigation and publication | Follow an alert to a supported conclusion and explain the old/new findings | Comparative report, one incident case, sanitized repo, blog series |

The extractor contribution can be a read-only parser for selected fields with explicit version handling and malformed-input checks. Attribute any reused Elastic code. If the published extractor already works unchanged, describe its evaluation rather than calling it a new extractor.

## Detection scope

Begin with the three existing candidate hunts: Run-key writes, watchdog-related `EXEpath` writes, and a Run-key write followed by a connection from the same process. These are behavioral leads; none alone proves Remcos attribution.

Add a script/loader or scheduled-task rule only when that stage is available and its telemetry supports it. A payload-only run may never produce the loader's persistence events. ETW requires the chosen provider, keywords, event schema, and trace window to be recorded; do not equate it with EDR or assume it records every API call.

For every rule, record a positive or missed case, relevant benign matches, collection duration, event volume, and the evidence split used for tuning versus evaluation. Tiny lab counts support an experimental result, not production precision/recall or enterprise workload claims. Show concrete benign activities such as ordinary PowerShell administration and legitimate startup/task creation where appropriate.

## What makes the study yours

- Your own annotated code paths and version checks, with references distinguished from observations.
- A comparison table marking each finding as payload difference, configuration difference, delivery difference, telemetry difference, or unresolved.
- A process/flow timeline explaining actual discrepancies between tools.
- A detection failure or benign match that leads to a documented improvement or limitation.
- Equivalent detection intent across both SIEMs, with differing field mappings and collection coverage explained.

Two specimens are a case comparison. General claims about a version require additional specimens or other supporting evidence. Do not replace an unavailable campaign sample with another 7.0.4 sample without marking the change.

## Completion and time boundary

The [one-week plan](06-one-week-plan.md) is a pilot for one specimen and the collection/detection workflow. The full comparison with two SIEMs needs additional time; budget roughly 45-70 focused hours as a planning estimate, then revise after the pilot. Preserve the overall 10 December deadline by prioritizing the paired native-payload study and evidence-backed rules; add full delivery-chain reproduction only if artifacts and time permit.

Expanded-project completion requires locally verified versions of both payloads, selected RE findings for each, comparable repeated runs or clearly labeled external evidence, actual queries executed in both SIEMs, a separate benign/held-back evaluation, and a published limitations section. If a component remains unavailable, report the project as partial and name that component.

## Blog and CV

Use one repository and one major CV project. The blog is the explanation and evidence narrative:

1. **Inside the agent:** native PE identity, configuration/crypto reversing, and selected behavior.
2. **From document to payload:** the 7.0.4 campaign's document/script/.NET delivery stages, clearly separating your artifact work from published research.
3. **From behavior to detection:** Windows/network timeline, Splunk/Elastic rules, ETW findings, and validation limitations.

In-progress CV wording: *Building an isolated Remcos analysis lab to compare 4.9.3 Pro and 7.0.4 Pro, correlate Windows/network evidence, and evaluate behavioral detections in Splunk and Elastic Security.*

After completion, replace intentions with the specific artifacts and measured results you actually produced. Avoid claiming full reverse engineering, discovery of a new threat, or production SOC deployment.

Follow the [comparative collection protocol](08-comparative-traffic-telemetry-protocol.md) for experiments and [sample provenance guide](10-sample-provenance.md) for specimen selection.
