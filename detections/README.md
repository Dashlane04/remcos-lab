# Experimental detections

Status: **experimental**. R1–R3 behavior hunts have not been live-validated. R4–R6 were used to review the recorded Remcos 4.9.3 Pro YARA experiment in Splunk. No scheduled alerts or endpoint response actions are enabled by these files.

R1–R3 require the `remcos_sysmon` macro installed from the bundled Splunk app. R4–R6 query the recorded experiment directly and need its imported scan metadata or live Sysmon records. The Elastic JSON is a human-readable hunt catalog, **not** a Kibana rule import/export object. Copy a query into Discover or the correct custom-rule editor after checking its data view, language, and fields.

| ID | Data | Idea | Main limitation |
| --- | --- | --- | --- |
| R1 | Sysmon 13, TargetObject | Run/RunOnce startup value write | Ordinary software installers match |
| R2 | Sysmon 13, TargetObject | Registry value named EXEpath | Name alone is not Remcos attribution |
| R3 | Sysmon 13 + 3, ProcessGuid, host | Run write then connection, same process within 5m | Cross-process handoff/disabled network collection can cause misses |
| R4 | Imported `lab.yara` scan metadata | Display the 4.9.3 Pro native-file rule match | A recorded file scan, not a continuous endpoint sensor |
| R5 | All `lab.yara` rule evaluations | Review input groups, explicit no-matches, errors and test outcomes | Expectations and actual matches are separate fields; counts do not prove general coverage |
| R6 | `lab.yara` + Sysmon 1, SHA-256 | Link the later scan to an earlier process start | Retrospective hash correlation, not detection latency or blocking |

The behavior hunts explicitly target Sysmon, not arbitrary ETW event numbers. KQL R1/R2 are filters; R3 is EQL correlation with `event_category_field=event.dataset`. Offline normalized records use dataset `windows.sysmon_operational`, matching the Windows integration naming for these hunts. Confirm this against your actual integration version.

Scope to the development case/time while tuning, then a separate validation/holdout case/time. Do not add predicates for the expected malware label to make a detector pass. Synthetic data only checks parsing and query mechanics. Any claimed malware coverage requires original specimen evidence.

## YARA for the older 4.9.3 Pro specimen

[remcos493_lab.yar](yara/remcos493_lab.yar) contains a native x86 file prototype and a separate decoded-content IOC rule. They are scoped to the analyzed **Remcos 4.9.3 Pro** case; no 7.0.4 Pro or family-wide coverage is claimed. The native rule combines parsed PE/resource structure, version and reviewed RC4 KSA bytes. The decoded-content rule can also match benign analyst notes containing the same IOCs.

See the [validation and repeat guide](yara/README.md) for the input matrix, corpus limitations, dependencies and Splunk import steps. Only source and a compact validation summary are published; malware, raw scan events and private case evidence remain excluded. R4–R6 contain this experiment's IDs and time bounds; adapt them to your own scan.

The behavior hunts are informed by the Remcos research linked in [Sources](../docs/SOURCES.md). A resource named SETTINGS or a version string alone is insufficient as a family signature.
