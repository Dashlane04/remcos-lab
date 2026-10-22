# Experimental hunt pack

Status: **experimental; not live-validated**. No scheduled alerts or endpoint response actions are enabled by these files.

The SPL files require the `remcos_sysmon` macro installed from the bundled Splunk app. The Elastic JSON is a human-readable hunt catalog, **not** a Kibana rule import/export object. Copy a query into Discover or the correct custom-rule editor after checking its data view, language, and fields.

| ID | Data | Idea | Main limitation |
| --- | --- | --- | --- |
| R1 | Sysmon 13, TargetObject | Run/RunOnce startup value write | Ordinary software installers match |
| R2 | Sysmon 13, TargetObject | Registry value named EXEpath | Name alone is not Remcos attribution |
| R3 | Sysmon 13 + 3, ProcessGuid, host | Run write then connection, same process within 5m | Cross-process handoff/disabled network collection can cause misses |

All queries explicitly target Sysmon, not arbitrary ETW event numbers. KQL R1/R2 are filters; R3 is EQL correlation with `event_category_field=event.dataset`. Offline normalized records use dataset `windows.sysmon_operational`, matching the Windows integration naming for these hunts. Confirm this against your actual integration version.

Scope to the development case/time while tuning, then a separate validation/holdout case/time. Do not add predicates for the expected malware label to make a detector pass. Synthetic data only checks parsing and query mechanics. Any claimed malware coverage requires original specimen evidence.

These hunts are informed by the Remcos research linked in `docs/SOURCES.md`. A future payload YARA rule belongs here only after it has a supported source, defined file/memory scope, positive cases, and benign tests. Do not use a resource named SETTINGS or a version string alone as a family signature.
