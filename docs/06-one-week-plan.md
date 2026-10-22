# One-week core scope

This is a learning-time reference, not an alternative installation order. Follow [the canonical WSL2 setup chain](SETUP.md) and its resource/checkpoint requirements.

Assumption: about 4-6 focused hours per day. These are relative project days; they do not modify the existing VCS practice calendar or the 10 December deadline.

| Day | Focus | Finish line |
| --- | --- | --- |
| 1 | Topology + Splunk offline check | Can explain the four synthetic events and find them in Splunk |
| 2 | Windows Sysmon/forwarder + benign baseline | Real endpoint events arrive; preserved export and ingestion checks |
| 3 | Elastic/Fleet/Defend + optional 30-second ETW | Endpoint component health, telemetry visibility, actual license/policy recorded |
| 4 | Guided analysis of one selected Remcos path | Specimen identity, configuration context, observed process/registry evidence |
| 5 | Three hunts and investigation | Queries run in both SIEMs with field mappings checked |
| 6 | Benign/held-back case validation | Explain alerts, misses, telemetry gaps, and any tuning |
| 7 | Report + reproducibility | Clean README, sanitized results, screenshots, honest CV bullet |

If Fleet setup consumes the available time, complete Splunk with preserved Windows evidence and record Elastic as pending. If malware access is unavailable, finish an explicitly labeled telemetry/detection lab and leave actual Remcos validation pending. Do not rebrand synthetic fixtures as real malware evidence.

Stretch work: full second-version comparison, a validated YARA rule derived from actual specimens, provider-specific ETW normalization, more validation specimens, or a larger workload study. Do not make these core completion requirements.
