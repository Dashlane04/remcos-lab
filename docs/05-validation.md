# Experiments, detections, and analyst workflow

## Three evidence levels

1. Synthetic fixture: parser, data routing, and query smoke checks only.
2. Benign background / benign emulation: exercise collection and expose false positives. Label constructed tests honestly.
3. Actual malware evidence: a preserved recording from a known Remcos specimen or a trusted original dataset, tied to SHA-256, source, execution window, and protection policy.

Replaying existing evidence tests analytics; it does not reproduce execution, endpoint prevention, collection overhead, or a live EDR decision. Do not change historical timestamps to make a scheduled rule appear successful. Use historical windows and describe replay as replay.

## Experiments

| ID | Question | Required evidence | Result to record |
| --- | --- | --- | --- |
| E0 | Can each SIEM parse a known event? | Synthetic fixture | Original vs indexed timestamp, host, provider, event code, key fields |
| E1 | Is real benign collection working? | Windows export + agent health | Missing channels, ingestion delay, events by source, storage |
| E2 | What selected Remcos behavior actually occurs? | Specimen hash + trace/report | Enabled config, process tree, observed artifacts, prevented stages |
| E3 | Do the three hunts find it? | Frozen development case | Matches, missing fields, expected behaviors absent, rule version |
| E4 | Do ordinary applications match? | Separate benign sessions | Alerts per monitored hour and cause of each alert |
| E5 | Does tuning generalize? | Previously unused validation/holdout case | Misses, benign matches, changes from development |

Do not invent positives to satisfy every row. If persistence is disabled in a specimen, its absence is a configuration-dependent negative, not necessarily a detection miss. If required telemetry was not collected, classify it as an observability gap. A blocked sample may yield a prevention alert and no later network activity.

## Candidate hunts

Read each query's comments. They are research hypotheses, not production-ready Remcos signatures:

- R1: writes to Run/RunOnce startup values. Broad persistence hunting; installers often match.
- R2: registry value named EXEpath, discussed in Elastic's Remcos watchdog research. Not unique; validate against configuration and process context.
- R3: a Run/RunOnce write followed within five minutes by a network event with the same host and process GUID. Correlation can miss behavior delegated to a different process, and a network event proves a connection, not successful C2.

Keep Elastic built-in EDR alerts, your custom behavior hunts, and any future payload YARA matches as separate evidence sources. No actual payload YARA signature is supplied because deriving one requires analysis and validation of your specimens. Network payload content may be unavailable under TLS; DNS names, IPs, timing, or an unusual port alone do not establish Remcos.

## Record workload honestly

Measure duration, endpoint count, event count, events/second, ingested bytes, rule execution time, alert delay (if live), and benign alert count. For manually replayed data, report query runtime separately from live detection latency. More copies of one session do not make a more representative workload. Keep attack and benign intervals in a ground-truth manifest, not as label-dependent predicates in detection logic.

Do not tune and evaluate on the same capture. With one specimen you have a case study, not family-wide coverage. For a percentage, disclose its denominator: e.g., matched scenarios / applicable observed scenarios. Do not label a synthetic four-event match as a malware detection rate.

## Investigation steps

1. Confirm the time window, host, data source, duplicate ingestion risk, and rule version.
2. Inspect the original event and the available process tree, including parent, user, command line, and process identity.
3. Correlate the registry value/data, executable path/hash, network metadata, and recovered configuration when available.
4. Explain a benign alternative and what evidence would support/refute it.
5. Decide: benign, suspicious/unresolved, or confirmed malware with supporting evidence.
6. Record scope, missing telemetry, and proposed response. This starter does not automate quarantine, deletion, or host isolation.

Use `templates/case-report.md`, `ground-truth.csv`, and `validation-results.csv`. Preserve original timezone/UTC conversion. Publish sanitized evidence rather than personal browsing histories, tokens, or raw specimen archives.
