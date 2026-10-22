# Case ID / investigation title

Status: not started / collection verified / analysis in progress / reviewed

## Question and scope

State what you are investigating, the host(s), UTC collection window, evidence type, development/validation split, and selected behavior. Identify guidance you followed and which findings you reproduced yourself.

## Environment and provenance

- Windows build, architecture, VM snapshot:
- Splunk image/release, license, forwarder version:
- Elastic Stack/Agent/Defend package versions, license, effective protection policy:
- Sysmon binary/schema/config hash:
- Specimen or original dataset SHA-256, source, payload/wrapper relationship:
- Collector/export versions and raw file hashes:
- ETW provider, keywords, level, trace duration, loss counters (if collected):

## Alert or initial observation

Rule ID/version, platform/query language, time range, data view/index, fields required, and the original matching event. Distinguish built-in EDR alerts from your own rule and from a YARA scan.

## Investigation timeline

| UTC time | Host/process identity | Observation | Evidence reference | Confidence / alternative |
| --- | --- | --- | --- | --- |
| | | | | |

## Malware analysis connection

Selected functions/configuration fields, annotated evidence, enabled/disabled behavior, and what the SIEM can actually observe. Keep third-party loader behavior separate from the Remcos payload.

## Validation

Applicable observed scenarios, matches, misses, missing telemetry, benign collection duration/event count, alert causes, tuning changes, and separate holdout results. Report real denominators. Do not count synthetic matches as true malware positives.

## Conclusion and limitations

Benign / suspicious unresolved / confirmed malware, evidence supporting the conclusion, scope, gaps, and proposed analyst response. Include what would change the conclusion. Do not claim containment actions you did not perform.

## Reproduction and attribution

Exact query version, inputs and hashes, safe setup steps, source links, adapted code/rules and their attribution. Share sanitized examples rather than raw sensitive logs or malware archives.
