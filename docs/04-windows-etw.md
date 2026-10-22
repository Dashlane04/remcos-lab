# Windows and ETW setup has moved into the ordered chain

Follow [step 4: Windows endpoint preparation](setup/04-windows-endpoint.md), then [step 5: benign validation](setup/05-benign-validation.md). Run PowerShell collection commands **inside the disposable Windows VM**, not Ubuntu.

[Step 6](setup/06-specimen-collection.md) describes the automated ETW/PCAP/marker/export sequence and owned-session recovery. [The manual telemetry reference](12-telemetry-collection-runbook.md) explains individual collector commands, provider mapping, loss/retention checks, timestamp interpretation, and export semantics.

ETW is not a universal API recorder. Its provider, keywords, level, schema, selected interval, circular retention, and lost events determine what can be concluded. Sysmon event IDs cannot be applied to other providers merely because the numbers match.
