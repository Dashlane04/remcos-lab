# Synthetic fixture

`synthetic-sysmon.xml` contains four invented records for data-path checks. It contains no executable payload, credentials, or active threat infrastructure. `192.0.2.10` is a documentation address. Nothing represented by the records was executed or written to a live registry.

Expected normalized results: four events; codes `1,13,3,13`; host `SYNTHETIC-WIN`; provider `Microsoft-Windows-Sysmon`; evidence label `synthetic` when following the README command.

Expected query mechanics after correct ingestion: R1 finds the single invented Run write, R2 finds the single invented EXEpath write, R3 links the invented Run write to the invented connection three seconds later. These expected results have not been verified in a running Splunk/Elastic installation by the starter. They are not malware coverage or a false-positive benchmark.

Use a separate fixture/case for ETW. The normalizer preserves provider identity so event 13 from a different provider does not become a Sysmon registry event.
