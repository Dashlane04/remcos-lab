# Splunk setup has moved into the ordered chain

Use [the setup index](SETUP.md) first. Follow [step 3: Splunk-first server startup and fixture check](setup/03-siem-services.md), [step 4: Windows Universal Forwarder](setup/04-windows-endpoint.md), and [step 5: benign validation](setup/05-benign-validation.md).

Server initialization and Docker commands run in **Ubuntu Bash**. The endpoint forwarder and Windows collection scripts run in the **Windows VM**. No PowerShell initializer is required on Ubuntu.

For offline imports, field/duplicate handling, and actual case evaluation, continue to [step 7](setup/07-evidence-and-detection.md). The [validation methodology](05-validation.md) and [manual telemetry reference](12-telemetry-collection-runbook.md) explain the underlying evidence paths.
