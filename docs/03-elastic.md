# Elastic setup has moved into the ordered chain

Start with [the setup index](SETUP.md). Use [step 3: Elastic/Kibana, public CA, Fleet Server policy/token/output](setup/03-siem-services.md), [step 4: Windows Elastic Agent/Defend enrollment](setup/04-windows-endpoint.md), and [step 5: live benign validation](setup/05-benign-validation.md).

Docker, configuration editing, and Python imports run in **Ubuntu Bash**. Endpoint installation runs in the **Windows VM**. Browser policy actions run in the **Windows host browser**.

The native WSL engine uses distinct private advertised/bind addresses, documented in [step 2](setup/02-network.md). Endpoint traffic uses the forwarded 9200/8220 ports; Ubuntu imports use TLS localhost 19200. CA enrollment trust and Elasticsearch output trust are separate settings.

For offline analysis and EDR preservation, use [step 7](setup/07-evidence-and-detection.md). A native endpoint alert, offline replay, and a custom SIEM rule result are separate forms of evidence. Actual policy/license capabilities must be recorded rather than assumed.
