# Getting help

PacketIQ ships with no support contract, but questions are welcome and the
answer is usually already written down. Please try these in order.

## 1. Check the documentation

| Question | Where |
|---|---|
| How do I install and run it? | [README, Quick Start](README.md#-quick-start) |
| What does each detector look for? | [README, Detection Capabilities](README.md#-detection-capabilities) |
| What can the web app do? | [README, Web Interface](README.md#-web-interface) |
| How do I tune a threshold? | [README, Configuration](README.md#-configuration) and [packetiq.toml.example](packetiq.toml.example) |
| How accurate is it, really? | [reports/detection_real.md](reports/detection_real.md) |
| How fast is it? | [reports/performance.md](reports/performance.md) |
| How does the AI copilot avoid inventing indicators? | [docs/grounding_guardrail.md](docs/grounding_guardrail.md) |
| How do I run a local model instead of a cloud one? | [docs/ollama_integration.md](docs/ollama_integration.md) |
| What is the security posture? | [SECURITY.md](SECURITY.md) |
| How do I contribute? | [CONTRIBUTING.md](CONTRIBUTING.md) |

## 2. Ask the tool

Most "what happened here" questions are answerable offline:

```bash
packetiq --help
packetiq analyze <capture> --help
packetiq feeds status          # which threat-intel feeds are loaded, and how old they are
packetiq version
```

## 3. Open an issue

Use [the issue templates](https://github.com/Jatinkumar78/PacketIQ/issues/new/choose).
There are three, and picking the right one gets you a faster answer:

* **Bug report** for a crash, a wrong result, or something that does not work as
  documented.
* **Detection issue** for a false positive or a missed detection. This is the
  most valuable kind of report this project receives, because detection accuracy
  is measured rather than asserted and a real counter-example moves the number.
* **Feature request** for a new detector, input format, export or integration.

## What to include

A report that can be reproduced gets fixed. Please give us:

* the output of `packetiq version`, your operating system, and your Python version;
* the exact command or the steps in the web app;
* what you expected and what happened instead;
* the full traceback if there was one.

**About captures.** Do not attach a capture from a production network. It
contains real addresses, hostnames, credentials in cleartext protocols and
possibly payloads you are not free to share. Instead:

* reproduce it with `python samples/generate_sample.py`, which builds a synthetic
  capture locally and ships nothing;
* or carve the smallest relevant slice with `packetiq slice`, check what is in it,
  and confirm you are permitted to publish it;
* or describe the traffic pattern in words. For a detector issue that is often
  enough, since the thresholds are documented.

Maintainers will not ask you to upload a capture you cannot share.

## What this is not

PacketIQ is a defensive analysis tool. Requests for help attacking a system,
evading detection, or analysing a third party's network without authorisation
are out of scope and will be closed. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security vulnerabilities

Do not open an issue. Follow [SECURITY.md](SECURITY.md), which asks for a private
advisory so a fix can ship before the details are public.
