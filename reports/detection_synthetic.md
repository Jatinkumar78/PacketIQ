# PacketIQ Detection Accuracy — PacketIQ synthetic fixture suite

Binary classification (malicious vs benign) at severity threshold **MEDIUM+**. Metrics computed by running the real detection pipeline over each labeled capture.

*Measured 2026-08-11 · PacketIQ v1.0.0 · macOS-26.6.1-arm64-arm-64bit · Python 3.12.13.*

| Metric | Value |
|---|---|
| True positives | 7 |
| False positives | 0 |
| True negatives | 2 |
| False negatives | 0 |
| **Precision** | **100.0%** |
| **Recall** | **100.0%** |
| **F1** | **100.0%** |
| **Accuracy** | **100.0%** |

## Per-detector recall

| Detector (event type) | Detected | Recall |
|---|--:|--:|
| BRUTE_FORCE | 1/1 | 100% |
| C2_BEACON | 1/1 | 100% |
| CREDENTIAL_EXPOSURE | 1/1 | 100% |
| DNS_TUNNELING | 1/1 | 100% |
| HTTP_ATTACK | 1/1 | 100% |
| PORT_SCAN | 1/1 | 100% |
| SUSPICIOUS_FLAGS | 1/1 | 100% |

## Per-capture results

| Capture | Label | Flagged | Outcome | Risk | Events |
|---|---|---|---|--:|--:|
| benign_web.pcap | benign | no | TN | 0/100 | 0 |
| benign_office.pcap | benign | no | TN | 0/100 | 0 |
| port_scan.pcap | malicious | yes | TP | 57/100 | 3 |
| ssh_brute.pcap | malicious | yes | TP | 26/100 | 2 |
| xmas_scan.pcap | malicious | yes | TP | 18/100 | 2 |
| cleartext_ftp.pcap | malicious | yes | TP | 45/100 | 3 |
| http_attack.pcap | malicious | yes | TP | 16/100 | 2 |
| dns_tunnel.pcap | malicious | yes | TP | 29/100 | 2 |
| c2_beacon.pcap | malicious | yes | TP | 32/100 | 2 |
