# PacketIQ Performance — Pipeline Throughput

Measured on **macOS-26.5.2-arm64-arm-64bit**, Python 3.9.6. The timed pipeline (parse → extract → detect) is the same one used by the CLI, web app and validation harness. Numbers are real measurements on this machine, single-threaded.

**Aggregate: 1,660 packets/s, 0.7 MB/s** across 7 capture(s) (188,223 packets, 76.2 MB in 113.36s).

| Capture | Packets | Size (MB) | Parse (s) | Detect (s) | Total (s) | Packets/s | MB/s | Peak RSS (MB) |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| donbot.pcap | 24,764 | 5.0 | 2.72 | 8.88 | 11.59 | 2,136 | 0.4 | 107 |
| normal-20110817.pcap | 20,549 | 2.5 | 2.72 | 8.64 | 11.36 | 1,810 | 0.2 | 107 |
| normal-dns-2013.pcap | 1,720 | 0.3 | 0.89 | 3.35 | 4.24 | 406 | 0.1 | 107 |
| normal-dns-2015.pcap | 5,966 | 0.7 | 1.65 | 5.70 | 7.35 | 811 | 0.1 | 108 |
| qvod.pcap | 85,735 | 20.4 | 11.99 | 37.95 | 49.94 | 1,717 | 0.4 | 117 |
| rbot-dos-icmp.pcap | 28,826 | 29.3 | 4.27 | 14.24 | 18.51 | 1,558 | 1.6 | 120 |
| sogou.pcap | 20,663 | 18.0 | 2.42 | 7.96 | 10.38 | 1,991 | 1.7 | 151 |

*Parse* streams packets through the scapy-based reader and the feature extractor; *detect* runs every detector over the extracted session state. Peak RSS is the whole-process high-water mark. Because parsing is streaming, memory stays roughly flat with capture size rather than loading the whole PCAP into RAM.
