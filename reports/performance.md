# PacketIQ Performance — Pipeline Throughput

Measured **2026-08-11** on **macOS-26.6.1-arm64-arm-64bit**, Python 3.12.13, PacketIQ v1.0.0. The timed pipeline (parse → extract → detect) is the same one used by the CLI, web app and validation harness. Numbers are real measurements on this machine, single-threaded.

**Aggregate: 4,005 packets/s, 1.0 MB/s** across 12 capture(s) (1,668,975 packets, 427.7 MB in 416.77s).

| Capture | Packets | Size (MB) | Parse (s) | Detect (s) | Total (s) | Packets/s | MB/s | Peak RSS (MB) |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| donbot.pcap | 24,764 | 5.0 | 1.86 | 3.05 | 4.91 | 5,039 | 1.0 | 112 |
| fastflux-46.pcap | 45,853 | 29.5 | 3.86 | 6.34 | 10.21 | 4,493 | 2.9 | 122 |
| neris-42.pcap | 323,154 | 55.6 | 35.58 | 63.66 | 99.23 | 3,256 | 0.6 | 192 |
| neris-43.pcap | 176,064 | 34.6 | 15.87 | 25.57 | 41.44 | 4,249 | 0.8 | 192 |
| normal-20110817.pcap | 20,549 | 2.5 | 1.93 | 3.07 | 5.00 | 4,111 | 0.5 | 192 |
| normal-dns-2013.pcap | 1,720 | 0.3 | 0.59 | 1.11 | 1.70 | 1,013 | 0.2 | 192 |
| normal-dns-2015.pcap | 5,966 | 0.7 | 1.09 | 1.90 | 2.99 | 1,996 | 0.2 | 192 |
| qvod.pcap | 85,735 | 20.4 | 8.66 | 13.90 | 22.57 | 3,799 | 0.9 | 192 |
| rbot-44.pcap | 495,056 | 122.6 | 40.61 | 71.95 | 112.56 | 4,398 | 1.1 | 240 |
| rbot-dos-icmp.pcap | 28,826 | 29.3 | 2.95 | 4.73 | 7.68 | 3,752 | 3.8 | 240 |
| sogou.pcap | 20,663 | 18.0 | 1.79 | 3.01 | 4.80 | 4,303 | 3.7 | 240 |
| virut-fastflux.pcap | 440,625 | 109.3 | 39.31 | 64.36 | 103.67 | 4,250 | 1.1 | 243 |

*Parse* streams packets through the scapy-based reader and the feature extractor; *detect* runs every detector over the extracted session state. Because parsing is streaming, memory grows far more slowly than capture size rather than loading the whole PCAP into RAM.

**Reading the RSS column.** It is `getrusage`'s *peak* for the whole process, which never decreases, so when several captures are benchmarked in one run each row inherits the high-water mark of every row above it. Read the column as the running maximum up to that point, not as the cost of that capture alone. For a per-capture figure, benchmark that capture on its own (`--pcap`), which starts a fresh process.
