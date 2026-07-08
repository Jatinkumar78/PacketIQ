#!/usr/bin/env bash
# Fetch a small, balanced set of REAL labeled captures from the Stratosphere IPS
# CTU-13 / Malware Capture Facility Project (https://www.stratosphereips.org).
#
# These are genuine captures with authoritative ground-truth labels:
#   * botnet-capture-* : a host infected with real malware (label: MALICIOUS)
#   * normal-capture-* / *-only-dns : real benign traffic  (label: BENIGN)
#
# They are downloaded into datasets/real/pcaps/ (gitignored — never committed).
# Total ~185 MB (8 captures, 5 malware families). Re-runnable: skips files already
# present (curl -C - resume).
set -euo pipefail
BASE="https://mcfp.felk.cvut.cz/publicDatasets"
DEST="$(cd "$(dirname "$0")" && pwd)/real/pcaps"
mkdir -p "$DEST"

# folder/path  ->  local filename        (label encoded in the manifest, not here)
FILES=(
  "CTU-Malware-Capture-Botnet-47/botnet-capture-20110816-donbot.pcap|donbot.pcap"
  "CTU-Malware-Capture-Botnet-48/botnet-capture-20110816-sogou.pcap|sogou.pcap"
  "CTU-Malware-Capture-Botnet-49/botnet-capture-20110816-qvod.pcap|qvod.pcap"
  "CTU-Malware-Capture-Botnet-45/botnet-capture-20110815-rbot-dos-icmp.pcap|rbot-dos-icmp.pcap"
  "CTU-Malware-Capture-Botnet-54/botnet-capture-20110815-fast-flux-2.pcap|virut-fastflux.pcap"
  "CTU-Malware-Capture-Botnet-50/normal-capture-20110817.pcap|normal-20110817.pcap"
  "CTU-Normal-4-only-DNS/2015-03-24_capture1-only-dns.pcap|normal-dns-2015.pcap"
  "CTU-Normal-6-filtered/2013-10-21_capture-1-only-dns.pcap|normal-dns-2013.pcap"
)

for entry in "${FILES[@]}"; do
  remote="${entry%%|*}"; local="${entry##*|}"
  out="$DEST/$local"
  if [ -s "$out" ]; then echo "[skip] $local (present, $(du -h "$out" | cut -f1))"; continue; fi
  echo "[get ] $local  <-  $remote"
  curl -fSL --retry 3 --retry-delay 2 -C - -o "$out" "$BASE/$remote" \
    && echo "[ok  ] $local  ($(du -h "$out" | cut -f1))" \
    || { echo "[FAIL] $local"; rm -f "$out"; }
done
echo "DONE. Files in $DEST:"
ls -lh "$DEST"
