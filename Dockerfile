# PacketIQ — AI PCAP Forensics & SOC Intelligence
FROM python:3.12-slim

# libpcap is optional (file parsing is pure Python); build tools for cryptography wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (better layer caching)
COPY setup.py requirements.txt README.md ./
COPY packetiq ./packetiq
RUN pip install --no-cache-dir -e .

# Web app port
EXPOSE 8080

# Bind to all interfaces inside the container
ENV PACKETIQ_FEED_DIR=/data/feeds
VOLUME ["/data"]

ENTRYPOINT ["packetiq"]
CMD ["webapp", "--host", "0.0.0.0", "--port", "8080", "--no-browser"]
