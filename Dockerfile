# PacketIQ — AI PCAP Forensics & SOC Intelligence
FROM python:3.12-slim

# libpcap is optional (file parsing is pure Python); build tools for cryptography wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Packaging is PEP 621 / pyproject-only — there has been no setup.py since the
# move off setuptools scripts, so the previous COPY failed on the first build
# step. Dependencies and package data both come from pyproject.
#
# LICENSE is copied because pyproject declares `license-files = ["LICENSE"]`
# under PEP 639. Without it setuptools reports `Pattern 'LICENSE' did not match
# any files`, builds the wheel anyway with no licence metadata in it, and warns
# that it stops supporting the build in February 2027. The image was therefore
# shipping an unlicensed-looking package with an expiry date on its own build.
COPY pyproject.toml README.md LICENSE ./
COPY packetiq ./packetiq
# Not editable: an editable install is silently skipped by some Python 3.12+
# builds, which leaves the `packetiq` entry point missing at runtime.
RUN pip install --no-cache-dir .

# Web app port
EXPOSE 8080

# Bind to all interfaces inside the container
ENV PACKETIQ_FEED_DIR=/data/feeds
VOLUME ["/data"]

ENTRYPOINT ["packetiq"]
CMD ["webapp", "--host", "0.0.0.0", "--port", "8080", "--no-browser"]
