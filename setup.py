from setuptools import setup, find_packages

setup(
    name="packetiq",
    version="1.0.0",
    author="PacketIQ SOC Copilot",
    description="AI PCAP Forensics & SOC Copilot",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "packetiq": [
            "detection/data/*.csv",
            "detection/data/yara_rules/*",
            "enrichment/data/*",
            "webapp/templates/*.html",
            "dashboard/templates/*.html",
        ],
    },
    python_requires=">=3.10",   # security-patched deps (requests/python-multipart/urllib3) need 3.10+
    install_requires=[
        "scapy>=2.5.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "python-dotenv>=1.2.2",          # security: GHSA-mf9w-mj56-hr94
        "tabulate>=0.9.0",
        "colorama>=0.4.6",
        "requests>=2.33.0",              # security: GHSA-gc5v-m9x4-r6x2
        "urllib3>=2.7.0",                # security: PYSEC-2026-141/142
        "anthropic>=0.40.0",
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.29.0",
        "python-multipart>=0.0.31",      # security: multipart DoS advisories
        "google-genai>=1.0.0",
        "groq>=0.11.0",
        'tomli>=2.0.0; python_version < "3.11"',
        "cryptography>=44.0.1",          # security: GHSA-537c-gmf6-5ccf and prior
    ],
    extras_require={
        "dev": ["pytest>=8.0.0", "pyyaml>=6.0.0", "pysigma>=0.11.0", "yara-python>=4.3.0", "ruff", "mypy"],
        "yara": ["yara-python>=4.3.0"],
        "geoip": ["geoip2>=4.7.0"],
    },
    entry_points={
        "console_scripts": [
            "packetiq=packetiq.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
