"""Alternative inputs — analyze flow logs (Zeek, NetFlow/IPFIX) without a raw PCAP."""

from packetiq.inputs.netflow import load_netflow
from packetiq.inputs.zeek import load_conn_log

__all__ = ["load_conn_log", "load_netflow"]
