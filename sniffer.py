from __future__ import annotations

from dataclasses import dataclass
import socket
from typing import Callable

import psutil
from scapy.all import IP, ICMP, TCP, UDP, sniff


@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    direction: str


def _get_local_ips() -> set[str]:
    local_ips: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address:
                local_ips.add(addr.address)
    return local_ips


def parse_packet(packet, local_ips: set[str]) -> PacketInfo | None:
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "OTHER"
    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol = "TCP"
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        protocol = "UDP"
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    if src_ip in local_ips:
        direction = "OUT"
    elif dst_ip in local_ips:
        direction = "IN"
    else:
        direction = "UNKNOWN"

    return PacketInfo(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        direction=direction,
    )


def start_sniffing(handler: Callable[[PacketInfo], None]) -> None:
    local_ips = _get_local_ips()

    def _callback(packet) -> None:
        info = parse_packet(packet, local_ips)
        if info:
            handler(info)

    sniff(prn=_callback, store=False)
