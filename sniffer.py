from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from scapy.all import IP, ICMP, TCP, UDP, sniff


@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    direction: str


def parse_packet(packet) -> PacketInfo | None:
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

    direction = "OUT" if ip_layer.src == packet[IP].src else "IN"

    return PacketInfo(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        direction=direction,
    )


def start_sniffing(handler: Callable[[PacketInfo], None]) -> None:
    def _callback(packet) -> None:
        info = parse_packet(packet)
        if info:
            handler(info)

    sniff(prn=_callback, store=False)
