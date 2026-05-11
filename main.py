from __future__ import annotations

import os
import sys
from pathlib import Path

from firewall import block_ip, block_port
from logger import log_event, setup_logger
from rules import RuleEngine
from sniffer import PacketInfo, start_sniffing


def ensure_root() -> None:
    if os.geteuid() != 0:
        print("This program must be run as root. Try: sudo python3 main.py")
        sys.exit(1)


def handle_packet(info: PacketInfo, rules: RuleEngine, logger) -> None:
    blocked = rules.is_blocked(
        src_ip=info.src_ip,
        dst_ip=info.dst_ip,
        src_port=info.src_port,
        dst_port=info.dst_port,
        protocol=info.protocol,
    )

    if blocked:
        block_ip(info.src_ip, info.direction)
        if info.dst_port is not None:
            block_port(info.dst_port, info.protocol, info.direction)
        action = "BLOCK"
    else:
        action = "ALLOW"

    log_event(
        logger,
        action=action,
        direction=info.direction,
        protocol=info.protocol,
        src_ip=info.src_ip,
        dst_ip=info.dst_ip,
        src_port=info.src_port,
        dst_port=info.dst_port,
    )

    print(
        f"{action} {info.direction} {info.protocol} "
        f"{info.src_ip}:{info.src_port or '-'} -> {info.dst_ip}:{info.dst_port or '-'}"
    )


def main() -> None:
    ensure_root()

    rules = RuleEngine()
    rules.load_blacklist(Path("blacklist.txt"))

    logger = setup_logger()
    print("Starting personal firewall. Press Ctrl+C to stop.")

    def _handler(info: PacketInfo) -> None:
        handle_packet(info, rules, logger)

    try:
        start_sniffing(_handler)
    except KeyboardInterrupt:
        print("Stopping.")


if __name__ == "__main__":
    main()
