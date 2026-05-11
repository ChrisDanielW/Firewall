from __future__ import annotations

import os
import sys
from pathlib import Path

from engine import PacketProcessor
from logger import setup_logger
from rules import RuleEngine
from sniffer import PacketInfo, start_sniffing


def ensure_root() -> None:
    if os.geteuid() != 0:
        print("This program must be run as root. Try: sudo python3 main.py")
        sys.exit(1)


def handle_packet(info: PacketInfo, processor: PacketProcessor) -> None:
    result = processor.handle(info)
    print(
        f"{result.action} {result.direction} {result.protocol} "
        f"{result.src_ip}:{result.src_port or '-'} -> {result.dst_ip}:{result.dst_port or '-'}"
    )


def main() -> None:
    ensure_root()

    rules = RuleEngine()
    rules.load_blacklist(Path("blacklist.txt"))

    logger = setup_logger()
    print("Starting personal firewall. Press Ctrl+C to stop.")

    processor = PacketProcessor(rules, logger)

    def _handler(info: PacketInfo) -> None:
        handle_packet(info, processor)

    try:
        start_sniffing(_handler)
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        processor.cleanup()


if __name__ == "__main__":
    main()
