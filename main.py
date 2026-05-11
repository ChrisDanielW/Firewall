from __future__ import annotations

import os
import sys
from pathlib import Path

from firewall import add_rule, build_ip_rule, build_port_rule, delete_rule
from logger import log_event, setup_logger
from rules import RuleEngine
from sniffer import PacketInfo, start_sniffing


def ensure_root() -> None:
    if os.geteuid() != 0:
        print("This program must be run as root. Try: sudo python3 main.py")
        sys.exit(1)


def handle_packet(info: PacketInfo, rules: RuleEngine, logger, added_rules: list[tuple[str, list[str]]], rule_keys: set[str]) -> None:
    blocked = rules.is_blocked(
        src_ip=info.src_ip,
        dst_ip=info.dst_ip,
        src_port=info.src_port,
        dst_port=info.dst_port,
        protocol=info.protocol,
    )

    action = "ALLOW"
    if blocked and info.direction in {"IN", "OUT"}:
        target_ip = info.src_ip if info.direction == "IN" else info.dst_ip
        rule_spec = build_ip_rule(target_ip, info.direction)
        rule_key = f"{rule_spec[0]} {' '.join(rule_spec[1])}"
        if rule_key not in rule_keys:
            add_rule(rule_spec[0], rule_spec[1])
            rule_keys.add(rule_key)
            added_rules.append(rule_spec)

        if info.dst_port is not None:
            port_rule = build_port_rule(info.dst_port, info.protocol, info.direction, ip=target_ip)
            if port_rule:
                port_key = f"{port_rule[0]} {' '.join(port_rule[1])}"
                if port_key not in rule_keys:
                    add_rule(port_rule[0], port_rule[1])
                    rule_keys.add(port_key)
                    added_rules.append(port_rule)

        action = "BLOCK"

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

    added_rules: list[tuple[str, list[str]]] = []
    rule_keys: set[str] = set()

    def _handler(info: PacketInfo) -> None:
        handle_packet(info, rules, logger, added_rules, rule_keys)

    try:
        start_sniffing(_handler)
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        for chain, rule in reversed(added_rules):
            delete_rule(chain, rule)


if __name__ == "__main__":
    main()
