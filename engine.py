from __future__ import annotations

from dataclasses import dataclass

from firewall import add_rule, build_ip_rule, build_port_rule, delete_rule
from logger import log_event
from rules import RuleEngine
from sniffer import PacketInfo


@dataclass
class ProcessResult:
    action: str
    direction: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None


class PacketProcessor:
    def __init__(self, rules: RuleEngine, logger) -> None:
        self._rules = rules
        self._logger = logger
        self._added_rules: list[tuple[str, list[str]]] = []
        self._rule_keys: set[str] = set()

    def handle(self, info: PacketInfo) -> ProcessResult:
        blocked = self._rules.is_blocked(
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
            self._add_rule(rule_spec)

            if info.dst_port is not None:
                port_rule = build_port_rule(info.dst_port, info.protocol, info.direction, ip=target_ip)
                if port_rule:
                    self._add_rule(port_rule)

            action = "BLOCK"

        log_event(
            self._logger,
            action=action,
            direction=info.direction,
            protocol=info.protocol,
            src_ip=info.src_ip,
            dst_ip=info.dst_ip,
            src_port=info.src_port,
            dst_port=info.dst_port,
        )

        return ProcessResult(
            action=action,
            direction=info.direction,
            protocol=info.protocol,
            src_ip=info.src_ip,
            dst_ip=info.dst_ip,
            src_port=info.src_port,
            dst_port=info.dst_port,
        )

    def cleanup(self) -> None:
        for chain, rule in reversed(self._added_rules):
            delete_rule(chain, rule)
        self._added_rules.clear()
        self._rule_keys.clear()

    def _add_rule(self, rule_spec: tuple[str, list[str]]) -> None:
        key = f"{rule_spec[0]} {' '.join(rule_spec[1])}"
        if key in self._rule_keys:
            return
        add_rule(rule_spec[0], rule_spec[1])
        self._rule_keys.add(key)
        self._added_rules.append(rule_spec)
