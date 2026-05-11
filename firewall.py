from __future__ import annotations

import subprocess
from typing import Iterable


def _run_iptables(args: list[str]) -> None:
    subprocess.run(["iptables", *args], check=False)


def add_rule(chain: str, rule: Iterable[str]) -> None:
    _run_iptables(["-A", chain, *rule])


def delete_rule(chain: str, rule: Iterable[str]) -> None:
    _run_iptables(["-D", chain, *rule])


def build_ip_rule(ip: str, direction: str) -> tuple[str, list[str]]:
    chain = "INPUT" if direction == "IN" else "OUTPUT"
    rule = ["-s" if direction == "IN" else "-d", ip, "-j", "DROP"]
    return chain, rule


def build_port_rule(port: int, protocol: str, direction: str, ip: str | None = None) -> tuple[str, list[str]] | None:
    chain = "INPUT" if direction == "IN" else "OUTPUT"
    proto = protocol.lower()
    if proto not in {"tcp", "udp"}:
        return
    rule = ["-p", proto]
    if ip:
        rule.extend(["-s" if direction == "IN" else "-d", ip])
    rule.extend(["--dport", str(port), "-j", "DROP"])
    return chain, rule


def block_ip(ip: str, direction: str) -> tuple[str, list[str]]:
    chain, rule = build_ip_rule(ip, direction)
    add_rule(chain, rule)
    return chain, rule


def block_port(port: int, protocol: str, direction: str, ip: str | None = None) -> tuple[str, list[str]] | None:
    rule_spec = build_port_rule(port, protocol, direction, ip)
    if not rule_spec:
        return None
    chain, rule = rule_spec
    add_rule(chain, rule)
    return chain, rule
