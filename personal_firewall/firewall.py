from __future__ import annotations

import subprocess


def _run_iptables(args: list[str]) -> None:
    subprocess.run(["iptables", *args], check=False)


def block_ip(ip: str, direction: str) -> None:
    chain = "INPUT" if direction == "IN" else "OUTPUT"
    _run_iptables(["-A", chain, "-s" if direction == "IN" else "-d", ip, "-j", "DROP"])


def block_port(port: int, protocol: str, direction: str) -> None:
    chain = "INPUT" if direction == "IN" else "OUTPUT"
    proto = protocol.lower()
    if proto not in {"tcp", "udp"}:
        return
    _run_iptables(["-A", chain, "-p", proto, "--dport", str(port), "-j", "DROP"])
