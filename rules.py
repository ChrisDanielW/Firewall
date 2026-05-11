from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RuleEngine:
    blocked_ips: set[str] = field(default_factory=set)
    blocked_ports: set[int] = field(default_factory=set)
    blocked_protocols: set[str] = field(default_factory=set)

    def load_blacklist(self, path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            self.blocked_ips.add(entry)

    def is_blocked(self, src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None, protocol: str) -> bool:
        if protocol in self.blocked_protocols:
            return True
        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            return True
        if src_port is not None and src_port in self.blocked_ports:
            return True
        if dst_port is not None and dst_port in self.blocked_ports:
            return True
        return False
