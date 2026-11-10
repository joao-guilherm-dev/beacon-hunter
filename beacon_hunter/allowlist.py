"""Allowlist para reduzir falsos positivos (NTP, updates, monitoramento...)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List

from .models import Conn


@dataclass
class Allowlist:
    networks: List = field(default_factory=list)   # CIDRs/IPs de destino
    ports: set = field(default_factory=lambda: {123})  # NTP por padrão
    sources: List = field(default_factory=list)    # CIDRs/IPs de origem

    @classmethod
    def from_file(cls, path: str) -> "Allowlist":
        """Formato (um por linha, # comentário):
            dst 8.8.8.0/24
            src 10.0.0.5
            port 123
        """
        al = cls(ports=set())
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                kind, _, value = line.partition(" ")
                value = value.strip()
                if kind == "dst":
                    al.networks.append(ipaddress.ip_network(value, strict=False))
                elif kind == "src":
                    al.sources.append(ipaddress.ip_network(value, strict=False))
                elif kind == "port":
                    al.ports.add(int(value))
        return al

    @staticmethod
    def _in(ip: str, nets: list) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)

    def is_allowed(self, c: Conn) -> bool:
        if c.dport in self.ports:
            return True
        return self._in(c.dst, self.networks) or self._in(c.src, self.sources)
