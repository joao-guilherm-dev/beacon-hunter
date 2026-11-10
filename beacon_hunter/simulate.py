"""Gerador de tráfego SINTÉTICO para testes e demonstração.

Cria um CSV com tráfego benigno (navegação irregular, NTP, update horário)
e dois padrões de beaconing com jitter, para validar o detector.
Usa apenas IPs de documentação (RFC 5737). Não gera tráfego real.
"""
from __future__ import annotations

import csv
import random
from typing import List

from .models import Conn

HOURS = 12


def _beacon(rng, src, dst, port, interval, jitter, start, end, size, size_var):
    out, t = [], start
    while t < end:
        out.append(Conn(t, src, dst, port, "tcp",
                        max(40, int(rng.gauss(size, size_var))), rng.randint(200, 900)))
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return out


def generate(seed: int = 42, hours: int = HOURS) -> List[Conn]:
    rng = random.Random(seed)
    start, end = 1_700_000_000.0, 1_700_000_000.0 + hours * 3600
    conns: List[Conn] = []

    # 1) Beacon rápido: 60s, 20% jitter, HTTPS, payload ~ 250 bytes
    conns += _beacon(rng, "10.0.0.15", "203.0.113.50", 443, 60, 0.20, start, end, 250, 15)
    # 2) Beacon lento: 300s, 10% jitter, HTTP alternativo
    conns += _beacon(rng, "10.0.0.22", "198.51.100.23", 8080, 300, 0.10, start, end, 180, 10)
    # 3) Benigno quase regular: checagem de update a cada 1h (payload variável)
    conns += _beacon(rng, "10.0.0.31", "192.0.2.80", 443, 3600, 0.02, start, end, 1200, 900)
    # 4) NTP (porta 123 - allowlist padrão)
    conns += _beacon(rng, "10.0.0.31", "192.0.2.123", 123, 64, 0.01, start, end, 48, 0)

    # 5) Navegação humana: rajadas e pausas aleatórias para vários destinos
    for host in range(1, 9):
        dst = f"192.0.2.{100 + host}"
        t = start + rng.uniform(0, 600)
        while t < end:
            for _ in range(rng.randint(1, 12)):  # rajada
                conns.append(Conn(t, "10.0.0.40", dst, 443, "tcp",
                                  rng.randint(300, 40000), rng.randint(1000, 900000)))
                t += rng.expovariate(1 / 8)
            t += rng.expovariate(1 / 900)         # pausa longa

    conns.sort(key=lambda c: c.ts)
    return conns


def write_csv(path: str, conns: List[Conn]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "src", "dst", "dport", "proto", "bytes_out", "bytes_in"])
        for c in conns:
            w.writerow([f"{c.ts:.3f}", c.src, c.dst, c.dport, c.proto, c.bytes_out, c.bytes_in])
