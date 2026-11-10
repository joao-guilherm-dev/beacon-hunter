"""Funções estatísticas em Python puro (sem dependências externas)."""
from __future__ import annotations

import math
from typing import List, Sequence


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def stdev(xs: Sequence[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def mad(xs: Sequence[float]) -> float:
    """Median Absolute Deviation."""
    if not xs:
        return 0.0
    m = median(xs)
    return median([abs(x - m) for x in xs])


def cv(xs: Sequence[float]) -> float:
    """Coeficiente de variação (desvio padrão / média)."""
    m = mean(xs)
    return stdev(xs) / m if m > 0 else float("inf")


def robust_cv(xs: Sequence[float]) -> float:
    """CV robusto a outliers: 1.4826 * MAD / mediana."""
    m = median(xs)
    return (1.4826 * mad(xs)) / m if m > 0 else float("inf")


def deltas(sorted_ts: Sequence[float]) -> List[float]:
    return [b - a for a, b in zip(sorted_ts, sorted_ts[1:])]


def dominant_ratio(xs: Sequence[float], tolerance: float = 0.25) -> float:
    """Fração dos valores dentro de ±tolerance (relativo) da mediana.

    Beacons com jitter de até 25% continuam com razão alta; tráfego humano,
    não.
    """
    if not xs:
        return 0.0
    m = median(xs)
    if m <= 0:
        return 0.0
    hits = sum(1 for x in xs if abs(x - m) <= tolerance * m)
    return hits / len(xs)


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))
