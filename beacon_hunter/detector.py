"""Motor de detecção de beaconing.

Ideia central: implantes de malware (Cobalt Strike, Sliver, Meterpreter,
Empire...) fazem "check-in" no servidor C2 em intervalos quase fixos, com
um pouco de jitter. Tráfego humano/legítimo é irregular (rajadas, pausas
longas). Medimos essa regularidade em várias dimensões e combinamos num score.

Sinais usados (pesos em Config):
  1. Regularidade dos intervalos  -> CV e CV robusto (MAD)
  2. Intervalo dominante          -> % dos intervalos perto da mediana
  3. Consistência de tamanho      -> payloads parecidos a cada check-in
  4. Cobertura temporal           -> atividade distribuída ao longo da captura
  5. Volume/persistência          -> nº de conexões e duração suficientes
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from . import stats
from .allowlist import Allowlist
from .models import Conn, Finding


@dataclass
class Config:
    min_connections: int = 10        # mínimo de conexões por par
    min_duration_s: float = 600.0    # mínimo de duração observada (10 min)
    merge_window_s: float = 1.0      # conexões < 1s viram uma só (rajadas)
    jitter_tolerance: float = 0.25   # tolerância p/ intervalo dominante
    threshold: float = 55.0          # score mínimo para reportar
    include_internal: bool = False   # analisar destinos privados?
    coverage_windows: int = 20       # nº de janelas p/ cobertura temporal
    weights: Dict[str, float] = field(default_factory=lambda: {
        "regularity": 35.0,
        "dominant": 25.0,
        "size": 15.0,
        "coverage": 15.0,
        "persistence": 10.0,
    })


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]


def _is_internal(ip: str) -> bool:
    """Destino interno/não roteável. Não usa is_private de propósito: ele marca
    como privadas as faixas de documentação (RFC 5737), usadas nos exemplos."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL_NETS if n.version == a.version)


def _merge_bursts(ts: List[float], window: float) -> List[int]:
    """Retorna índices das conexões que iniciam um novo 'evento'."""
    keep, last = [], None
    for i, t in enumerate(ts):
        if last is None or t - last >= window:
            keep.append(i)
        last = t
    return keep


def severity(score: float) -> str:
    if score >= 80:
        return "ALTO"
    if score >= 65:
        return "MÉDIO"
    return "BAIXO"


def _coverage(ts: List[float], windows: int) -> float:
    if len(ts) < 2 or windows < 1:
        return 0.0
    t0, t1 = ts[0], ts[-1]
    span = t1 - t0
    if span <= 0:
        return 0.0
    hit = set()
    for t in ts:
        hit.add(min(windows - 1, int((t - t0) / span * windows)))
    return len(hit) / windows


def score_group(conns: List[Conn], cfg: Config) -> Finding | None:
    conns = sorted(conns, key=lambda c: c.ts)
    ts_all = [c.ts for c in conns]
    idx = _merge_bursts(ts_all, cfg.merge_window_s)
    ev = [conns[i] for i in idx]
    ts = [c.ts for c in ev]

    if len(ts) < cfg.min_connections:
        return None
    duration = ts[-1] - ts[0]
    if duration < cfg.min_duration_s:
        return None

    d = stats.deltas(ts)
    if not d or stats.median(d) <= 0:
        return None

    cv = stats.cv(d)
    rcv = stats.robust_cv(d)
    dom = stats.dominant_ratio(d, cfg.jitter_tolerance)
    sizes = [float(c.bytes_out) for c in ev]
    size_cv = stats.cv(sizes) if stats.mean(sizes) > 0 else 1.0
    cov = _coverage(ts, cfg.coverage_windows)

    w = cfg.weights
    # 1) Regularidade: CV 0 -> 1.0 ; CV >= 1 -> 0.0. Usa o melhor entre CV e CV robusto
    reg = stats.clamp01(1.0 - min(cv, rcv * 1.5 if rcv != float("inf") else cv))
    # 2) Intervalo dominante: 50% -> 0, 100% -> 1
    dom_s = stats.clamp01((dom - 0.5) / 0.5)
    # 3) Tamanho: CV 0 -> 1.0 ; CV >= 1 -> 0.0
    size_s = stats.clamp01(1.0 - size_cv)
    # 4) Cobertura temporal
    cov_s = stats.clamp01(cov)
    # 5) Persistência: 10 conexões -> 0, 60+ conexões -> 1
    per_s = stats.clamp01((len(ts) - cfg.min_connections) / 50.0)

    score = (reg * w["regularity"] + dom_s * w["dominant"] + size_s * w["size"]
             + cov_s * w["coverage"] + per_s * w["persistence"])
    total_w = sum(w.values())
    score = round(100.0 * score / total_w, 1)

    reasons = []
    med = stats.median(d)
    if reg >= 0.7:
        reasons.append(f"intervalos muito regulares (~{med:.0f}s, CV={cv:.2f})")
    elif reg >= 0.5:
        reasons.append(f"intervalos relativamente regulares (~{med:.0f}s, CV={cv:.2f})")
    if dom >= 0.8:
        reasons.append(f"{dom:.0%} dos intervalos próximos da mediana (jitter ≤ {cfg.jitter_tolerance:.0%})")
    if size_s >= 0.7:
        reasons.append("payloads de tamanho consistente (padrão de check-in)")
    if cov >= 0.9:
        reasons.append("atividade contínua durante toda a captura")
    if len(ts) >= 40:
        reasons.append(f"alta persistência ({len(ts)} conexões em {duration/3600:.1f}h)")

    first = ev[0]
    return Finding(
        src=first.src, dst=first.dst, dport=first.dport, proto=first.proto,
        connections=len(ts), duration_s=round(duration, 1),
        mean_interval_s=round(stats.mean(d), 2), median_interval_s=round(med, 2),
        cv=round(cv, 3), robust_cv=round(rcv, 3), dominant_ratio=round(dom, 3),
        size_cv=round(size_cv, 3), coverage=round(cov, 3),
        score=score, severity=severity(score), reasons=reasons,
    )


def analyze(conns: Iterable[Conn], cfg: Config | None = None,
            allowlist: Allowlist | None = None) -> List[Finding]:
    cfg = cfg or Config()
    allowlist = allowlist or Allowlist()
    groups: Dict[Tuple[str, str, int, str], List[Conn]] = defaultdict(list)
    for c in conns:
        if not cfg.include_internal and _is_internal(c.dst):
            continue
        if allowlist.is_allowed(c):
            continue
        groups[(c.src, c.dst, c.dport, c.proto)].append(c)

    findings = []
    for g in groups.values():
        f = score_group(g, cfg)
        if f and f.score >= cfg.threshold:
            findings.append(f)
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
