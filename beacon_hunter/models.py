from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List


@dataclass(frozen=True)
class Conn:
    """Uma conexão de rede normalizada."""
    ts: float          # epoch (segundos)
    src: str
    dst: str
    dport: int
    proto: str = "tcp"
    bytes_out: int = 0
    bytes_in: int = 0


@dataclass
class Finding:
    """Resultado da análise de um par (src, dst, porta, proto)."""
    src: str
    dst: str
    dport: int
    proto: str
    connections: int
    duration_s: float
    mean_interval_s: float
    median_interval_s: float
    cv: float                 # coeficiente de variação dos intervalos
    robust_cv: float          # 1.4826 * MAD / mediana
    dominant_ratio: float     # % de intervalos próximos da mediana
    size_cv: float            # variação do tamanho dos payloads
    coverage: float           # % das janelas de tempo com atividade
    score: float
    severity: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
