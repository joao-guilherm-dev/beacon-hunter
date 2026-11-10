"""Saídas: console, JSON, CSV e HTML autocontido."""
from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from typing import List

from .models import Finding


def _fmt_dur(s: float) -> str:
    if s >= 3600:
        return f"{s/3600:.1f}h"
    if s >= 60:
        return f"{s/60:.0f}min"
    return f"{s:.0f}s"


def to_console(findings: List[Finding]) -> str:
    if not findings:
        return "Nenhum beaconing suspeito encontrado."
    lines = [f"{'SEV':<6} {'SCORE':>5}  {'ORIGEM':<15} {'DESTINO':<18} {'PORTA':>5} {'CONNS':>5} {'INTERVALO':>9} {'CV':>5}"]
    lines.append("-" * 80)
    for f in findings:
        lines.append(f"{f.severity:<6} {f.score:>5.1f}  {f.src:<15} {f.dst:<18} {f.dport:>5} "
                     f"{f.connections:>5} {_fmt_dur(f.median_interval_s):>9} {f.cv:>5.2f}")
        for r in f.reasons:
            lines.append(f"         -> {r}")
    return "\n".join(lines)


def to_json(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, ensure_ascii=False, indent=2)


def to_csv(findings: List[Finding], path: str) -> None:
    cols = ["severity", "score", "src", "dst", "dport", "proto", "connections",
            "duration_s", "median_interval_s", "mean_interval_s", "cv", "robust_cv",
            "dominant_ratio", "size_cv", "coverage"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            w.writerow(f.to_dict())


_COLORS = {"ALTO": "#e5484d", "MÉDIO": "#f5a524", "BAIXO": "#3e9bff"}


def to_html(findings: List[Finding], path: str, source: str = "") -> None:
    rows = []
    for f in findings:
        color = _COLORS.get(f.severity, "#888")
        reasons = "".join(f"<li>{html.escape(r)}</li>" for r in f.reasons)
        rows.append(f"""
<tr>
 <td><span class="sev" style="background:{color}">{f.severity}</span></td>
 <td><div class="bar"><div style="width:{f.score}%;background:{color}"></div></div>{f.score}</td>
 <td>{html.escape(f.src)}</td><td>{html.escape(f.dst)}:{f.dport}/{f.proto}</td>
 <td>{f.connections}</td><td>{_fmt_dur(f.median_interval_s)}</td><td>{f.cv:.2f}</td>
 <td><ul>{reasons}</ul></td>
</tr>""")
    body = "".join(rows) or '<tr><td colspan="8">Nenhum beaconing suspeito encontrado.</td></tr>'
    doc = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beacon Hunter — Relatório</title>
<style>
:root{{--bg:#0d1117;--fg:#c9d1d9;--card:#161b22;--bd:#30363d;--mut:#8b949e}}
@media (prefers-color-scheme: light){{:root{{--bg:#fff;--fg:#1f2328;--card:#f6f8fa;--bd:#d0d7de;--mut:#656d76}}}}
body{{font-family:ui-monospace,Consolas,monospace;background:var(--bg);color:var(--fg);margin:0;padding:24px}}
h1{{margin:0 0 4px}} .mut{{color:var(--mut);font-size:13px;margin-bottom:20px}}
.wrap{{overflow-x:auto}}
table{{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--bd)}}
th,td{{padding:8px 10px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:top;font-size:13px}}
th{{color:var(--mut)}} ul{{margin:0;padding-left:16px}}
.sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}}
.bar{{width:90px;height:6px;background:var(--bd);border-radius:3px;margin-bottom:4px}}
.bar div{{height:100%;border-radius:3px}}
</style></head><body>
<h1>🔎 Beacon Hunter</h1>
<div class="mut">Gerado em {datetime.now():%d/%m/%Y %H:%M} · fonte: {html.escape(source)} · {len(findings)} achado(s)</div>
<div class="wrap"><table>
<tr><th>Sev.</th><th>Score</th><th>Origem</th><th>Destino</th><th>Conns</th><th>Intervalo</th><th>CV</th><th>Motivos</th></tr>
{body}
</table></div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
