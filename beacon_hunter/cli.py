from __future__ import annotations

import argparse
import sys

from . import __version__
from .allowlist import Allowlist
from .detector import Config, analyze
from .parsers import read_connections
from .report import to_console, to_csv, to_html, to_json
from .simulate import generate, write_csv


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="beacon-hunter",
        description="Detecção de beaconing (C2) em logs de conexão de rede.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analisa um arquivo de log")
    a.add_argument("file", help="CSV, Zeek conn.log (TSV) ou JSON lines")
    a.add_argument("--format", choices=["auto", "csv", "zeek", "jsonl"], default="auto")
    a.add_argument("--min-conns", type=int, default=10, help="mínimo de conexões por par (padrão 10)")
    a.add_argument("--min-duration", type=float, default=600, help="duração mínima em segundos (padrão 600)")
    a.add_argument("--threshold", type=float, default=55, help="score mínimo 0-100 (padrão 55)")
    a.add_argument("--jitter", type=float, default=0.25, help="tolerância de jitter (padrão 0.25)")
    a.add_argument("--include-internal", action="store_true", help="inclui destinos privados/internos")
    a.add_argument("--allowlist", help="arquivo de allowlist (dst/src/port)")
    a.add_argument("--json", dest="json_out", help="salva JSON")
    a.add_argument("--csv", dest="csv_out", help="salva CSV")
    a.add_argument("--html", dest="html_out", help="salva relatório HTML")

    g = sub.add_parser("generate-sample", help="gera tráfego sintético para teste")
    g.add_argument("output", help="CSV de saída")
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--hours", type=int, default=12)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "generate-sample":
        conns = generate(args.seed, args.hours)
        write_csv(args.output, conns)
        print(f"{len(conns)} conexões sintéticas salvas em {args.output}")
        return 0

    cfg = Config(min_connections=args.min_conns, min_duration_s=args.min_duration,
                 threshold=args.threshold, jitter_tolerance=args.jitter,
                 include_internal=args.include_internal)
    al = Allowlist.from_file(args.allowlist) if args.allowlist else Allowlist()
    try:
        conns = list(read_connections(args.file, args.format))
    except (OSError, ValueError) as e:
        print(f"Erro ao ler {args.file}: {e}", file=sys.stderr)
        return 2

    print(f"[+] {len(conns)} conexões lidas de {args.file}")
    findings = analyze(conns, cfg, al)
    print(to_console(findings))

    if args.json_out:
        to_json(findings, args.json_out)
    if args.csv_out:
        to_csv(findings, args.csv_out)
    if args.html_out:
        to_html(findings, args.html_out, args.file)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
