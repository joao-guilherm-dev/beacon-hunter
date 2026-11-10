"""Leitura de logs: CSV genérico, Zeek conn.log (TSV) e Zeek JSON lines."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from typing import Iterator, Optional

from .models import Conn

_ALIASES = {
    "ts": ("ts", "timestamp", "time", "_time", "@timestamp", "datetime"),
    "src": ("src", "src_ip", "source", "id.orig_h", "source_ip", "client"),
    "dst": ("dst", "dst_ip", "destination", "id.resp_h", "dest_ip", "destination_ip", "server"),
    "dport": ("dport", "dst_port", "dest_port", "id.resp_p", "destination_port", "port"),
    "proto": ("proto", "protocol"),
    "bytes_out": ("bytes_out", "orig_bytes", "sent_bytes", "bytes_sent", "out_bytes"),
    "bytes_in": ("bytes_in", "resp_bytes", "recv_bytes", "bytes_received", "in_bytes"),
}


def parse_ts(value) -> Optional[float]:
    """Aceita epoch (s ou ms) e ISO 8601."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s == "-":
        return None
    try:
        f = float(s)
        return f / 1000.0 if f > 1e11 else f
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.timestamp()
    except ValueError:
        return None


def _int(value) -> int:
    try:
        s = str(value).strip()
        return 0 if s in ("", "-", "(empty)") else int(float(s))
    except (ValueError, TypeError):
        return 0


def _pick(row: dict, key: str):
    for alias in _ALIASES[key]:
        if alias in row and row[alias] not in (None, ""):
            return row[alias]
    return None


def _row_to_conn(row: dict) -> Optional[Conn]:
    ts = parse_ts(_pick(row, "ts"))
    src, dst = _pick(row, "src"), _pick(row, "dst")
    if ts is None or not src or not dst:
        return None
    return Conn(
        ts=ts,
        src=str(src).strip(),
        dst=str(dst).strip(),
        dport=_int(_pick(row, "dport")),
        proto=str(_pick(row, "proto") or "tcp").lower(),
        bytes_out=_int(_pick(row, "bytes_out")),
        bytes_in=_int(_pick(row, "bytes_in")),
    )


def detect_format(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = ""
        for line in fh:
            if line.strip():
                first = line.strip()
                break
    if first.startswith("#separator") or first.startswith("#fields"):
        return "zeek"
    if first.startswith("{"):
        return "jsonl"
    return "csv"


def _read_csv(path: str) -> Iterator[Conn]:
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            c = _row_to_conn({k.strip(): v for k, v in row.items() if k})
            if c:
                yield c


def _read_jsonl(path: str) -> Iterator[Conn]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                c = _row_to_conn(json.loads(line))
            except json.JSONDecodeError:
                continue
            if c:
                yield c


def _read_zeek(path: str) -> Iterator[Conn]:
    fields: list = []
    sep = "\t"
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                token = line.split(" ", 1)[1].strip()
                sep = bytes(token, "utf-8").decode("unicode_escape") if token.startswith("\\x") else "\t"
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#") or not line:
                continue
            elif fields:
                c = _row_to_conn(dict(zip(fields, line.split(sep))))
                if c:
                    yield c


def read_connections(path: str, fmt: str = "auto") -> Iterator[Conn]:
    if fmt == "auto":
        fmt = detect_format(path)
    readers = {"csv": _read_csv, "jsonl": _read_jsonl, "zeek": _read_zeek}
    if fmt not in readers:
        raise ValueError(f"Formato desconhecido: {fmt}")
    return readers[fmt](path)
