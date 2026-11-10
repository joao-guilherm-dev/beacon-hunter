# 🔎 Beacon Hunter — Detecção de Beaconing (C2)

[![tests](https://github.com/joao-guilherm-dev/beacon-hunter/actions/workflows/tests.yml/badge.svg)](https://github.com/joao-guilherm-dev/beacon-hunter/actions)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![deps](https://img.shields.io/badge/dependências-zero-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Ferramenta **defensiva (blue team)** que identifica **beaconing**: o padrão de comunicação repetitivo que implantes de malware usam para fazer *check-in* em servidores de Comando e Controle (C2).

Funciona sobre **logs de conexão** (Zeek `conn.log`, firewall, proxy, NetFlow exportado em CSV) — não captura nem gera tráfego.

---

## 🧠 Como funciona

Implantes (Cobalt Strike, Sliver, Meterpreter, Empire…) consultam o C2 em intervalos quase fixos, geralmente com algum *jitter* para tentar se esconder. Humanos e aplicações legítimas geram tráfego em **rajadas e pausas irregulares**.

O detector agrupa as conexões por `(origem, destino, porta, protocolo)` e mede a regularidade em 5 dimensões, combinando num **score de 0 a 100**:

| Sinal | O que mede | Peso |
|---|---|---|
| **Regularidade** | Coeficiente de variação (CV) e CV robusto (MAD) dos intervalos | 35 |
| **Intervalo dominante** | % de intervalos próximos da mediana (tolera jitter configurável) | 25 |
| **Tamanho consistente** | Variação do tamanho dos payloads enviados | 15 |
| **Cobertura temporal** | Atividade distribuída em toda a janela de captura | 15 |
| **Persistência** | Nº de conexões observadas | 10 |

Tratamentos para reduzir ruído: fusão de rajadas (conexões < 1s viram um evento), descarte de destinos internos por padrão, mínimo de conexões/duração e **allowlist** (NTP, updates, monitoramento).

### Severidade
`ALTO` ≥ 80 · `MÉDIO` ≥ 65 · `BAIXO` ≥ 55 (limiar ajustável com `--threshold`)

## 🗺️ MITRE ATT&CK

| Técnica | Relação |
|---|---|
| [T1071](https://attack.mitre.org/techniques/T1071/) — Application Layer Protocol | C2 sobre HTTP/HTTPS/DNS |
| [T1029](https://attack.mitre.org/techniques/T1029/) — Scheduled Transfer | comunicação em horários/intervalos definidos |
| [T1573](https://attack.mitre.org/techniques/T1573/) — Encrypted Channel | beacon sobre TLS: o detector não depende do conteúdo |
| [T1008](https://attack.mitre.org/techniques/T1008/) — Fallback Channels | múltiplos destinos com o mesmo padrão (use o JSON/CSV para correlacionar) |

## 🚀 Instalação e uso

Sem dependências externas (somente biblioteca padrão). Python 3.10+.

```bash
git clone https://github.com/joao-guilherm-dev/beacon-hunter.git
cd beacon-hunter

# 1) gerar tráfego SINTÉTICO de demonstração (IPs de documentação RFC 5737)
python -m beacon_hunter generate-sample examples/sample_traffic.csv

# 2) analisar
python -m beacon_hunter analyze examples/sample_traffic.csv --html report.html

# analisar um conn.log do Zeek, com allowlist e saídas em JSON/CSV
python -m beacon_hunter analyze conn.log --allowlist examples/allowlist.example.txt \
    --json achados.json --csv achados.csv
```

Código de saída: `1` se houver achados, `0` se não — fácil de usar em pipelines/cron.

### Saída de exemplo

```
SEV    SCORE  ORIGEM          DESTINO            PORTA CONNS INTERVALO    CV
--------------------------------------------------------------------------------
ALTO    97.2  10.0.0.22       198.51.100.23       8080   144      5min  0.06
         -> intervalos muito regulares (~300s, CV=0.06)
         -> 100% dos intervalos próximos da mediana (jitter ≤ 25%)
         -> payloads de tamanho consistente (padrão de check-in)
ALTO    95.2  10.0.0.15       203.0.113.50         443   715      1min  0.11
MÉDIO   78.2  10.0.0.31       192.0.2.80           443    13     60min  0.01   <- falso positivo (update horário)
```

O último achado é um **falso positivo proposital** (checagem de update): resolva com allowlist (`dst 192.0.2.80/32`).

### Formatos de entrada
- **CSV** com cabeçalho — aceita aliases (`timestamp/ts/time`, `src/src_ip/id.orig_h`, `dst/dest_ip/id.resp_h`, `dport/dst_port/id.resp_p`, `bytes_out/orig_bytes`…)
- **Zeek `conn.log`** (TSV com `#fields`)
- **JSON lines** (Zeek JSON ou equivalente)

Timestamps em epoch (s ou ms) ou ISO 8601.

### Principais opções

| Opção | Padrão | Descrição |
|---|---|---|
| `--min-conns` | 10 | mínimo de conexões por par |
| `--min-duration` | 600 | duração mínima observada (s) |
| `--threshold` | 55 | score mínimo para reportar |
| `--jitter` | 0.25 | tolerância de jitter p/ intervalo dominante |
| `--include-internal` | off | inclui destinos privados (movimento lateral/pivô) |
| `--allowlist` | — | arquivo com `dst`, `src`, `port` a ignorar |

## 🧪 Testes

```bash
pip install pytest
pytest -q
```

Cobrem: estatística, beacon com jitter, beacon lento, tráfego humano, fusão de rajadas, allowlist, destinos internos, parsers (CSV/Zeek/JSONL) e um teste ponta a ponta com o dataset sintético.

## 📁 Estrutura

```
beacon_hunter/
├── detector.py    # score e agrupamento
├── stats.py       # CV, MAD, mediana (stdlib)
├── parsers.py     # CSV, Zeek, JSONL
├── allowlist.py   # redução de falsos positivos
├── report.py      # console, JSON, CSV, HTML
├── simulate.py    # gerador de tráfego sintético
└── cli.py
tests/
examples/
```

## ⚠️ Limitações

- **Jitter alto** (> 50%) ou intervalos aleatórios reduzem o score — ajuste `--jitter` e `--threshold`, e considere análises complementares.
- **Falsos positivos** são esperados em tráfego automatizado legítimo (updates, telemetria, heartbeat de EDR/RMM, apps de chat). Use allowlist.
- Beacons **muito lentos** (horas) exigem janelas de captura longas (dias).
- Analisa metadados de conexão; **não** inspeciona conteúdo. É um sinal de *hunting*, não prova de comprometimento: valide com EDR, DNS, reputação de IP e análise de host.
- Roadmap: análise de DNS (tunneling/DGA), JA3/JA3S, correlação multi-destino e exportação de regras Sigma.

## 📄 Licença
MIT — veja [LICENSE](LICENSE).
