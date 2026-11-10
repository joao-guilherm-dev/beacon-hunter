from beacon_hunter.parsers import parse_ts, read_connections, detect_format


def test_parse_ts_variants():
    assert parse_ts("1700000000") == 1700000000.0
    assert parse_ts("1700000000000") == 1700000000.0
    assert parse_ts("2023-11-14T22:13:20Z") == 1700000000.0
    assert parse_ts("-") is None


def test_csv_with_aliases(tmp_path):
    p = tmp_path / "a.csv"
    p.write_text("time,src_ip,dest_ip,dst_port,protocol,sent_bytes\n1700000000,10.0.0.1,8.8.8.8,443,TCP,100\n")
    c = list(read_connections(str(p)))
    assert len(c) == 1 and c[0].dport == 443 and c[0].proto == "tcp" and c[0].bytes_out == 100


def test_zeek_tsv(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(
        "#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes\n"
        "#types\ttime\taddr\taddr\tport\tenum\tcount\tcount\n"
        "1700000000.5\t10.0.0.1\t1.2.3.4\t443\ttcp\t-\t20\n#close\t2023\n")
    assert detect_format(str(p)) == "zeek"
    c = list(read_connections(str(p)))
    assert len(c) == 1 and c[0].bytes_out == 0 and c[0].bytes_in == 20


def test_jsonl(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"ts": 1700000000.1, "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1", "id.resp_p": 443}\nlixo\n')
    assert len(list(read_connections(str(p)))) == 1
