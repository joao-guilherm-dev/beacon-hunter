import random

from beacon_hunter import stats
from beacon_hunter.allowlist import Allowlist
from beacon_hunter.detector import Config, analyze, _is_internal
from beacon_hunter.models import Conn
from beacon_hunter.simulate import generate


def make_beacon(interval=60, jitter=0.2, hours=4, dst="203.0.113.9", port=443, seed=1, src="10.0.0.5"):
    rng = random.Random(seed)
    out, t, end = [], 0.0, hours * 3600
    while t < end:
        out.append(Conn(t, src, dst, port, "tcp", int(rng.gauss(250, 10)), 500))
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return out


def make_human(hours=4, dst="203.0.113.77", seed=2):
    rng = random.Random(seed)
    out, t, end = [], 0.0, hours * 3600
    while t < end:
        for _ in range(rng.randint(1, 10)):
            out.append(Conn(t, "10.0.0.5", dst, 443, "tcp", rng.randint(300, 50000), 1000))
            t += rng.expovariate(1 / 6)
        t += rng.expovariate(1 / 600)
    return out


def test_stats_basics():
    assert stats.median([1, 2, 3, 4]) == 2.5
    assert stats.cv([10, 10, 10]) == 0
    assert stats.dominant_ratio([60, 61, 59, 300], 0.1) == 0.75


def test_detects_beacon_with_jitter():
    f = analyze(make_beacon(), Config())
    assert len(f) == 1 and f[0].score >= 80 and f[0].severity == "ALTO"


def test_detects_slow_beacon():
    f = analyze(make_beacon(interval=900, jitter=0.1, hours=24), Config())
    assert len(f) == 1 and 800 < f[0].median_interval_s < 1000


def test_ignores_human_traffic():
    assert analyze(make_human(), Config()) == []


def test_too_few_connections_ignored():
    assert analyze(make_beacon(interval=3600, hours=5), Config()) == []


def test_bursts_are_merged():
    conns = []
    for c in make_beacon():
        conns += [c, Conn(c.ts + 0.2, c.src, c.dst, c.dport, "tcp", c.bytes_out, 10)]
    f = analyze(conns, Config())
    assert f and f[0].median_interval_s > 30


def test_internal_destinations_skipped_by_default():
    conns = make_beacon(dst="10.1.1.1")
    assert analyze(conns, Config()) == []
    assert len(analyze(conns, Config(include_internal=True))) == 1


def test_documentation_ranges_are_not_internal():
    assert not _is_internal("203.0.113.5") and _is_internal("192.168.1.1")


def test_allowlist_by_port_and_cidr():
    assert analyze(make_beacon(port=123), Config()) == []
    al = Allowlist(ports=set())
    import ipaddress
    al.networks.append(ipaddress.ip_network("203.0.113.0/24"))
    assert analyze(make_beacon(), Config(), al) == []


def test_sample_dataset_end_to_end():
    f = analyze(generate(seed=42), Config())
    dsts = {x.dst for x in f}
    assert {"203.0.113.50", "198.51.100.23"} <= dsts
    assert not any(x.src == "10.0.0.40" for x in f)
