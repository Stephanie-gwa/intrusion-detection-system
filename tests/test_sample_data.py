from nids.sample_data import generate_all, generate_auth_events, generate_connection_events


def test_connection_events_are_deterministic_for_same_seed():
    a = generate_connection_events(seed=42)
    b = generate_connection_events(seed=42)
    assert [e.to_dict() for e in a] == [e.to_dict() for e in b]


def test_auth_events_are_deterministic_for_same_seed():
    a = generate_auth_events(seed=42)
    b = generate_auth_events(seed=42)
    assert [e.to_dict() for e in a] == [e.to_dict() for e in b]


def test_different_seeds_produce_different_data():
    a = generate_connection_events(seed=1)
    b = generate_connection_events(seed=2)
    assert [e.to_dict() for e in a] != [e.to_dict() for e in b]


def test_connection_events_are_sorted_by_timestamp():
    events = generate_connection_events()
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


def test_auth_events_are_sorted_by_timestamp():
    events = generate_auth_events()
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


def test_generate_all_returns_both_streams():
    conns, auths = generate_all()
    assert len(conns) > 0
    assert len(auths) > 0


def test_embedded_port_scan_present():
    events = generate_connection_events()
    scanner_events = [e for e in events if e.src_ip == "203.0.113.50"]
    assert len({e.dst_port for e in scanner_events}) >= 100


def test_embedded_brute_force_present():
    events = generate_auth_events()
    attacker_events = [e for e in events if e.src_ip == "198.51.100.23"]
    failures = [e for e in attacker_events if not e.success]
    assert len(failures) >= 20
    assert any(e.success for e in attacker_events)
