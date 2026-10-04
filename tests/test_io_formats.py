from datetime import datetime

from nids.events import AuthEvent, ConnectionEvent
from nids.io_formats import read_auth_log, read_connection_csv, write_auth_log, write_connection_csv


def test_connection_csv_roundtrip(tmp_path):
    events = [
        ConnectionEvent(timestamp=datetime(2026, 1, 1, 9, 0, 0), src_ip="10.0.0.1",
                         dst_ip="10.0.0.2", dst_port=22, protocol="tcp", bytes_sent=123, flag="S"),
        ConnectionEvent(timestamp=datetime(2026, 1, 1, 9, 0, 5), src_ip="10.0.0.3",
                         dst_ip="10.0.0.4", dst_port=443, protocol="tcp", bytes_sent=4567, flag="SA"),
    ]
    path = tmp_path / "conns.csv"
    write_connection_csv(events, path)
    loaded = read_connection_csv(path)

    assert len(loaded) == 2
    assert loaded[0].src_ip == "10.0.0.1"
    assert loaded[0].dst_port == 22
    assert loaded[1].bytes_sent == 4567
    assert loaded[1].flag == "SA"


def test_auth_log_roundtrip(tmp_path):
    events = [
        AuthEvent(timestamp=datetime(2026, 1, 1, 9, 0, 0), src_ip="198.51.100.5",
                  username="root", success=False),
        AuthEvent(timestamp=datetime(2026, 1, 1, 9, 0, 3), src_ip="198.51.100.5",
                  username="root", success=True),
    ]
    path = tmp_path / "auth.log"
    write_auth_log(events, path)
    loaded = read_auth_log(path)

    assert len(loaded) == 2
    assert loaded[0].success is False
    assert loaded[1].success is True
    assert loaded[0].username == "root"
    assert loaded[0].src_ip == "198.51.100.5"


def test_auth_log_skips_unparseable_lines(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "2026-01-01T09:00:00 sshd: Failed password for root from 1.2.3.4 port 1111 ssh2\n"
        "some unrelated log line that doesn't match the pattern\n"
        "2026-01-01T09:00:05 sshd: Accepted password for root from 1.2.3.4 port 1112 ssh2\n",
        encoding="utf-8",
    )
    loaded = read_auth_log(path)
    assert len(loaded) == 2


def test_auth_log_handles_empty_file(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")
    assert read_auth_log(path) == []
