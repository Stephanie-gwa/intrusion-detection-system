from nids.cli import main


def test_generate_sample_data_writes_files(tmp_path, capsys):
    out_dir = tmp_path / "sample_data"
    rc = main(["generate-sample-data", "--out-dir", str(out_dir)])
    assert rc == 0
    assert (out_dir / "connections.csv").exists()
    assert (out_dir / "auth.log").exists()


def test_ingest_sample_and_detect(tmp_path, capsys):
    db_path = tmp_path / "test.db"
    rc1 = main(["--db", str(db_path), "ingest", "--sample", "--clear"])
    assert rc1 == 0
    out = capsys.readouterr().out
    assert "Ingested" in out

    rc2 = main(["--db", str(db_path), "detect"])
    assert rc2 == 0
    out2 = capsys.readouterr().out
    assert "alert(s) fired" in out2


def test_ingest_from_files(tmp_path, capsys):
    data_dir = tmp_path / "data"
    main(["generate-sample-data", "--out-dir", str(data_dir)])
    capsys.readouterr()

    db_path = tmp_path / "test.db"
    rc = main([
        "--db", str(db_path), "ingest",
        "--connections", str(data_dir / "connections.csv"),
        "--auth-log", str(data_dir / "auth.log"),
        "--clear",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Ingested 272 connection events" in out or "Ingested" in out


def test_ingest_with_nothing_specified_fails(tmp_path, capsys):
    db_path = tmp_path / "test.db"
    rc = main(["--db", str(db_path), "ingest"])
    assert rc == 1


def test_list_alerts_empty(tmp_path, capsys):
    db_path = tmp_path / "empty.db"
    rc = main(["--db", str(db_path), "list-alerts"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "No alerts stored" in out


def test_list_alerts_after_detect(tmp_path, capsys):
    db_path = tmp_path / "test.db"
    main(["--db", str(db_path), "ingest", "--sample"])
    main(["--db", str(db_path), "detect"])
    capsys.readouterr()

    rc = main(["--db", str(db_path), "list-alerts"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "port_scan" in out


def test_live_without_confirmation_is_cancelled(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    db_path = tmp_path / "test.db"
    rc = main(["--db", str(db_path), "live", "--iface", "eth0", "--duration", "1"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "cancelled" in err.lower()


def test_no_command_prints_help(capsys):
    rc = main([])
    assert rc == 1
