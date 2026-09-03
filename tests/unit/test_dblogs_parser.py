from __future__ import annotations

from pathlib import Path

from seclogx.ingest.logsources.parsers.dblogs import (
    parse_mssql_file,
    parse_mysql_error_file,
    parse_mysql_general_file,
    parse_mysql_slow_file,
    parse_oracle_alert_file,
    parse_postgresql_file,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "db_logs"


def test_parse_mysql_error_file():
    rows, ok, err = parse_mysql_error_file(FIXTURES / "mysql_error.log", host="DB01")
    assert ok == 4
    assert err == 1
    assert len(rows) == 4

    new_row = rows[0]
    assert new_row["severity"] == "System"
    assert new_row["error_code"] == "MY-010931"
    assert new_row["component"] == "Server"
    assert new_row["thread_id"] == "0"
    assert new_row["message"] == "Basedir set to /usr/."
    assert new_row["time_created"] is not None

    error_row = rows[2]
    assert error_row["severity"] == "ERROR"
    assert error_row["error_code"] == "MY-013183"
    assert error_row["component"] == "InnoDB"

    old_row = rows[3]
    assert old_row["severity"] == "Note"
    assert old_row["thread_id"] is None
    assert old_row["error_code"] is None
    assert "Server socket created" in old_row["message"]
    assert old_row["time_created"] is not None


def test_parse_mysql_general_file():
    rows, ok, err = parse_mysql_general_file(FIXTURES / "mysql_general.log", host="DB01")
    assert ok == 4
    assert err == 1
    assert len(rows) == 4

    connect_row = rows[0]
    assert connect_row["thread_id"] == "5"
    assert connect_row["component"] == "Connect"
    assert "root@localhost" in connect_row["message"]
    assert connect_row["time_created"] is not None

    query_row = rows[1]
    assert query_row["component"] == "Query"
    assert query_row["message"] == "SELECT * FROM users"
    # continuation entry has no own timestamp -- inherits the last one seen
    assert query_row["time_created"] == connect_row["time_created"]

    init_db_row = rows[2]
    assert init_db_row["component"] == "Init DB"
    assert init_db_row["message"] == "test_db"

    quit_row = rows[3]
    assert quit_row["component"] == "Quit"
    assert quit_row["message"] is None


def test_parse_mysql_slow_file():
    rows, ok, err = parse_mysql_slow_file(FIXTURES / "mysql_slow.log", host="DB01")
    assert ok == 2
    assert err == 0
    assert len(rows) == 2

    first = rows[0]
    assert first["query_time_sec"] == 1.234567
    assert first["rows_examined"] == 1000
    assert first["user_name"] == "root"
    assert first["client_address"] == "localhost"
    assert first["thread_id"] == "12"
    assert "SELECT * FROM users WHERE id=1;" in first["message"]
    assert "lock_time" in first["extra"]

    second = rows[1]
    assert second["query_time_sec"] == 5.5
    assert second["rows_examined"] == 500000
    assert second["client_address"] == "10.0.0.5"
    assert "SELECT * FROM secrets;" in second["message"]


def test_parse_mysql_slow_file_counts_leading_content_as_error(tmp_path: Path):
    p = tmp_path / "slow.log"
    p.write_text(
        "/usr/sbin/mysqld, Version: 8.0.34. started with:\n"
        "# Time: 2024-01-01T00:10:00.000001Z\n"
        "# User@Host: root[root] @ localhost []  Id:    12\n"
        "# Query_time: 1.000000  Lock_time: 0.000000 Rows_sent: 1  Rows_examined: 1\n"
        "SET timestamp=1704067800;\n"
        "SELECT 1;\n"
    )
    rows, ok, err = parse_mysql_slow_file(p, host="DB01")
    assert ok == 1
    assert err == 1


def test_parse_postgresql_file():
    rows, ok, err = parse_postgresql_file(FIXTURES / "postgresql.log", host="DB01")
    assert ok == 3
    assert err == 1
    assert len(rows) == 3

    startup_row = rows[0]
    assert startup_row["severity"] == "LOG"
    assert startup_row["user_name"] is None
    assert startup_row["database_name"] is None

    statement_row = rows[1]
    assert statement_row["severity"] == "LOG"
    assert statement_row["user_name"] == "appuser"
    assert statement_row["database_name"] == "appdb"
    assert "SELECT * FROM accounts" in statement_row["message"]

    error_row = rows[2]
    assert error_row["severity"] == "ERROR"
    assert "does not exist" in error_row["message"]


def test_parse_mssql_file():
    rows, ok, err = parse_mssql_file(FIXTURES / "mssql_errorlog", host="DB01")
    assert ok == 4
    assert err == 1
    assert len(rows) == 4

    server_row = rows[0]
    assert server_row["component"] == "Server"
    assert server_row["thread_id"] is None

    spid_row = rows[1]
    assert spid_row["component"] == "spid5s"
    assert spid_row["thread_id"] == "5"

    logon_row = rows[2]
    assert logon_row["component"] == "Logon"
    assert "Error: 18456" in logon_row["message"]


def test_parse_oracle_alert_file():
    rows, ok, err = parse_oracle_alert_file(FIXTURES / "oracle_alert.log", host="DB01")
    assert ok == 2
    assert err == 0
    assert len(rows) == 2

    startup_row = rows[0]
    assert startup_row["error_code"] is None
    assert "Starting ORACLE instance" in startup_row["message"]

    error_row = rows[1]
    assert error_row["error_code"] == "ORA-01017"
    assert "invalid username/password" in error_row["message"]


def test_parse_mysql_error_file_handles_gb18030_encoded_message(tmp_path: Path):
    line = "2024-01-01T00:00:00.000000Z 0 [Note] [MY-010000] [Server] 系统日志: 用户登录失败\n"
    p = tmp_path / "mysql_error_gbk.log"
    p.write_bytes(line.encode("gb18030"))

    rows, ok, err = parse_mysql_error_file(p, host="DB01")
    assert ok == 1
    assert err == 0
    assert rows[0]["message"] == "系统日志: 用户登录失败"
