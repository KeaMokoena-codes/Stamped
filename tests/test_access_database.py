import sqlite3
from pathlib import Path

import pytest

from access import DatabaseError, connect_database


def test_database_connection_requires_an_existing_database(tmp_path):
    db_path = tmp_path / "missing.db"

    with pytest.raises(DatabaseError, match="python schemas/init_db.py"):
        with connect_database(db_path):
            pass

    assert not db_path.exists()


def test_database_connection_opens_and_closes_existing_database(tmp_path):
    db_path = tmp_path / "shared.db"
    sqlite3.connect(db_path).close()

    with connect_database(db_path) as connection:
        connection.execute("CREATE TABLE connection_check (value TEXT)")
        connection.commit()

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_database_path_environment_variable_is_used(tmp_path, monkeypatch):
    db_path = tmp_path / "configured.db"
    sqlite3.connect(db_path).close()
    monkeypatch.setenv("STAMPED_DB_PATH", str(db_path))

    with connect_database() as connection:
        assert Path(connection.execute("PRAGMA database_list").fetchone()[2]) == db_path
