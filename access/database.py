"""Shared database connection configuration for application entry points."""

from contextlib import contextmanager
import os
import sqlite3
from pathlib import Path
from typing import Iterator

DEFAULT_DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "stamped.db"
DATABASE_ENV_VAR = "STAMPED_DB_PATH"


class DatabaseError(RuntimeError):
    """The configured shared database is missing or could not be accessed."""


@contextmanager
def connect_database(path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    """Open the configured existing database and always close its connection."""
    db_path = Path(path or os.environ.get(DATABASE_ENV_VAR, DEFAULT_DATABASE_PATH)).expanduser()
    if not db_path.is_file():
        raise DatabaseError(
            f"Database not found at {db_path}. Initialize it with "
            "`python schemas/init_db.py` or set STAMPED_DB_PATH."
        )

    try:
        connection = sqlite3.connect(db_path)
    except sqlite3.Error as exc:
        raise DatabaseError(f"Could not open database at {db_path}: {exc}") from exc

    try:
        yield connection
    except sqlite3.Error as exc:
        raise DatabaseError(f"Database operation failed for {db_path}: {exc}") from exc
    finally:
        connection.close()
