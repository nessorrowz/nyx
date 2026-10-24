"""SQLite persistence layer.

A host-centric, queryable store is the point here: mid-engagement you want to
ask "which hosts expose SMB?" across the whole run, not grep a pile of text
files. SQLite keeps the scaffold dependency-free; swap the URL for Postgres
when you outgrow a single file.
"""
import os
from pathlib import Path
from sqlmodel import SQLModel, Session, create_engine

# RECON_DB keeps tests and one-off runs off the real engagement database.
DB_PATH = Path(
    os.environ.get("RECON_DB") or Path(__file__).resolve().parent.parent / "recon.db"
)
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    import app.models  # noqa: F401  (register tables)
    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)
