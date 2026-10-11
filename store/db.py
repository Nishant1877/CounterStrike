"""
Database Engine & Session Management for IdentityGuard (A-03).
Supports SQLite for self-contained local execution and ephemeral in-memory sandboxes for replays.
"""

from __future__ import annotations
import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from store.models import Base

DEFAULT_DB_PATH = "identityguard.db"


class DatabaseManager:
    """Manages SQLite database connections and table lifecycle."""

    def __init__(self, db_url: Optional[str] = None):
        if not db_url:
            self.db_url = f"sqlite:///{DEFAULT_DB_PATH}"
        else:
            self.db_url = db_url

        self.engine = create_engine(
            self.db_url,
            connect_args={"check_same_thread": False} if "sqlite" in self.db_url else {}
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.init_db()

    def init_db(self) -> None:
        """Creates all database tables."""
        Base.metadata.create_all(bind=self.engine)

    def reset_db(self) -> None:
        """Drops and recreates all tables (used for clean testing and sandbox runs)."""
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Provides a transactional scope around a series of operations."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# Global default database instance
default_db = DatabaseManager()
