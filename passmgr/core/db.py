from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from .config import DB_PATH
from .logging import logger


# -----------------------------------------
# SQLAlchemy Base + Engine
# -----------------------------------------
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    future=True,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


# -----------------------------------------
# INITIALIZE SCHEMA
# -----------------------------------------
def init_db():
    """
    Create tables if they do not exist.
    Does NOT handle migrations by itself.
    """
    from . import models  # noqa
    Base.metadata.create_all(bind=engine)


# -----------------------------------------
# SCHEMA VERSION TABLE
# -----------------------------------------
def get_current_version(db):
    inspector = inspect(db.bind)

    # Before version table exists
    if "schema_version" not in inspector.get_table_names():
        return 0

    result = db.execute(text("SELECT version FROM schema_version LIMIT 1")).fetchone()
    if not result:
        return 0

    return result[0]


# -----------------------------------------
# AUTOMATIC MIGRATIONS
# -----------------------------------------
def run_migrations():
    """
    Automatic database migration handler.
    Ensures old installations upgrade to new schema.
    """
    from .models import User
    from .security import create_user

    db = SessionLocal()

    version = get_current_version(db)

    # -------------------------------------
    # MIGRATION 0 → 1:
    # Add user_id column to entries, create default user
    # -------------------------------------
    if version < 1:
        logger.info("[MIGRATION] Starting migration 0 → 1")

        inspector = inspect(db.bind)
        columns = [c["name"] for c in inspector.get_columns("entries")]

        # Add missing user_id column
        if "user_id" not in columns:
            logger.info("[MIGRATION] Adding 'user_id' column to entries")
            db.execute(text("ALTER TABLE entries ADD COLUMN user_id INTEGER"))

        # Create a default user if no users exist
        if db.query(User).count() == 0:
            logger.info("[MIGRATION] Creating default 'legacy' user")
            create_user(db, "legacy", "temporary-password")

            legacy_id = db.query(User).filter_by(username="legacy").first().id
            logger.info(f"[MIGRATION] Assigning all entries to user_id={legacy_id}")
            db.execute(text(f"UPDATE entries SET user_id = {legacy_id}"))

        # Update schema version
        db.execute(text("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"))
        db.execute(text("DELETE FROM schema_version"))
        db.execute(text("INSERT INTO schema_version (version) VALUES (1)"))
        db.commit()

        logger.info("[MIGRATION] Migration 0 → 1 complete")

    logger.info("[MIGRATION] Database schema up-to-date")
