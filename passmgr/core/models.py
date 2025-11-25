from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from .db import Base
class Metadata(Base):
    __tablename__ = "metadata"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(String, nullable=True)
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(200), unique=True, nullable=False)
    salt = Column(String(64), nullable=False)
    verifier = Column(String(128), nullable=False)


class Entry(Base):
    __tablename__ = "entries"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    name = Column(String(200), nullable=False)
    username = Column(String(200))
    password_encrypted = Column(Text, nullable=False)
    url = Column(String(255))
    notes_encrypted = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SchemaVersion(Base):
    __tablename__ = "schema_version"

    version = Column(Integer, primary_key=True, nullable=False)
