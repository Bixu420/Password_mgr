from sqlalchemy.orm import Session
from .models import Entry, Metadata  # import the actual ORM models


def get_metadata(db: Session, key: str):
    m = db.query(Metadata).filter_by(key=key).first()
    return m.value if m else None


def set_metadata(db: Session, key: str, value: str):
    m = db.query(Metadata).filter_by(key=key).first()
    if m:
        m.value = value
    else:
        m = Metadata(key=key, value=value)
        db.add(m)
    db.commit()


def create_entry(db: Session, user_id: int, **fields) -> Entry:
    """
    Create a new entry owned by user_id.
    fields should contain: name, username, password_encrypted, url, notes_encrypted.
    """
    e = Entry(user_id=user_id, **fields)
    db.add(e)
    db.commit()
    db.refresh(e)
    return e


def list_entries(db: Session, user_id: int) -> list[Entry]:
    """
    List all entries belonging to a given user_id.
    """
    return db.query(Entry).filter_by(user_id=user_id).all()


def get_entry(db: Session, entry_id: int, user_id: int) -> Entry | None:
    """
    Get a single entry by id that belongs to user_id.
    """
    return db.query(Entry).filter_by(id=entry_id, user_id=user_id).first()


def delete_entry(db: Session, entry_id: int, user_id: int) -> bool:
    """
    Delete an entry owned by user_id.
    Returns True if deleted, False if not found.
    """
    entry = (
        db.query(Entry)
        .filter(Entry.id == entry_id, Entry.user_id == user_id)
        .first()
    )

    if not entry:
        return False

    db.delete(entry)
    db.commit()
    return True
