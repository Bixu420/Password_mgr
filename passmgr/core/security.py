import hashlib
import hmac
from sqlalchemy.orm import Session

from .crypto import derive_key, new_salt
from .models import User


def create_user(db: Session, username: str, master_password: str):
    if db.query(User).filter_by(username=username).first():
        raise ValueError("User already exists")

    salt = new_salt()
    key = derive_key(master_password, salt)

    verifier = hmac.new(key, b"verifier", hashlib.sha256).hexdigest()

    u = User(
        username=username,
        salt=salt.hex(),
        verifier=verifier
    )
    db.add(u)
    db.commit()
    return u


def verify_user(db: Session, username: str, master_password: str):
    u = db.query(User).filter_by(username=username).first()
    if not u:
        raise ValueError("Invalid username or password")

    salt = bytes.fromhex(u.salt)
    key = derive_key(master_password, salt)

    verifier = hmac.new(key, b"verifier", hashlib.sha256).hexdigest()
    if not hmac.compare_digest(verifier, u.verifier):
        raise ValueError("Invalid username or password")

    return key, u.id