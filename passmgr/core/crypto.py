import os
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

KDF_ITERATIONS = 200_000


def new_salt() -> bytes:
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(master_password.encode())
    return urlsafe_b64encode(key)


def encrypt(key: bytes, plaintext: str) -> str:
    f = Fernet(key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt(key: bytes, ciphertext: str) -> str:
    f = Fernet(key)
    return f.decrypt(ciphertext.encode()).decode()
